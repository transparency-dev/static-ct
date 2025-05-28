// Copyright 2016 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/ctonly"
	"github.com/transparency-dev/tesseract/internal/types/staticct"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// CreateStorage instantiates a Tessera storage implementation with a signer option.
type CreateStorage func(context.Context, note.Signer) (*CTStorage, error)

const (
	// Each key is 64 bytes long, so this will take up to 64MB.
	// A CT log references ~15k unique issuer certifiates in 2024, so this gives plenty of space
	// if we ever run into this limit, we should re-think how it works.
	maxCachedIssuerKeys = 1 << 20
)

type KV struct {
	K []byte
	V []byte
}

// IssuerStorage issuer certificates under their hex encoded sha256.
type IssuerStorage interface {
	AddIssuersIfNotExist(ctx context.Context, kv []KV) error
}

// CTStorage implements ct.Storage and tessera.LogReader.
type CTStorage struct {
	storeData    func(context.Context, *ctonly.Entry) tessera.IndexFuture
	storeIssuers func(context.Context, []KV) error
	reader       tessera.LogReader
	awaiter      *tessera.PublicationAwaiter
}

// NewCTStorage instantiates a CTStorage object.
func NewCTStorage(ctx context.Context, logStorage *tessera.Appender, issuerStorage IssuerStorage, reader tessera.LogReader) (*CTStorage, error) {
	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 200*time.Millisecond)
	ctStorage := &CTStorage{
		storeData:    tessera.NewCertificateTransparencyAppender(logStorage),
		storeIssuers: cachedStoreIssuers(issuerStorage),
		reader:       reader,
		awaiter:      awaiter,
	}
	return ctStorage, nil
}

func (cts *CTStorage) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	return cts.reader.ReadCheckpoint(ctx)
}

// TODO(phbnf): cache timestamps (or more) to avoid reparsing the entire leaf bundle
func (cts *CTStorage) dedupFuture(ctx context.Context, f tessera.IndexFuture) (index, timestamp uint64, err error) {
	ctx, span := tracer.Start(ctx, "tesseract.storage.dedupFuture")
	defer span.End()

	idx, cpRaw, err := cts.awaiter.Await(ctx, f)
	if err != nil {
		return 0, 0, fmt.Errorf("error waiting for Tessera future and its integration: %v", err)
	}

	// A https://c2sp.org/static-ct-api logsize is on the second line
	l := bytes.SplitN(cpRaw, []byte("\n"), 3)
	if len(l) < 2 {
		return 0, 0, errors.New("invalid checkpoint - no size")
	}
	ckptSize, err := strconv.ParseUint(string(l[1]), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid checkpoint - can't extract size: %v", err)
	}

	eBIdx := idx.Index / layout.EntryBundleWidth
	eBRaw, err := cts.reader.ReadEntryBundle(ctx, eBIdx, layout.PartialTileSize(0, eBIdx, ckptSize))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, fmt.Errorf("leaf bundle at index %d not found: %v", eBIdx, err)
		}
		return 0, 0, fmt.Errorf("failed to fetch entry bundle at index %d: %v", eBIdx, err)
	}
	eb := staticct.EntryBundle{}
	if err := eb.UnmarshalText(eBRaw); err != nil {
		return 0, 0, fmt.Errorf("failed to unmarshal entry bundle at index %d: %v", eBIdx, err)
	}

	eIdx := idx.Index % layout.EntryBundleWidth
	if uint64(len(eb.Entries)) <= eIdx {
		return 0, 0, fmt.Errorf("entry bundle at index %d has only %d entries, but wanted at least %d", eBIdx, eIdx, eBIdx)
	}
	e := staticct.Entry{}
	t, err := staticct.UnmarshalTimestamp([]byte(eb.Entries[eIdx]))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to extract timestamp from entry %d in entry bundle %d: %v", eIdx, eBIdx, e)
	}

	return idx.Index, t, nil
}

// Add stores CT entries.
func (cts *CTStorage) Add(ctx context.Context, entry *ctonly.Entry) (uint64, uint64, error) {
	ctx, span := tracer.Start(ctx, "tesseract.storage.Add")
	defer span.End()

	future := cts.storeData(ctx, entry)
	idx, err := future()
	if err != nil {
		return 0, 0, fmt.Errorf("error waiting for Tessera future: %v", err)
	}
	if idx.IsDup {
		return cts.dedupFuture(ctx, future)
	}
	return idx.Index, entry.Timestamp, nil

}

// AddIssuerChain stores every chain certificate under its sha256.
//
// If an object is already stored under this hash, continues.
func (cts *CTStorage) AddIssuerChain(ctx context.Context, chain []*x509.Certificate) error {
	ctx, span := tracer.Start(ctx, "tesseract.storage.AddIssuerChain")
	defer span.End()

	kvs := []KV{}
	for _, c := range chain {
		id := sha256.Sum256(c.Raw)
		key := []byte(hex.EncodeToString(id[:]))
		kvs = append(kvs, KV{K: key, V: c.Raw})
	}
	if err := cts.storeIssuers(ctx, kvs); err != nil {
		return fmt.Errorf("error storing intermediates: %v", err)
	}
	return nil
}

// cachedStoreIssuers returns a caching wrapper for an IssuerStorage
//
// This is intended to make querying faster. It does not keep a copy of the certs, only sha256.
// Only up to maxCachedIssuerKeys keys will be stored locally.
func cachedStoreIssuers(s IssuerStorage) func(context.Context, []KV) error {
	var mu sync.RWMutex
	m := make(map[string]struct{})
	return func(ctx context.Context, kv []KV) error {
		req := []KV{}
		for _, kv := range kv {
			mu.RLock()
			_, ok := m[string(kv.K)]
			mu.RUnlock()
			if ok {
				klog.V(2).Infof("cachedStoreIssuers wrapper: found %q in local key cache", kv.K)
				continue
			}
			req = append(req, kv)
		}
		if err := s.AddIssuersIfNotExist(ctx, req); err != nil {
			return fmt.Errorf("AddIssuersIfNotExist()s: error storing issuer data in the underlying IssuerStorage: %v", err)
		}
		for _, kv := range req {
			if len(m) >= maxCachedIssuerKeys {
				klog.V(2).Infof("cachedStoreIssuers wrapper: local issuer cache full, will stop caching issuers.")
				return nil
			}
			mu.Lock()
			m[string(kv.K)] = struct{}{}
			mu.Unlock()
		}
		return nil
	}
}
