// Copyright 2024 The Tessera authors. All Rights Reserved.
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

package gcp

import (
	"context"
	"fmt"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/apiv1/spannerpb"
	"github.com/transparency-dev/static-ct/modules/dedup"
	"google.golang.org/grpc/codes"
)

// NewDedupeStorage returns a struct which can be used to store identity -> index mappings backed
// by Spanner.
//
// Note that updates to this dedup storage is logically entriely separate from any updates
// happening to the log storage.
func NewDedupeStorage(ctx context.Context, spannerDB string) (*DedupStorage, error) {
	/*
	   Schema for reference:

	   	CREATE TABLE IDSeq (
	   	 id INT64 NOT NULL,
	   	 h BYTES(MAX) NOT NULL,
	   	 idx INT64 NOT NULL,
	   	 timestamp INT64 NOT NULL,
	   	) PRIMARY KEY (id, h);
	*/
	dedupDB, err := spanner.NewClient(ctx, spannerDB)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Spanner: %v", err)
	}

	return &DedupStorage{
		dbPool: dedupDB,
	}, nil
}

// DedupStorage is a GCP Spanner based dedup storage implementation for SCTFE.
type DedupStorage struct {
	dbPool *spanner.Client
}

var _ dedup.BEDedupStorage = &DedupStorage{}

// Get looks up the stored index, if any, for the given identity.
func (d *DedupStorage) Get(ctx context.Context, i []byte) (dedup.SCTDedupInfo, bool, error) {
	var idx, timestamp int64
	if row, err := d.dbPool.Single().ReadRow(ctx, "IDSeq", spanner.Key{0, i}, []string{"idx", "timestamp"}); err != nil {
		if c := spanner.ErrCode(err); c == codes.NotFound {
			return dedup.SCTDedupInfo{}, false, nil
		}
		return dedup.SCTDedupInfo{}, false, err
	} else {
		if err := row.Columns(&idx, &timestamp); err != nil {
			return dedup.SCTDedupInfo{}, false, fmt.Errorf("failed to read dedup index: %v", err)
		}
		idx := uint64(idx)
		t := uint64(timestamp)
		return dedup.SCTDedupInfo{Idx: idx, Timestamp: t}, true, nil
	}
}

// Add stores associations between the passed-in identities and their indices.
func (d *DedupStorage) Add(ctx context.Context, entries []dedup.LeafDedupInfo) error {
	m := make([]*spanner.MutationGroup, 0, len(entries))
	for _, e := range entries {
		m = append(m, &spanner.MutationGroup{
			Mutations: []*spanner.Mutation{
				spanner.Insert("IDSeq", []string{"id", "h", "idx", "timestamp"},
				[]interface{}{0, e.LeafID, int64(e.Idx), int64(e.Timestamp)})},
		})
	}

	i := d.dbPool.BatchWrite(ctx, m)
	return i.Do(func(r *spannerpb.BatchWriteResponse) error {
		s := r.GetStatus()
		if c := codes.Code(s.Code); c != codes.OK && c != codes.AlreadyExists {
			return fmt.Errorf("failed to write dedup record: %v (%v)", s.GetMessage(), c)
		}
		return nil
	})
}
