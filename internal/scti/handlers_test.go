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

package scti

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"

	"github.com/transparency-dev/static-ct/internal/testdata"
	"github.com/transparency-dev/static-ct/internal/testonly/storage/posix"
	"github.com/transparency-dev/static-ct/internal/types"
	"github.com/transparency-dev/static-ct/internal/x509util"
	"github.com/transparency-dev/static-ct/storage"
	"github.com/transparency-dev/static-ct/storage/bbolt"
	tessera "github.com/transparency-dev/trillian-tessera"
	posixTessera "github.com/transparency-dev/trillian-tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// Test root
var testRootPath = "../testdata/test_root_ca_cert.pem"

// Arbitrary time for use in tests
var fakeTime = time.Date(2016, 7, 22, 11, 01, 13, 0, time.UTC)
var fakeTimeMillis = uint64(fakeTime.UnixNano() / nanosPerMilli)

// Arbitrary origin for tests
var origin = "example.com"
var prefix = "/" + origin

type fixedTimeSource struct {
	fakeTime time.Time
}

// newFixedTimeSource creates a fixedTimeSource instance
func newFixedTimeSource(t time.Time) *fixedTimeSource {
	return &fixedTimeSource{fakeTime: t}
}

// Now returns the time value this instance contains
func (f *fixedTimeSource) Now() time.Time {
	return f.fakeTime
}

// setupTestLog creates test TesseraCT log using a POSIX backend.
func setupTestLog(t *testing.T) *log {
	t.Helper()

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	roots := x509util.NewPEMCertPool()
	if err := roots.AppendCertsFromPEMFile(testRootPath); err != nil {
		t.Fatalf("failed to read trusted roots: %v", err)
	}

	cvOpts := ChainValidationOpts{
		trustedRoots:    roots,
		rejectExpired:   false,
		rejectUnexpired: false,
	}

	log, err := NewLog(t.Context(), origin, signer, cvOpts, newPosixStorageFunc(t), newFixedTimeSource(fakeTime))
	if err != nil {
		t.Fatalf("newLog(): %v", err)
	}

	return log
}

// setupTestServer creates a test TesseraCT server with a single endpoint at path.
func setupTestServer(t *testing.T, log *log, path string) *httptest.Server {
	t.Helper()
	opts := &HandlerOptions{
		Deadline:           time.Millisecond * 500,
		RequestLog:         &DefaultRequestLog{},
		MaskInternalErrors: false,
		TimeSource:         newFixedTimeSource(fakeTime),
	}

	handlers := NewPathHandlers(opts, log)
	handler, ok := handlers[path]
	if !ok {
		t.Fatalf("Handler not found: %s", path)
	}

	return httptest.NewServer(handler)
}

// newPosixStorageFunc returns a function to create a new storage.CTStorage instance with:
//   - a POSIX Tessera storage driver
//   - a POSIX issuer storage system
//   - a BBolt deduplication database
func newPosixStorageFunc(t *testing.T) storage.CreateStorage {
	t.Helper()
	return func(ctx context.Context, signer note.Signer) (*storage.CTStorage, error) {
		driver, err := posixTessera.New(ctx, path.Join(t.TempDir(), "log"))
		if err != nil {
			klog.Fatalf("Failed to initialize POSIX Tessera storage driver: %v", err)
		}

		opts := tessera.NewAppendOptions().
			WithCheckpointSigner(signer).
			WithCTLayout()
			// TODO(phboneff): add other options like MaxBatchSize of 1 when implementing
			// additional tests

		appender, _, _, err := tessera.NewAppender(ctx, driver, opts)
		if err != nil {
			klog.Fatalf("Failed to initialize POSIX Tessera appender: %v", err)
		}

		issuerStorage, err := posix.NewIssuerStorage(t.TempDir())
		if err != nil {
			klog.Fatalf("failed to initialize InMemory issuer storage: %v", err)
		}

		beDedupStorage, err := bbolt.NewStorage(path.Join(t.TempDir(), "dedup.db"))
		if err != nil {
			klog.Fatalf("Failed to initialize BBolt deduplication database: %v", err)
		}

		s, err := storage.NewCTStorage(appender, issuerStorage, beDedupStorage)
		if err != nil {
			klog.Fatalf("Failed to initialize CTStorage: %v", err)
		}
		return s, nil
	}
}

func TestGetRoots(t *testing.T) {
	log := setupTestLog(t)
	server := setupTestServer(t, log, path.Join(prefix, "ct/v1/get-roots"))
	defer server.Close()

	t.Run("get-roots", func(t *testing.T) {
		resp, err := http.Get(server.URL + path.Join(prefix, "ct/v1/get-roots"))
		if err != nil {
			t.Fatalf("Failed to get roots: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Unexpected status code: %v", resp.StatusCode)
		}

		var roots types.GetRootsResponse
		err = json.NewDecoder(resp.Body).Decode(&roots)
		if err != nil {
			t.Errorf("Failed to decode response: %v", err)
		}

		if got, want := len(roots.Certificates), 1; got != want {
			t.Errorf("Unexpected number of certificates: got %d, want %d", got, want)
		}

		got, err := base64.StdEncoding.DecodeString(roots.Certificates[0])
		if err != nil {
			t.Errorf("Failed to decode certificate: %v", err)
		}
		want, _ := pem.Decode([]byte(testdata.CACertPEM))
		if !bytes.Equal(got, want.Bytes) {
			t.Errorf("Unexpected root: got %s, want %s", roots.Certificates[0], base64.StdEncoding.EncodeToString(want.Bytes))
		}
	})
}
