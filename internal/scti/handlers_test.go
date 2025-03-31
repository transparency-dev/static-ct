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
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/static-ct/internal/testdata"
	"github.com/transparency-dev/static-ct/internal/types"
	"github.com/transparency-dev/static-ct/internal/x509util"
	"github.com/transparency-dev/static-ct/mockstorage"
	"github.com/transparency-dev/static-ct/modules/dedup"
	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/ctonly"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"
)

// Arbitrary time for use in tests
var fakeTime = time.Date(2016, 7, 22, 11, 01, 13, 0, time.UTC)
var fakeTimeMillis = uint64(fakeTime.UnixNano() / nanosPerMilli)

// Arbitrary origin for tests
var origin = "example.com"
var prefix = "/" + origin

// The deadline should be the above bumped by 500ms
var fakeDeadlineTime = time.Date(2016, 7, 22, 11, 01, 13, 500*1000*1000, time.UTC)
var fakeTimeSource = newFixedTimeSource(fakeTime)

var entrypaths = []string{prefix + types.AddChainPath, prefix + types.AddPreChainPath, prefix + types.GetRootsPath}

type handlerTestInfo struct {
	mockCtrl *gomock.Controller
	roots    *x509util.PEMCertPool
	storage  *mockstorage.MockStorage
	handlers map[string]appHandler
}

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

// setupTest creates mock objects and contexts.  Caller should invoke info.mockCtrl.Finish().
func setupTest(t *testing.T, pemRoots []string, signer crypto.Signer) handlerTestInfo {
	t.Helper()
	info := handlerTestInfo{
		mockCtrl: gomock.NewController(t),
		roots:    x509util.NewPEMCertPool(),
	}

	info.storage = mockstorage.NewMockStorage(info.mockCtrl)
	vOpts := ChainValidationOpts{
		trustedRoots:  info.roots,
		rejectExpired: false,
	}

	hOpts := HandlerOptions{
		Deadline:   time.Millisecond * 500,
		RequestLog: new(DefaultRequestLog),
		TimeSource: fakeTimeSource,
	}
	signSCT := func(leaf *types.MerkleTreeLeaf) (*types.SignedCertificateTimestamp, error) {
		return buildV1SCT(signer, leaf)
	}
	log := log{
		storage:             info.storage,
		signSCT:             signSCT,
		origin:              origin,
		chainValidationOpts: vOpts,
	}
	info.handlers = NewPathHandlers(&hOpts, &log)

	for _, pemRoot := range pemRoots {
		if !info.roots.AppendCertsFromPEM([]byte(pemRoot)) {
			klog.Fatal("failed to load cert pool")
		}
	}

	return info
}

func (info handlerTestInfo) getHandlers(t *testing.T) pathHandlers {
	t.Helper()
	handler, ok := info.handlers[prefix+types.GetRootsPath]
	if !ok {
		t.Fatalf("%q path not registered", types.GetRootsPath)
	}
	return pathHandlers{prefix + types.GetRootsPath: handler}
}

func (info handlerTestInfo) postHandlers(t *testing.T) pathHandlers {
	t.Helper()
	addChainHandler, ok := info.handlers[prefix+types.AddChainPath]
	if !ok {
		t.Fatalf("%q path not registered", types.AddPreChainStr)
	}
	addPreChainHandler, ok := info.handlers[prefix+types.AddPreChainPath]
	if !ok {
		t.Fatalf("%q path not registered", types.AddPreChainStr)
	}

	return map[string]appHandler{
		prefix + types.AddChainPath:    addChainHandler,
		prefix + types.AddPreChainPath: addPreChainHandler,
	}
}

func TestPostHandlersRejectGet(t *testing.T) {
	info := setupTest(t, []string{testdata.CACertPEM}, nil)
	defer info.mockCtrl.Finish()

	// Anything in the post handler list should reject GET
	for path, handler := range info.postHandlers(t) {
		t.Run(path, func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			resp, err := http.Get(s.URL + "/ct/v1/" + path)
			if err != nil {
				t.Fatalf("http.Get(%s)=(_,%q); want (_,nil)", path, err)
			}
			if got, want := resp.StatusCode, http.StatusMethodNotAllowed; got != want {
				t.Errorf("http.Get(%s)=(%d,nil); want (%d,nil)", path, got, want)
			}
		})
	}
}

func TestGetHandlersRejectPost(t *testing.T) {
	info := setupTest(t, []string{testdata.CACertPEM}, nil)
	defer info.mockCtrl.Finish()

	// Anything in the get handler list should reject POST.
	for path, handler := range info.getHandlers(t) {
		t.Run(path, func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			resp, err := http.Post(s.URL+"/ct/v1/"+path, "application/json", nil)
			if err != nil {
				t.Fatalf("http.Post(%s)=(_,%q); want (_,nil)", path, err)
			}
			if got, want := resp.StatusCode, http.StatusMethodNotAllowed; got != want {
				t.Errorf("http.Post(%s)=(%d,nil); want (%d,nil)", path, got, want)
			}
		})
	}
}

func TestPostHandlersFailure(t *testing.T) {
	var tests = []struct {
		descr string
		body  io.Reader
		want  int
	}{
		{"nil", nil, http.StatusBadRequest},
		{"''", strings.NewReader(""), http.StatusBadRequest},
		{"malformed-json", strings.NewReader("{ !$%^& not valid json "), http.StatusBadRequest},
		{"empty-chain", strings.NewReader(`{ "chain": [] }`), http.StatusBadRequest},
		{"wrong-chain", strings.NewReader(`{ "chain": [ "test" ] }`), http.StatusBadRequest},
	}

	info := setupTest(t, []string{testdata.CACertPEM}, nil)
	defer info.mockCtrl.Finish()
	for path, handler := range info.postHandlers(t) {
		t.Run(path, func(t *testing.T) {
			s := httptest.NewServer(handler)

			for _, test := range tests {
				resp, err := http.Post(s.URL+"/ct/v1/"+path, "application/json", test.body)
				if err != nil {
					t.Errorf("http.Post(%s,%s)=(_,%q); want (_,nil)", path, test.descr, err)
					continue
				}
				if resp.StatusCode != test.want {
					t.Errorf("http.Post(%s,%s)=(%d,nil); want (%d,nil)", path, test.descr, resp.StatusCode, test.want)
				}
			}
		})
	}
}

func TestHandlers(t *testing.T) {
	info := setupTest(t, nil, nil)
	defer info.mockCtrl.Finish()
	t.Run("Handlers", func(t *testing.T) {
		handlers := info.handlers
		// Check each entrypoint has a handler
		if got, want := len(handlers), len(entrypoints); got != want {
			t.Fatalf("len(info.handler)=%d; want %d", got, want)
		}

		// We want to see the same set of handler names and paths that we think we registered.
		var hNames []entrypointName
		var hPaths []string
		for p, v := range handlers {
			hNames = append(hNames, v.name)
			hPaths = append(hPaths, p)
		}

		if !cmp.Equal(entrypoints, hNames, cmpopts.SortSlices(func(n1, n2 entrypointName) bool {
			return n1 < n2
		})) {
			t.Errorf("Handler names mismatch got: %v, want: %v", hNames, entrypoints)
		}

		if !cmp.Equal(entrypaths, hPaths, cmpopts.SortSlices(func(n1, n2 string) bool {
			return n1 < n2
		})) {
			t.Errorf("Handler paths mismatch got: %v, want: %v", hPaths, entrypaths)
		}
	})
}

func parseChain(t *testing.T, isPrecert bool, pemChain []string, root *x509.Certificate) (*ctonly.Entry, []*x509.Certificate) {
	t.Helper()
	pool := loadCertsIntoPoolOrDie(t, pemChain)
	leafChain := pool.RawCertificates()
	if !leafChain[len(leafChain)-1].Equal(root) {
		// The submitted chain may not include a root, but the generated LogLeaf will
		fullChain := make([]*x509.Certificate, len(leafChain)+1)
		copy(fullChain, leafChain)
		fullChain[len(leafChain)] = root
		leafChain = fullChain
	}
	entry, err := entryFromChain(leafChain, isPrecert, fakeTimeMillis)
	if err != nil {
		t.Fatalf("failed to create entry")
	}
	return entry, leafChain
}

func TestAddChainWhitespace(t *testing.T) {
	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{testdata.CACertPEM}, signer)
	defer info.mockCtrl.Finish()

	// Throughout we use variants of a hard-coded POST body derived from a chain of:
	pemChain := []string{testdata.CertFromIntermediate, testdata.IntermediateFromRoot}
	cert, rest := pem.Decode([]byte(testdata.CertFromIntermediate))
	if len(rest) > 0 {
		t.Fatalf("got %d bytes remaining after decoding cert, want 0", len(rest))
	}
	certB64 := base64.StdEncoding.EncodeToString(cert.Bytes)
	intermediate, rest := pem.Decode([]byte(testdata.IntermediateFromRoot))
	if len(rest) > 0 {
		t.Fatalf("got %d bytes remaining after decoding intermediate, want 0", len(rest))
	}
	intermediateB64 := base64.StdEncoding.EncodeToString(intermediate.Bytes)

	// Break the JSON into chunks:
	intro := "{\"chain\""
	// followed by colon then the first line of the PEM file
	chunk1a := "[\"" + certB64[:64]
	// straight into rest of first entry
	chunk1b := certB64[64:] + "\""
	// followed by comma then
	chunk2 := "\"" + intermediateB64 + "\""
	epilog := "]}\n"

	req, leafChain := parseChain(t, false, pemChain, info.roots.RawCertificates()[0])
	rsp := tessera.Index{Index: 0}

	var tests = []struct {
		descr string
		body  string
		want  int
	}{
		{
			descr: "valid",
			body:  intro + ":" + chunk1a + chunk1b + "," + chunk2 + epilog,
			want:  http.StatusOK,
		},
		{
			descr: "valid-space-between",
			body:  intro + " : " + chunk1a + chunk1b + " , " + chunk2 + epilog,
			want:  http.StatusOK,
		},
		{
			descr: "valid-newline-between",
			body:  intro + " : " + chunk1a + chunk1b + ",\n" + chunk2 + epilog,
			want:  http.StatusOK,
		},
		{
			descr: "invalid-raw-newline-in-string",
			body:  intro + ":" + chunk1a + "\n" + chunk1b + "," + chunk2 + epilog,
			want:  http.StatusBadRequest,
		},
		{
			descr: "valid-escaped-newline-in-string",
			body:  intro + ":" + chunk1a + "\\n" + chunk1b + "," + chunk2 + epilog,
			want:  http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.descr, func(t *testing.T) {
			if test.want == http.StatusOK {
				info.storage.EXPECT().GetCertDedupInfo(deadlineMatcher(), cmpMatcher{leafChain[0]}).Return(dedup.SCTDedupInfo{Idx: uint64(0), Timestamp: fakeTimeMillis}, false, nil)
				info.storage.EXPECT().AddIssuerChain(deadlineMatcher(), cmpMatcher{leafChain[1:]}).Return(nil)
				info.storage.EXPECT().Add(deadlineMatcher(), cmpMatcher{req}).Return(func() (tessera.Index, error) { return rsp, nil })
				info.storage.EXPECT().AddCertDedupInfo(deadlineMatcher(), cmpMatcher{leafChain[0]}, dedup.SCTDedupInfo{Idx: uint64(0), Timestamp: fakeTimeMillis}).Return(nil)
			}

			recorder := httptest.NewRecorder()
			handler, ok := info.handlers["/example.com/ct/v1/add-chain"]
			if !ok {
				t.Fatalf("%q path not registered", types.AddChainStr)
			}
			req, err := http.NewRequest(http.MethodPost, "http://example.com/ct/v1/add-chain", strings.NewReader(test.body))
			if err != nil {
				t.Fatalf("Failed to create POST request: %v", err)
			}
			handler.ServeHTTP(recorder, req)

			if recorder.Code != test.want {
				t.Fatalf("addChain()=%d (body:%v); want %dv", recorder.Code, recorder.Body, test.want)
			}
		})
	}
}

func TestAddChain(t *testing.T) {
	var tests = []struct {
		descr string
		chain []string
		// TODO(phboneff): can this be removed?
		toSign string // hex-encoded
		want   int
		err    error
	}{
		{
			descr: "leaf-only",
			chain: []string{testdata.CertFromIntermediate},
			want:  http.StatusBadRequest,
		},
		{
			descr: "wrong-entry-type",
			chain: []string{testdata.PreCertFromIntermediate},
			want:  http.StatusBadRequest,
		},
		{
			descr:  "backend-storage-fail",
			chain:  []string{testdata.CertFromIntermediate, testdata.IntermediateFromRoot},
			toSign: "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			want:   http.StatusInternalServerError,
			err:    status.Errorf(codes.Internal, "error"),
		},
		{
			descr:  "success-without-root",
			chain:  []string{testdata.CertFromIntermediate, testdata.IntermediateFromRoot},
			toSign: "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			want:   http.StatusOK,
		},
		{
			descr:  "success",
			chain:  []string{testdata.CertFromIntermediate, testdata.IntermediateFromRoot, testdata.CACertPEM},
			toSign: "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			want:   http.StatusOK,
		},
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{testdata.CACertPEM}, signer)
	defer info.mockCtrl.Finish()

	for _, test := range tests {
		t.Run(test.descr, func(t *testing.T) {
			pool := loadCertsIntoPoolOrDie(t, test.chain)
			chain := createJSONChain(t, *pool)
			if len(test.toSign) > 0 {
				req, leafChain := parseChain(t, false, test.chain, info.roots.RawCertificates()[0])
				rsp := tessera.Index{Index: 0}
				info.storage.EXPECT().GetCertDedupInfo(deadlineMatcher(), cmpMatcher{leafChain[0]}).Return(dedup.SCTDedupInfo{Idx: uint64(0), Timestamp: fakeTimeMillis}, false, nil)
				info.storage.EXPECT().AddIssuerChain(deadlineMatcher(), cmpMatcher{leafChain[1:]}).Return(nil)
				info.storage.EXPECT().Add(deadlineMatcher(), cmpMatcher{req}).Return(func() (tessera.Index, error) { return rsp, test.err })
				if test.want == http.StatusOK {
					info.storage.EXPECT().AddCertDedupInfo(deadlineMatcher(), cmpMatcher{leafChain[0]}, dedup.SCTDedupInfo{Idx: uint64(0), Timestamp: fakeTimeMillis}).Return(nil)
				}
			}

			recorder := makeAddChainRequest(t, info.handlers, chain)
			if recorder.Code != test.want {
				t.Fatalf("addChain()=%d (body:%v); want %dv", recorder.Code, recorder.Body, test.want)
			}
			if test.want == http.StatusOK {
				var resp types.AddChainResponse
				if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
					t.Fatalf("json.Decode(%s)=%v; want nil", recorder.Body.Bytes(), err)
				}

				if got, want := types.Version(resp.SCTVersion), types.V1; got != want {
					t.Errorf("resp.SCTVersion=%v; want %v", got, want)
				}
				if got, want := resp.ID, demoLogID[:]; !bytes.Equal(got, want) {
					t.Errorf("resp.ID=%v; want %v", got, want)
				}
				if got, want := resp.Timestamp, uint64(1469185273000); got != want {
					t.Errorf("resp.Timestamp=%d; want %d", got, want)
				}
				if got, want := hex.EncodeToString(resp.Signature), "040300067369676e6564"; got != want {
					t.Errorf("resp.Signature=%s; want %s", got, want)
				}
				// TODO(phboneff): check that the index is in the SCT
				// TODO(phboneff): add a test with a not after range
				// TODO(phboneff): add a test with a start date only
			}
		})
	}
}

func TestAddPrechain(t *testing.T) {
	var tests = []struct {
		descr  string
		chain  []string
		root   string
		toSign string // hex-encoded
		err    error
		want   int
	}{
		{
			descr: "leaf-signed-by-different",
			chain: []string{testdata.PrecertPEMValid, testdata.FakeIntermediateCertPEM},
			want:  http.StatusBadRequest,
		},
		{
			descr: "wrong-entry-type",
			chain: []string{testdata.TestCertPEM},
			want:  http.StatusBadRequest,
		},
		{
			descr:  "backend-storage-fail",
			chain:  []string{testdata.PrecertPEMValid, testdata.CACertPEM},
			toSign: "92ecae1a2dc67a6c5f9c96fa5cab4c2faf27c48505b696dad926f161b0ca675a",
			err:    status.Errorf(codes.Internal, "error"),
			want:   http.StatusInternalServerError,
		},
		{
			descr:  "success",
			chain:  []string{testdata.PrecertPEMValid, testdata.CACertPEM},
			toSign: "92ecae1a2dc67a6c5f9c96fa5cab4c2faf27c48505b696dad926f161b0ca675a",
			want:   http.StatusOK,
		},
		{
			descr:  "success-without-root",
			chain:  []string{testdata.PrecertPEMValid},
			toSign: "92ecae1a2dc67a6c5f9c96fa5cab4c2faf27c48505b696dad926f161b0ca675a",
			want:   http.StatusOK,
		},
		// TODO(phboneff): add a test with an intermediate
		// TODO(phboneff): add a test with a pre-issuer intermediate cert
		// TODO(phboneff): add a test with a not after range
		// TODO(phboneff): add a test with a start date only
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{testdata.CACertPEM}, signer)
	defer info.mockCtrl.Finish()

	for _, test := range tests {
		t.Run(test.descr, func(t *testing.T) {
			pool := loadCertsIntoPoolOrDie(t, test.chain)
			chain := createJSONChain(t, *pool)
			if len(test.toSign) > 0 {
				req, leafChain := parseChain(t, true, test.chain, info.roots.RawCertificates()[0])
				rsp := tessera.Index{Index: 0}
				info.storage.EXPECT().GetCertDedupInfo(deadlineMatcher(), cmpMatcher{leafChain[0]}).Return(dedup.SCTDedupInfo{Idx: uint64(0), Timestamp: fakeTimeMillis}, false, nil)
				info.storage.EXPECT().AddIssuerChain(deadlineMatcher(), cmpMatcher{leafChain[1:]}).Return(nil)
				info.storage.EXPECT().Add(deadlineMatcher(), cmpMatcher{req}).Return(func() (tessera.Index, error) { return rsp, test.err })
				if test.want == http.StatusOK {
					info.storage.EXPECT().AddCertDedupInfo(deadlineMatcher(), cmpMatcher{leafChain[0]}, dedup.SCTDedupInfo{Idx: uint64(0), Timestamp: fakeTimeMillis}).Return(nil)
				}
			}

			recorder := makeAddPrechainRequest(t, info.handlers, chain)
			if recorder.Code != test.want {
				t.Fatalf("addPrechain()=%d (body:%v); want %d", recorder.Code, recorder.Body, test.want)
			}
			if test.want == http.StatusOK {
				var resp types.AddChainResponse
				if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
					t.Fatalf("json.Decode(%s)=%v; want nil", recorder.Body.Bytes(), err)
				}

				if got, want := types.Version(resp.SCTVersion), types.V1; got != want {
					t.Errorf("resp.SCTVersion=%v; want %v", got, want)
				}
				if got, want := resp.ID, demoLogID[:]; !bytes.Equal(got, want) {
					t.Errorf("resp.ID=%x; want %x", got, want)
				}
				if got, want := resp.Timestamp, fakeTimeMillis; got != want {
					t.Errorf("resp.Timestamp=%d; want %d", got, want)
				}
				if got, want := hex.EncodeToString(resp.Signature), "040300067369676e6564"; got != want {
					t.Errorf("resp.Signature=%s; want %s", got, want)
				}
			}
		})
	}
}

func createJSONChain(t *testing.T, p x509util.PEMCertPool) io.Reader {
	t.Helper()
	var req types.AddChainRequest
	for _, rawCert := range p.RawCertificates() {
		req.Chain = append(req.Chain, rawCert.Raw)
	}

	var buffer bytes.Buffer
	// It's tempting to avoid creating and flushing the intermediate writer but it doesn't work
	writer := bufio.NewWriter(&buffer)
	err := json.NewEncoder(writer).Encode(&req)
	if err := writer.Flush(); err != nil {
		t.Error(err)
	}

	if err != nil {
		t.Fatalf("Failed to create test json: %v", err)
	}

	return bufio.NewReader(&buffer)
}

type dlMatcher struct {
}

func deadlineMatcher() gomock.Matcher {
	return dlMatcher{}
}

func (d dlMatcher) Matches(x any) bool {
	ctx, ok := x.(context.Context)
	if !ok {
		return false
	}

	deadlineTime, ok := ctx.Deadline()
	if !ok {
		return false // we never make calls without a deadline set
	}

	return deadlineTime.Equal(fakeDeadlineTime)
}

func (d dlMatcher) String() string {
	return fmt.Sprintf("deadline is %v", fakeDeadlineTime)
}

func makeAddPrechainRequest(t *testing.T, handlers pathHandlers, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	handler, ok := handlers[prefix+types.AddPreChainPath]
	if !ok {
		t.Fatalf("%q path not registered", types.AddPreChainStr)
	}
	return makeAddChainRequestInternal(t, handler, "add-pre-chain", body)
}

func makeAddChainRequest(t *testing.T, handlers pathHandlers, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	handler, ok := handlers[prefix+types.AddChainPath]
	if !ok {
		t.Fatalf("%q path not registered", types.AddChainStr)
	}
	return makeAddChainRequestInternal(t, handler, "add-chain", body)
}

func makeAddChainRequestInternal(t *testing.T, handler appHandler, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://example.com/ct/v1/%s", path), body)
	if err != nil {
		t.Fatalf("Failed to create POST request: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w
}

func loadCertsIntoPoolOrDie(t *testing.T, certs []string) *x509util.PEMCertPool {
	t.Helper()
	pool := x509util.NewPEMCertPool()
	for _, cert := range certs {
		if !pool.AppendCertsFromPEM([]byte(cert)) {
			t.Fatalf("couldn't parse test certs: %v", certs)
		}
	}
	return pool
}

// cmpMatcher is a custom gomock.Matcher that uses cmp.Equal combined with a
// cmp.Comparer that knows how to properly compare proto.Message types.
type cmpMatcher struct{ want any }

func (m cmpMatcher) Matches(got any) bool {
	return cmp.Equal(got, m.want, cmp.Comparer(proto.Equal))
}
func (m cmpMatcher) String() string {
	return fmt.Sprintf("equals %v", m.want)
}
