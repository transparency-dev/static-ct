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

package sctfe

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/monitoring"
	"github.com/transparency-dev/static-ct/modules/dedup"
	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/ctonly"
	"k8s.io/klog/v2"

	ct "github.com/google/certificate-transparency-go"
)

const (
	// HTTP content type header
	contentTypeHeader string = "Content-Type"
	// MIME content type for JSON
	contentTypeJSON string = "application/json"
	// The name of the JSON response map key in get-roots responses
	jsonMapKeyCertificates string = "certificates"
)

// entrypointName identifies a CT entrypoint as defined in section 4 of RFC 6962.
type entrypointName string

// Constants for entrypoint names, as exposed in statistics/logging.
const (
	addChainName    = entrypointName("AddChain")
	addPreChainName = entrypointName("AddPreChain")
	getRootsName    = entrypointName("GetRoots")
)

var (
	// Metrics are all per-log (label "origin"), but may also be
	// per-entrypoint (label "ep") or per-return-code (label "rc").
	once             sync.Once
	knownLogs        monitoring.Gauge     // origin => value (always 1.0)
	lastSCTTimestamp monitoring.Gauge     // origin => value
	reqsCounter      monitoring.Counter   // origin, ep => value
	rspsCounter      monitoring.Counter   // origin, ep, rc => value
	rspLatency       monitoring.Histogram // origin, ep, rc => value
)

// setupMetrics initializes all the exported metrics.
func setupMetrics(mf monitoring.MetricFactory) {
	knownLogs = mf.NewGauge("known_logs", "Set to 1 for known logs", "logid")
	lastSCTTimestamp = mf.NewGauge("last_sct_timestamp", "Time of last SCT in ms since epoch", "logid")
	reqsCounter = mf.NewCounter("http_reqs", "Number of requests", "logid", "ep")
	rspsCounter = mf.NewCounter("http_rsps", "Number of responses", "logid", "ep", "rc")
	rspLatency = mf.NewHistogram("http_latency", "Latency of responses in seconds", "logid", "ep", "rc")
}

// entrypoints is a list of entrypoint names as exposed in statistics/logging.
var entrypoints = []entrypointName{addChainName, addPreChainName, getRootsName}

// pathHandlers maps from a path to the relevant AppHandler instance.
type pathHandlers map[string]appHandler

// appHandler holds a logInfo and a handler function that uses it, and is
// an implementation of the http.Handler interface.
type appHandler struct {
	info    *logInfo
	handler func(context.Context, *logInfo, http.ResponseWriter, *http.Request) (int, error)
	name    entrypointName
	method  string // http.MethodGet or http.MethodPost
}

// ServeHTTP for an AppHandler invokes the underlying handler function but
// does additional common error and stats processing.
func (a appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var statusCode int
	label0 := a.info.log.origin
	label1 := string(a.name)
	reqsCounter.Inc(label0, label1)
	startTime := a.info.iOpts.TimeSource.Now()
	logCtx := a.info.iOpts.RequestLog.start(r.Context())
	a.info.iOpts.RequestLog.origin(logCtx, a.info.log.origin)
	defer func() {
		latency := a.info.iOpts.TimeSource.Now().Sub(startTime).Seconds()
		rspLatency.Observe(latency, label0, label1, strconv.Itoa(statusCode))
	}()
	klog.V(2).Infof("%s: request %v %q => %s", a.info.log.origin, r.Method, r.URL, a.name)
	// TODO(phboneff): add a.Method directly on the handler path and remove this test.
	if r.Method != a.method {
		klog.Warningf("%s: %s wrong HTTP method: %v", a.info.log.origin, a.name, r.Method)
		a.info.sendHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed: %s", r.Method))
		a.info.iOpts.RequestLog.status(logCtx, http.StatusMethodNotAllowed)
		return
	}

	// For GET requests all params come as form encoded so we might as well parse them now.
	// POSTs will decode the raw request body as JSON later.
	if r.Method == http.MethodGet {
		if err := r.ParseForm(); err != nil {
			a.info.sendHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to parse form data: %s", err))
			a.info.iOpts.RequestLog.status(logCtx, http.StatusBadRequest)
			return
		}
	}

	// impose a deadline on this onward request.
	ctx, cancel := context.WithDeadline(logCtx, deadlineTime(a.info))
	defer cancel()

	var err error
	statusCode, err = a.handler(ctx, a.info, w, r)
	a.info.iOpts.RequestLog.status(ctx, statusCode)
	klog.V(2).Infof("%s: %s <= st=%d", a.info.log.origin, a.name, statusCode)
	rspsCounter.Inc(label0, label1, strconv.Itoa(statusCode))
	if err != nil {
		klog.Warningf("%s: %s handler error: %v", a.info.log.origin, a.name, err)
		a.info.sendHTTPError(w, statusCode, err)
		return
	}

	// Additional check, for consistency the handler must return an error for non-200 st
	if statusCode != http.StatusOK {
		klog.Warningf("%s: %s handler non 200 without error: %d %v", a.info.log.origin, a.name, statusCode, err)
		a.info.sendHTTPError(w, http.StatusInternalServerError, fmt.Errorf("http handler misbehaved, st: %d", statusCode))
		return
	}
}

// logInfo holds information for a specific log instance.
type logInfo struct {
	log   *log
	iOpts *HandlerOptions
}

// HandlerOptions describes log handlers options.
type HandlerOptions struct {
	// Deadline is a timeout for HTTP requests.
	Deadline time.Duration
	// MetricFactory allows creating metrics.
	MetricFactory monitoring.MetricFactory
	// RequestLog provides structured logging of CTFE requests.
	RequestLog requestLog
	// MaskInternalErrors indicates if internal server errors should be masked
	// or returned to the user containing the full error message.
	MaskInternalErrors bool
	// TimeSource indicated the system time and can be injfected for testing.
	TimeSource timeSource
}

func NewPathHandlers(opts *HandlerOptions, log *log) pathHandlers {
	li := &logInfo{
		log:   log,
		iOpts: opts,
	}

	once.Do(func() { setupMetrics(opts.MetricFactory) })
	knownLogs.Set(1.0, log.origin)

	return li.handlers(log.origin)
}

// handlers returns a map from URL paths (with the given prefix) and AppHandler instances
// to handle those entrypoints.
func (li *logInfo) handlers(prefix string) pathHandlers {
	prefix = strings.TrimRight(prefix, "/")

	// Bind the logInfo instance to give an AppHandler instance for each endpoint.
	ph := pathHandlers{
		prefix + ct.AddChainPath:    appHandler{info: li, handler: addChain, name: addChainName, method: http.MethodPost},
		prefix + ct.AddPreChainPath: appHandler{info: li, handler: addPreChain, name: addPreChainName, method: http.MethodPost},
		prefix + ct.GetRootsPath:    appHandler{info: li, handler: getRoots, name: getRootsName, method: http.MethodGet},
	}

	return ph
}

// sendHTTPError generates a custom error page to give more information on why something didn't work
func (li *logInfo) sendHTTPError(w http.ResponseWriter, statusCode int, err error) {
	errorBody := http.StatusText(statusCode)
	if !li.iOpts.MaskInternalErrors || statusCode != http.StatusInternalServerError {
		errorBody += fmt.Sprintf("\n%v", err)
	}
	http.Error(w, errorBody, statusCode)
}

// parseBodyAsJSONChain tries to extract cert-chain out of request.
func parseBodyAsJSONChain(r *http.Request) (ct.AddChainRequest, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		klog.V(1).Infof("Failed to read request body: %v", err)
		return ct.AddChainRequest{}, err
	}

	var req ct.AddChainRequest
	if err := json.Unmarshal(body, &req); err != nil {
		klog.V(1).Infof("Failed to parse request body: %v", err)
		return ct.AddChainRequest{}, err
	}

	// The cert chain is not allowed to be empty. We'll defer other validation for later
	if len(req.Chain) == 0 {
		klog.V(1).Infof("Request chain is empty: %q", body)
		return ct.AddChainRequest{}, errors.New("cert chain was empty")
	}

	return req, nil
}

// addChainInternal is called by add-chain and add-pre-chain as the logic involved in
// processing these requests is almost identical
func addChainInternal(ctx context.Context, li *logInfo, w http.ResponseWriter, r *http.Request, isPrecert bool) (int, error) {
	var method entrypointName
	if isPrecert {
		method = addPreChainName
	} else {
		method = addChainName
	}

	// Check the contents of the request and convert to slice of certificates.
	addChainReq, err := parseBodyAsJSONChain(r)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("%s: failed to parse add-chain body: %s", li.log.origin, err)
	}
	// Log the DERs now because they might not parse as valid X.509.
	for _, der := range addChainReq.Chain {
		li.iOpts.RequestLog.addDERToChain(ctx, der)
	}
	chain, err := verifyAddChain(li, addChainReq, isPrecert)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to verify add-chain contents: %s", err)
	}
	for _, cert := range chain {
		li.iOpts.RequestLog.addCertToChain(ctx, cert)
	}
	// Get the current time in the form used throughout RFC6962, namely milliseconds since Unix
	// epoch, and use this throughout.
	timeMillis := uint64(li.iOpts.TimeSource.Now().UnixNano() / nanosPerMilli)

	entry, err := entryFromChain(chain, isPrecert, timeMillis)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to build MerkleTreeLeaf: %s", err)
	}

	klog.V(2).Infof("%s: %s => storage.GetCertIndex", li.log.origin, method)
	sctDedupInfo, isDup, err := li.log.storage.GetCertDedupInfo(ctx, chain[0])
	idx := sctDedupInfo.Idx
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("couldn't deduplicate the request: %s", err)
	}

	if isDup {
		klog.V(3).Infof("%s: %s - found duplicate entry at index %d", li.log.origin, method, idx)
		entry.Timestamp = sctDedupInfo.Timestamp
	} else {
		if err := li.log.storage.AddIssuerChain(ctx, chain[1:]); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("failed to store issuer chain: %s", err)
		}

		klog.V(2).Infof("%s: %s => storage.Add", li.log.origin, method)
		idx, err = li.log.storage.Add(ctx, entry)()
		if err != nil {
			if errors.Is(err, tessera.ErrPushback) {
				w.Header().Add("Retry-After", "1")
				return http.StatusServiceUnavailable, fmt.Errorf("Tessera sequencer pushed back: %v", err)
			}
			return http.StatusInternalServerError, fmt.Errorf("couldn't store the leaf: %v", err)
		}
		// We store the index for this certificate in the deduplication storage immediately.
		// It might be stored again later, if a local deduplication storage is synced, potentially
		// with a smaller value.
		klog.V(2).Infof("%s: %s => storage.AddCertIndex", li.log.origin, method)
		err = li.log.storage.AddCertDedupInfo(ctx, chain[0], dedup.SCTDedupInfo{Idx: idx, Timestamp: entry.Timestamp})
		// TODO: block log writes if deduplication breaks
		if err != nil {
			klog.Warningf("AddCertIndex(): failed to store certificate index: %v", err)
		}
	}

	// Always use the returned leaf as the basis for an SCT.
	var loggedLeaf ct.MerkleTreeLeaf
	leafValue := entry.MerkleTreeLeaf(idx)
	if rest, err := tls.Unmarshal(leafValue, &loggedLeaf); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to reconstruct MerkleTreeLeaf: %s", err)
	} else if len(rest) > 0 {
		return http.StatusInternalServerError, fmt.Errorf("extra data (%d bytes) on reconstructing MerkleTreeLeaf", len(rest))
	}

	// As the Log server has definitely got the Merkle tree leaf, we can
	// generate an SCT and respond with it.
	// TODO(phboneff): this should work, but double check
	sct, err := li.log.signSCT(&loggedLeaf)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to generate SCT: %s", err)
	}
	sctBytes, err := tls.Marshal(*sct)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to marshall SCT: %s", err)
	}
	// We could possibly fail to issue the SCT after this but it's v. unlikely.
	li.iOpts.RequestLog.issueSCT(ctx, sctBytes)
	err = marshalAndWriteAddChainResponse(sct, w)
	if err != nil {
		// reason is logged and http status is already set
		return http.StatusInternalServerError, fmt.Errorf("failed to write response: %s", err)
	}
	klog.V(3).Infof("%s: %s <= SCT", li.log.origin, method)
	if sct.Timestamp == timeMillis {
		lastSCTTimestamp.Set(float64(sct.Timestamp), li.log.origin)
	}

	return http.StatusOK, nil
}

func addChain(ctx context.Context, li *logInfo, w http.ResponseWriter, r *http.Request) (int, error) {
	return addChainInternal(ctx, li, w, r, false)
}

func addPreChain(ctx context.Context, li *logInfo, w http.ResponseWriter, r *http.Request) (int, error) {
	return addChainInternal(ctx, li, w, r, true)
}

func getRoots(_ context.Context, li *logInfo, w http.ResponseWriter, _ *http.Request) (int, error) {
	// Pull out the raw certificates from the parsed versions
	rawCerts := make([][]byte, 0, len(li.log.chainValidationOpts.trustedRoots.RawCertificates()))
	for _, cert := range li.log.chainValidationOpts.trustedRoots.RawCertificates() {
		rawCerts = append(rawCerts, cert.Raw)
	}

	jsonMap := make(map[string]interface{})
	jsonMap[jsonMapKeyCertificates] = rawCerts
	enc := json.NewEncoder(w)
	err := enc.Encode(jsonMap)
	if err != nil {
		klog.Warningf("%s: get_roots failed: %v", li.log.origin, err)
		return http.StatusInternalServerError, fmt.Errorf("get-roots failed with: %s", err)
	}

	return http.StatusOK, nil
}

// deadlineTime calculates the future time a request should expire based on our config.
func deadlineTime(li *logInfo) time.Time {
	return li.iOpts.TimeSource.Now().Add(li.iOpts.Deadline)
}

// verifyAddChain is used by add-chain and add-pre-chain. It does the checks that the supplied
// cert is of the correct type and chains to a trusted root.
func verifyAddChain(li *logInfo, req ct.AddChainRequest, expectingPrecert bool) ([]*x509.Certificate, error) {
	// We already checked that the chain is not empty so can move on to verification
	validPath, err := validateChain(req.Chain, li.log.chainValidationOpts)
	if err != nil {
		// We rejected it because the cert failed checks or we could not find a path to a root etc.
		// Lots of possible causes for errors
		return nil, fmt.Errorf("chain failed to verify: %s", err)
	}

	isPrecert, err := isPrecertificate(validPath[0])
	if err != nil {
		return nil, fmt.Errorf("precert test failed: %s", err)
	}

	// The type of the leaf must match the one the handler expects
	if isPrecert != expectingPrecert {
		if expectingPrecert {
			klog.Warningf("%s: Cert (or precert with invalid CT ext) submitted as precert chain: %q", li.log.origin, req.Chain)
		} else {
			klog.Warningf("%s: Precert (or cert with invalid CT ext) submitted as cert chain: %q", li.log.origin, req.Chain)
		}
		return nil, fmt.Errorf("cert / precert mismatch: %T", expectingPrecert)
	}

	return validPath, nil
}

// marshalAndWriteAddChainResponse is used by add-chain and add-pre-chain to create and write
// the JSON response to the client
func marshalAndWriteAddChainResponse(sct *ct.SignedCertificateTimestamp, w http.ResponseWriter) error {
	sig, err := tls.Marshal(sct.Signature)
	if err != nil {
		return fmt.Errorf("failed to marshal signature: %s", err)
	}

	rsp := ct.AddChainResponse{
		SCTVersion: sct.SCTVersion,
		Timestamp:  sct.Timestamp,
		ID:         sct.LogID.KeyID[:],
		Extensions: base64.StdEncoding.EncodeToString(sct.Extensions),
		Signature:  sig,
	}

	w.Header().Set(contentTypeHeader, contentTypeJSON)
	jsonData, err := json.Marshal(&rsp)
	if err != nil {
		return fmt.Errorf("failed to marshal add-chain: %s", err)
	}

	_, err = w.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to write add-chain resp: %s", err)
	}

	return nil
}

// entryFromChain generates an Entry from a chain and timestamp.
// copied from certificate-transparency-go/serialization.go
// TODO(phboneff): move in a different file maybe?
func entryFromChain(chain []*x509.Certificate, isPrecert bool, timestamp uint64) (*ctonly.Entry, error) {
	leaf := ctonly.Entry{
		IsPrecert: isPrecert,
		Timestamp: timestamp,
	}

	if len(chain) > 1 {
		issuersChain := make([][32]byte, len(chain)-1)
		for i, c := range chain[1:] {
			issuersChain[i] = sha256.Sum256(c.Raw)
		}
		leaf.FingerprintsChain = issuersChain
	}

	if !isPrecert {
		leaf.Certificate = chain[0].Raw
		return &leaf, nil
	}

	// Pre-certs are more complicated. First, parse the leaf pre-cert and its
	// putative issuer.
	if len(chain) < 2 {
		return nil, fmt.Errorf("no issuer cert available for precert leaf building")
	}
	issuer := chain[1]
	cert := chain[0]

	var preIssuer *x509.Certificate
	if isPreIssuer(issuer) {
		// Replace the cert's issuance information with details from the pre-issuer.
		preIssuer = issuer

		// The issuer of the pre-cert is not going to be the issuer of the final
		// cert.  Change to use the final issuer's key hash.
		if len(chain) < 3 {
			return nil, fmt.Errorf("no issuer cert available for pre-issuer")
		}
		issuer = chain[2]
	}

	// Next, post-process the DER-encoded TBSCertificate, to remove the CT poison
	// extension and possibly update the issuer field.
	defangedTBS, err := x509.BuildPrecertTBS(cert.RawTBSCertificate, preIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to remove poison extension: %v", err)
	}

	leaf.Precertificate = cert.Raw
	leaf.PrecertSigningCert = issuer.Raw
	leaf.Certificate = defangedTBS

	issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	leaf.IssuerKeyHash = issuerKeyHash[:]
	return &leaf, nil
}

// isPreIssuer indicates whether a certificate is a pre-cert issuer with the specific
// certificate transparency extended key usage.
// copied form certificate-transparency-go/serialization.go
func isPreIssuer(issuer *x509.Certificate) bool {
	for _, eku := range issuer.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCertificateTransparency {
			return true
		}
	}
	return false
}
