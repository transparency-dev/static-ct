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

// The ct_server binary runs the CT personality.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	sctfe "github.com/transparency-dev/static-ct"
	"github.com/transparency-dev/static-ct/storage"
	gcpSCTFE "github.com/transparency-dev/static-ct/storage/gcp"
	tessera "github.com/transparency-dev/trillian-tessera"
	gcpTessera "github.com/transparency-dev/trillian-tessera/storage/gcp"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

func init() {
	flag.Var(&notAfterStart, "not_after_start", "Start of the range of acceptable NotAfter values, inclusive. Leaving this unset implies no lower bound to the range. RFC3339 UTC format, e.g: 2024-01-02T15:04:05Z.")
	flag.Var(&notAfterLimit, "not_after_limit", "Cut off point of notAfter dates - only notAfter dates strictly *before* notAfterLimit will be accepted. Leaving this unset means no upper bound on the accepted range. RFC3339 UTC format, e.g: 2024-01-02T15:04:05Z.")
}

// Global flags that affect all log instances.
var (
	notAfterStart timestampFlag
	notAfterLimit timestampFlag

	httpEndpoint               = flag.String("http_endpoint", "localhost:6962", "Endpoint for HTTP (host:port).")
	metricsEndpoint            = flag.String("metrics_endpoint", "", "Endpoint for serving metrics; if left empty, metrics will be visible on --http_endpoint.")
	httpDeadline               = flag.Duration("http_deadline", time.Second*10, "Deadline for HTTP requests.")
	maskInternalErrors         = flag.Bool("mask_internal_errors", false, "Don't return error strings with Internal Server Error HTTP responses.")
	origin                     = flag.String("origin", "", "Origin of the log, for checkpoints and the monitoring prefix.")
	bucket                     = flag.String("bucket", "", "Name of the bucket to store the log in.")
	spannerDB                  = flag.String("spanner_db_path", "", "Spanner database path: projects/{projectId}/instances/{instanceId}/databases/{databaseId}.")
	spannerDedupDB             = flag.String("spanner_dedup_db_path", "", "Spanner deduplication database path: projects/{projectId}/instances/{instanceId}/databases/{databaseId}.")
	rootsPemFile               = flag.String("roots_pem_file", "", "Path to the file containing root certificates that are acceptable to the log. The certs are served through get-roots endpoint.")
	rejectExpired              = flag.Bool("reject_expired", false, "If true then the certificate validity period will be checked against the current time during the validation of submissions. This will cause expired certificates to be rejected.")
	rejectUnexpired            = flag.Bool("reject_unexpired", false, "If true then CTFE rejects certificates that are either currently valid or not yet valid.")
	extKeyUsages               = flag.String("ext_key_usages", "", "If set, will restrict the set of such usages that the server will accept. By default all are accepted. The values specified must be ones known to the x509 package.")
	rejectExtensions           = flag.String("reject_extension", "", "A list of X.509 extension OIDs, in dotted string form (e.g. '2.3.4.5') which, if present, should cause submissions to be rejected.")
	signerPublicKeySecretName  = flag.String("signer_public_key_secret_name", "", "Public key secret name for checkpoints and SCTs signer. Format: projects/{projectId}/secrets/{secretName}/versions/{secretVersion}.")
	signerPrivateKeySecretName = flag.String("signer_private_key_secret_name", "", "Private key secret name for checkpoints and SCTs signer. Format: projects/{projectId}/secrets/{secretName}/versions/{secretVersion}.")
)

// nolint:staticcheck
func main() {
	klog.InitFlags(nil)
	flag.Parse()
	ctx := context.Background()

	signer, err := NewSecretManagerSigner(ctx, *signerPublicKeySecretName, *signerPrivateKeySecretName)
	if err != nil {
		klog.Exitf("Can't create secret manager signer: %v", err)
	}

	chainValidationConfig := sctfe.ChainValidationConfig{
		RootsPEMFile:     *rootsPemFile,
		RejectExpired:    *rejectExpired,
		RejectUnexpired:  *rejectUnexpired,
		ExtKeyUsages:     *extKeyUsages,
		RejectExtensions: *rejectExtensions,
		NotAfterStart:    notAfterStart.t,
		NotAfterLimit:    notAfterLimit.t,
	}

	logHandler, err := sctfe.NewLogHandler(ctx, *origin, signer, chainValidationConfig, newGCPStorage, *httpDeadline, *maskInternalErrors)
	if err != nil {
		klog.Exitf("Can't initialize CT HTTP Server: %v", err)
	}

	klog.CopyStandardLogTo("WARNING")
	klog.Info("**** CT HTTP Server Starting ****")
	http.Handle("/", logHandler)

	metricsAt := *metricsEndpoint
	if metricsAt == "" {
		metricsAt = *httpEndpoint
	}

	if metricsAt != *httpEndpoint {
		// Run a separate handler for metrics.
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			metricsServer := http.Server{Addr: metricsAt, Handler: mux}
			err := metricsServer.ListenAndServe()
			klog.Warningf("Metrics server exited: %v", err)
		}()
	} else {
		// Handle metrics on the DefaultServeMux.
		http.Handle("/metrics", promhttp.Handler())
	}

	// Bring up the HTTP server and serve until we get a signal not to.
	srv := http.Server{Addr: *httpEndpoint}
	shutdownWG := new(sync.WaitGroup)
	go awaitSignal(func() {
		shutdownWG.Add(1)
		defer shutdownWG.Done()
		// Allow 60s for any pending requests to finish then terminate any stragglers
		// TODO(phboneff): maybe wait for the sequencer queue to be empty?
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
		defer cancel()
		klog.Info("Shutting down HTTP server...")
		if err := srv.Shutdown(ctx); err != nil {
			klog.Errorf("srv.Shutdown(): %v", err)
		}
		klog.Info("HTTP server shutdown")
	})

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		klog.Warningf("Server exited: %v", err)
	}
	// Wait will only block if the function passed to awaitSignal was called,
	// in which case it'll block until the HTTP server has gracefully shutdown
	shutdownWG.Wait()
	klog.Flush()
}

// awaitSignal waits for standard termination signals, then runs the given
// function; it should be run as a separate goroutine.
func awaitSignal(doneFn func()) {
	// Arrange notification for the standard set of signals used to terminate a server
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Now block main and wait for a signal
	sig := <-sigs
	klog.Warningf("Signal received: %v", sig)
	klog.Flush()

	doneFn()
}

func newGCPStorage(ctx context.Context, signer note.Signer) (*storage.CTStorage, error) {
	if *bucket == "" {
		return nil, errors.New("missing bucket")
	}

	if *spannerDB == "" {
		return nil, errors.New("missing spannerDB")
	}

	gcpCfg := gcpTessera.Config{
		Bucket:  *bucket,
		Spanner: *spannerDB,
	}

	driver, err := gcpTessera.New(ctx, gcpCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCP Tessera storage driver: %v", err)
	}

	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithCTLayout()

	// TODO(phbnf): figure out the best way to thread the `shutdown` func NewAppends returns back out to main so we can cleanly close Tessera down
	// when it's time to exit.
	appender, _, _, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCP Tessera appender: %v", err)
	}

	issuerStorage, err := gcpSCTFE.NewIssuerStorage(ctx, *bucket, "fingerprints/", "application/pkix-cert")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCP issuer storage: %v", err)
	}

	beDedupStorage, err := gcpSCTFE.NewDedupeStorage(ctx, *spannerDedupDB)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCP Spanner deduplication database: %v", err)
	}

	return storage.NewCTStorage(appender, issuerStorage, beDedupStorage)
}

type timestampFlag struct {
	t *time.Time
}

func (t *timestampFlag) String() string {
	if t.t != nil {
		return t.t.Format(time.RFC3339)
	}
	return ""
}

func (t *timestampFlag) Set(w string) error {
	if !strings.HasSuffix(w, "Z") {
		return fmt.Errorf("timestamps MUST be in UTC, got %v", w)
	}
	tt, err := time.Parse(time.RFC3339, w)
	if err != nil {
		return fmt.Errorf("can't parse %q as RFC3339 timestamp: %v", w, err)
	}
	t.t = &tt
	return nil
}
