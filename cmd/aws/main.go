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
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/transparency-dev/tessera"
	taws "github.com/transparency-dev/tessera/storage/aws"
	aws_as "github.com/transparency-dev/tessera/storage/aws/antispam"
	"github.com/transparency-dev/tesseract"
	"github.com/transparency-dev/tesseract/storage"
	"github.com/transparency-dev/tesseract/storage/aws"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

func init() {
	flag.Var(&notAfterStart, "not_after_start", "Start of the range of acceptable NotAfter values, inclusive. Leaving this unset or empty implies no lower bound to the range. RFC3339 UTC format, e.g: 2024-01-02T15:04:05Z.")
	flag.Var(&notAfterLimit, "not_after_limit", "Cut off point of notAfter dates - only notAfter dates strictly *before* notAfterLimit will be accepted. Leaving this unset or empty means no upper bound on the accepted range. RFC3339 UTC format, e.g: 2024-01-02T15:04:05Z.")
}

// Global flags that affect all log instances.
var (
	notAfterStart timestampFlag
	notAfterLimit timestampFlag

	httpEndpoint               = flag.String("http_endpoint", "localhost:6962", "Endpoint for HTTP (host:port).")
	httpDeadline               = flag.Duration("http_deadline", time.Second*10, "Deadline for HTTP requests.")
	maskInternalErrors         = flag.Bool("mask_internal_errors", false, "Don't return error strings with Internal Server Error HTTP responses.")
	origin                     = flag.String("origin", "", "Origin of the log, for checkpoints and the monitoring prefix.")
	bucket                     = flag.String("bucket", "", "Name of the bucket to store the log in.")
	dbName                     = flag.String("db_name", "", "AuroraDB name")
	antispamDBName             = flag.String("antispam_db_name", "", "AuroraDB antispam name")
	dbHost                     = flag.String("db_host", "", "AuroraDB host")
	dbPort                     = flag.Int("db_port", 3306, "AuroraDB port")
	dbUser                     = flag.String("db_user", "", "AuroraDB user")
	dbPassword                 = flag.String("db_password", "", "AuroraDB password")
	dbMaxConns                 = flag.Int("db_max_conns", 0, "Maximum connections to the database, defaults to 0, i.e unlimited")
	dbMaxIdle                  = flag.Int("db_max_idle_conns", 2, "Maximum idle database connections in the connection pool, defaults to 2")
	inMemoryAntispamCacheSize  = flag.Uint("inmemory_antispam_cache_size", 256<<10, "Maximum number of entries to keep in the in-memory antispam cache.")
	rootsPemFile               = flag.String("roots_pem_file", "", "Path to the file containing root certificates that are acceptable to the log. The certs are served through get-roots endpoint.")
	rejectExpired              = flag.Bool("reject_expired", false, "If true then the certificate validity period will be checked against the current time during the validation of submissions. This will cause expired certificates to be rejected.")
	rejectUnexpired            = flag.Bool("reject_unexpired", false, "If true then TesseraCT rejects certificates that are either currently valid or not yet valid.")
	extKeyUsages               = flag.String("ext_key_usages", "", "If set, will restrict the set of such usages that the server will accept. By default all are accepted. The values specified must be ones known to the x509 package.")
	rejectExtensions           = flag.String("reject_extension", "", "A list of X.509 extension OIDs, in dotted string form (e.g. '2.3.4.5') which, if present, should cause submissions to be rejected.")
	signerPublicKeySecretName  = flag.String("signer_public_key_secret_name", "", "Public key secret name for checkpoints and SCTs signer")
	signerPrivateKeySecretName = flag.String("signer_private_key_secret_name", "", "Private key secret name for checkpoints and SCTs signer")
	checkpointInterval         = flag.Duration("checkpoint_interval", tessera.DefaultCheckpointInterval, "Interval between checkpoint publishing")
	batchMaxSize               = flag.Uint("batch_max_size", tessera.DefaultBatchMaxSize, "Maximum number of entries to process in a single Tessera sequencing batch.")
	batchMaxAge                = flag.Duration("batch_max_age", tessera.DefaultBatchMaxAge, "Maximum age of entries in a single Tessera sequencing batch.")
	pushbackMaxOutstanding     = flag.Uint("pushback_max_outstanding", tessera.DefaultPushbackMaxOutstanding, "Maximum number of number of in-flight add requests - i.e. the number of entries with sequence numbers assigned, but which are not yet integrated into the log.")
)

// nolint:staticcheck
func main() {
	klog.InitFlags(nil)
	flag.Parse()
	ctx := context.Background()

	signer, err := NewSecretsManagerSigner(ctx, *signerPublicKeySecretName, *signerPrivateKeySecretName)
	if err != nil {
		klog.Exitf("Can't create AWS Secrets Manager signer: %v", err)
	}

	chainValidationConfig := tesseract.ChainValidationConfig{
		RootsPEMFile:     *rootsPemFile,
		RejectExpired:    *rejectExpired,
		RejectUnexpired:  *rejectUnexpired,
		ExtKeyUsages:     *extKeyUsages,
		RejectExtensions: *rejectExtensions,
		NotAfterStart:    notAfterStart.t,
		NotAfterLimit:    notAfterLimit.t,
	}

	logHandler, err := tesseract.NewLogHandler(ctx, *origin, signer, chainValidationConfig, newAWSStorage, *httpDeadline, *maskInternalErrors)
	if err != nil {
		klog.Exitf("Can't initialize CT HTTP Server: %v", err)
	}

	klog.CopyStandardLogTo("WARNING")
	klog.Info("**** CT HTTP Server Starting ****")
	http.Handle("/", otelhttp.NewHandler(logHandler, "/"))

	// Bring up the HTTP server and serve until we get a signal not to.
	srv := http.Server{Addr: *httpEndpoint}
	shutdownWG := new(sync.WaitGroup)
	shutdownWG.Add(1)
	go awaitSignal(func() {
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

func newAWSStorage(ctx context.Context, signer note.Signer) (*storage.CTStorage, error) {
	awsCfg := storageConfigFromFlags()
	driver, err := taws.New(ctx, awsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AWS Tessera storage driver: %v", err)
	}

	var antispam tessera.Antispam
	if *antispamDBName != "" {
		antispam, err = aws_as.NewAntispam(ctx, antispamMySQLConfig().FormatDSN(), aws_as.AntispamOpts{})
		if err != nil {
			klog.Exitf("Failed to create new AWS antispam storage: %v", err)
		}
	}

	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithCTLayout().
		WithAntispam(*inMemoryAntispamCacheSize, antispam).
		WithCheckpointInterval(*checkpointInterval).
		WithBatching(*batchMaxSize, *batchMaxAge).
		WithPushback(*pushbackMaxOutstanding)

	appender, _, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AWS Tessera storage: %v", err)
	}

	issuerStorage, err := aws.NewIssuerStorage(ctx, *bucket, "fingerprints/", "application/pkix-cert")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AWS issuer storage: %v", err)
	}

	return storage.NewCTStorage(ctx, appender, issuerStorage, reader)
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
	if w == "" {
		return nil
	} else if !strings.HasSuffix(w, "Z") {
		return fmt.Errorf("timestamps MUST be in UTC, got %v", w)
	}
	tt, err := time.Parse(time.RFC3339, w)
	if err != nil {
		return fmt.Errorf("can't parse %q as RFC3339 timestamp: %v", w, err)
	}
	t.t = &tt
	return nil
}

// storageConfigFromFlags returns an aws.Config struct populated with values
// provided via flags.
func storageConfigFromFlags() taws.Config {
	if *bucket == "" {
		klog.Exit("--bucket must be set")
	}
	if *dbName == "" {
		klog.Exit("--db_name must be set")
	}
	if *dbHost == "" {
		klog.Exit("--db_host must be set")
	}
	if *dbPort == 0 {
		klog.Exit("--db_port must be set")
	}
	if *dbUser == "" {
		klog.Exit("--db_user must be set")
	}
	// Empty password isn't an option with AuroraDB MySQL.
	if *dbPassword == "" {
		klog.Exit("--db_password must be set")
	}

	c := mysql.Config{
		User:                    *dbUser,
		Passwd:                  *dbPassword,
		Net:                     "tcp",
		Addr:                    fmt.Sprintf("%s:%d", *dbHost, *dbPort),
		DBName:                  *dbName,
		AllowCleartextPasswords: true,
		AllowNativePasswords:    true,
	}

	return taws.Config{
		Bucket:       *bucket,
		DSN:          c.FormatDSN(),
		MaxOpenConns: *dbMaxConns,
		MaxIdleConns: *dbMaxIdle,
	}
}

func antispamMySQLConfig() *mysql.Config {
	if *antispamDBName == "" {
		klog.Exit("--antispam_db_name must be set")
	}
	if *dbHost == "" {
		klog.Exit("--db_host must be set")
	}
	if *dbPort == 0 {
		klog.Exit("--db_port must be set")
	}
	if *dbUser == "" {
		klog.Exit("--db_user must be set")
	}
	// Empty passord isn't an option with AuroraDB MySQL.
	if *dbPassword == "" {
		klog.Exit("--db_password must be set")
	}

	return &mysql.Config{
		User:                    *dbUser,
		Passwd:                  *dbPassword,
		Net:                     "tcp",
		Addr:                    fmt.Sprintf("%s:%d", *dbHost, *dbPort),
		DBName:                  *antispamDBName,
		AllowCleartextPasswords: true,
		AllowNativePasswords:    true,
	}
}
