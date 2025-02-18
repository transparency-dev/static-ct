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

// hammer is a tool to load test a Static CT API log.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/static-ct/internal/client"
	"github.com/transparency-dev/static-ct/internal/hammer/loadtest"
	"golang.org/x/net/http2"

	"k8s.io/klog/v2"
)

func init() {
	flag.Var(&logURL, "log_url", "Log storage root URL (can be specified multiple times), e.g. https://log.server/and/path/")
	flag.Var(&writeLogURL, "write_log_url", "Root URL for writing to a log (can be specified multiple times), e.g. https://log.server/and/path/ (optional, defaults to log_url)")
}

var (
	logURL      multiStringFlag
	writeLogURL multiStringFlag

	logPubKey                 = flag.String("log_public_key", os.Getenv("TILES_LOG_PUBLIC_KEY"), "Public key for the log. This is defaulted to the environment variable TILES_LOG_PUBLIC_KEY")
	intermediateCACertPath    = flag.String("intermediate_ca_cert_path", "./internal/hammer/testdata/test_intermediate_ca_cert.pem", "Intermediate CA certificate path for certificate generator")
	intermediateCAKeyPath     = flag.String("intermediate_ca_key_path", "./internal/hammer/testdata/test_intermediate_ca_private_key.pem", "Intermediate CA key path for certificate generator (Only RSA/Ed25519 are accepted)")
	certSigningPrivateKeyPath = flag.String("cert_sign_private_key_path", "./internal/hammer/testdata/test_leaf_cert_signing_private_key.pem", "Certificate signing private key path for certificate generator (Only RSA/Ed25519 are accepted)")

	maxReadOpsPerSecond = flag.Int("max_read_ops", 20, "The maximum number of read operations per second")
	numReadersRandom    = flag.Int("num_readers_random", 4, "The number of readers looking for random leaves")
	numReadersFull      = flag.Int("num_readers_full", 4, "The number of readers downloading the whole log")

	maxWriteOpsPerSecond = flag.Int("max_write_ops", 0, "The maximum number of write operations per second")
	numWriters           = flag.Int("num_writers", 0, "The number of independent write tasks to run")

	dupChance = flag.Float64("dup_chance", 0.1, "The probability of a generated leaf being a duplicate of a previous value")

	leafWriteGoal = flag.Int64("leaf_write_goal", 0, "Exit after writing this number of leaves, or 0 to keep going indefinitely")
	maxRunTime    = flag.Duration("max_runtime", 0, "Fail after this amount of time has passed, or 0 to keep going indefinitely")

	showUI = flag.Bool("show_ui", true, "Set to false to disable the text-based UI")

	bearerToken      = flag.String("bearer_token", "", "The bearer token for auth. For GCP this is the result of `gcloud auth print-access-token`")
	bearerTokenWrite = flag.String("bearer_token_write", "", "The bearer token for auth to write. For GCP this is the result of `gcloud auth print-identity-token`. If unset will default to --bearer_token.")

	forceHTTP2 = flag.Bool("force_http2", false, "Use HTTP/2 connections *only*")

	hc = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 256,
			DisableKeepAlives:   false,
		},
		Timeout: 5 * time.Second,
	}
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *forceHTTP2 {
		hc.Transport = &http2.Transport{
			TLSClientConfig: &tls.Config{},
		}
	}

	// If bearerTokenWrite is unset, default it to whatever bearerToken has (which may too be unset).
	if *bearerTokenWrite == "" {
		*bearerTokenWrite = *bearerToken
	}

	ctx, cancel := context.WithCancel(context.Background())

	logSigV, err := note.NewVerifier(*logPubKey)
	if err != nil {
		klog.Exitf("failed to create verifier: %v", err)
	}

	f, w, err := loadtest.NewLogClients(logURL, writeLogURL, loadtest.ClientOpts{
		Client:           hc,
		BearerToken:      *bearerToken,
		BearerTokenWrite: *bearerTokenWrite,
	})
	if err != nil {
		klog.Exit(err)
	}

	var cpRaw []byte
	cons := client.UnilateralConsensus(f.ReadCheckpoint)
	tracker, err := client.NewLogStateTracker(ctx, f.ReadCheckpoint, f.ReadTile, cpRaw, logSigV, logSigV.Name(), cons)
	if err != nil {
		klog.Exitf("Failed to create LogStateTracker: %v", err)
	}
	// Fetch initial state of log
	_, _, _, err = tracker.Update(ctx)
	if err != nil {
		klog.Exitf("Failed to get initial state of the log: %v", err)
	}

	ha := loadtest.NewHammerAnalyser(func() uint64 { return tracker.LatestConsistent.Size })
	ha.Run(ctx)

	intermediateCACert, err := loadIntermediateCACert(*intermediateCACertPath)
	if err != nil {
		klog.Exitf("Failed to load intermediate CA certificate from %s: %v", *intermediateCACertPath, err)
	}
	intermediateCAKey, err := loadPrivateKey(*intermediateCAKeyPath)
	if err != nil {
		klog.Exitf("Failed to load intermediate CA private key from %s: %v", *intermediateCAKeyPath, err)
	}
	privateKey, err := loadPrivateKey(*certSigningPrivateKeyPath)
	if err != nil {
		klog.Exitf("Failed to load certificate signing private key from %s: %v", *certSigningPrivateKeyPath, err)
	}

	gen := newLeafGenerator(tracker.LatestConsistent.Size, *dupChance, intermediateCACert, intermediateCAKey, privateKey)
	opts := loadtest.HammerOpts{
		MaxReadOpsPerSecond:  *maxReadOpsPerSecond,
		MaxWriteOpsPerSecond: *maxWriteOpsPerSecond,
		NumReadersRandom:     *numReadersRandom,
		NumReadersFull:       *numReadersFull,
		NumWriters:           *numWriters,
	}
	hammer := loadtest.NewHammer(&tracker, f.ReadEntryBundle, w, gen, ha.SeqLeafChan, ha.ErrChan, opts)

	exitCode := 0
	if *leafWriteGoal > 0 {
		go func() {
			startTime := time.Now()
			goal := tracker.LatestConsistent.Size + uint64(*leafWriteGoal)
			klog.Infof("Will exit once tree size is at least %d", goal)
			tick := time.NewTicker(1 * time.Second)
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if tracker.LatestConsistent.Size >= goal {
						elapsed := time.Since(startTime)
						klog.Infof("Reached tree size goal of %d after %s; exiting", goal, elapsed)
						cancel()
						return
					}
				}
			}
		}()
	}
	if *maxRunTime > 0 {
		go func() {
			klog.Infof("Will fail after %s", *maxRunTime)
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(*maxRunTime):
					klog.Infof("Max runtime reached; exiting")
					exitCode = 1
					cancel()
					return
				}
			}
		}()
	}
	hammer.Run(ctx)

	if *showUI {
		c := loadtest.NewController(hammer, ha)
		c.Run(ctx)
	} else {
		<-ctx.Done()
	}
	os.Exit(exitCode)
}

// newLeafGenerator returns a function that generates values to append to a log.
// The generator can be used by concurrent threads.
//
// dupChance provides the probability that a new leaf will be a duplicate of a previous entry.
// Leaves will be unique if dupChance is 0, and if set to 1 then all values will be duplicates.
// startSize should be set to the initial size of the log so that repeated runs of the
// hammer can start seeding leaves to avoid duplicates with previous runs.
func newLeafGenerator(startSize uint64, dupChance float64, intermediateCACert *x509.Certificate, intermediateCAKey, leafCertSigningPrivateKey any) func() []byte {
	certGen := newChainGenerator(intermediateCACert, intermediateCAKey, publicKey(leafCertSigningPrivateKey))

	sizeLocked := startSize
	var mu sync.Mutex
	return func() []byte {
		mu.Lock()
		thisSize := sizeLocked

		if thisSize > 0 && rand.Float64() <= dupChance {
			thisSize = rand.Uint64N(thisSize)
		} else {
			sizeLocked++
		}
		mu.Unlock()

		// Do this outside of the protected block so that writers don't block on leaf generation (especially for larger leaves).
		return certGen.addChainRequestBody(int64(thisSize))
	}
}

// multiStringFlag allows a flag to be specified multiple times on the command
// line, and stores all of these values.
type multiStringFlag []string

func (ms *multiStringFlag) String() string {
	return strings.Join(*ms, ",")
}

func (ms *multiStringFlag) Set(w string) error {
	*ms = append(*ms, w)
	return nil
}

func loadPrivateKey(path string) (any, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err == nil {
			return key, nil
		}
		rsaKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err == nil {
			return rsaKey, nil
		}

		ecKey, err := x509.ParseECPrivateKey(keyBytes)
		if err == nil {
			return ecKey, nil
		}

		return nil, fmt.Errorf("failed to decode PEM block and failed to parse as DER: %w", err)
	}

	// Fix block type for testing keys.
	block.Type = testingKey(block.Type)

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func loadIntermediateCACert(path string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, rest := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected PEM block type 'CERTIFICATE', got '%s'", block.Type)
	}
	if len(rest) > 0 {
		klog.Info("Warning: More than one PEM block found. Parsing only the first.")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	return cert, nil
}

// publicKey returns the public key associated with the private key.
func publicKey(privKey any) any {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return k.Public()
	case *ecdsa.PrivateKey:
		return k.Public()
	case *ed25519.PrivateKey:
		return k.Public()
	default:
		klog.Fatalf("Unknown private key type: %T", privKey)
		return nil // Or panic, or return an error
	}
}

func testingKey(s string) string {
	return strings.ReplaceAll(s, "TEST PRIVATE KEY", "PRIVATE KEY")
}
