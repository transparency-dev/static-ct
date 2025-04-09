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
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/transparency-dev/static-ct/internal/scti"
	"github.com/transparency-dev/static-ct/internal/x509util"
	"github.com/transparency-dev/static-ct/storage"
)

// ChainValidationConfig contains parameters to configure chain validation.
type ChainValidationConfig struct {
	// RootsPEMFile is the path to the file containing root certificates that
	// are acceptable to the log. The certs are served through get-roots
	// endpoint.
	RootsPEMFile string
	// RejectExpired controls if true then the certificate validity period will be
	// checked against the current time during the validation of submissions.
	// This will cause expired certificates to be rejected.
	RejectExpired bool
	// RejectUnexpired controls if the SCTFE rejects certificates that are
	// either currently valid or not yet valid.
	// TODO(phboneff): evaluate whether we need to keep this one.
	RejectUnexpired bool
	// ExtKeyUsages lists Extended Key Usage values that newly submitted
	// certificates MUST contain. By default all are accepted. The
	// values specified must be ones known to the x509 package, comma separated.
	ExtKeyUsages string
	// RejectExtensions lists X.509 extension OIDs that newly submitted
	// certificates MUST NOT contain. Empty by default. Values must be
	// specificed in dotted string form (e.g. "2.3.4.5").
	RejectExtensions string
	// NotAfterStart defines the start of the range of acceptable NotAfter
	// values, inclusive.
	// Leaving this unset implies no lower bound to the range.
	NotAfterStart *time.Time
	// NotAfterLimit defines the end of the range of acceptable NotAfter values,
	// exclusive.
	// Leaving this unset implies no upper bound to the range.
	NotAfterLimit *time.Time
}

// systemTimeSource implments scti.TimeSource.
type systemTimeSource struct{}

// Now returns the true current local time.
func (s systemTimeSource) Now() time.Time {
	return time.Now()
}

var sysTimeSource = systemTimeSource{}

// newCertValidationOpts checks that a chain validation config is valid,
// parses it, and loads resources to validate chains.
func newCertValidationOpts(cfg ChainValidationConfig) (*scti.ChainValidationOpts, error) {
	// Load the trusted roots.
	if cfg.RootsPEMFile == "" {
		return nil, errors.New("empty rootsPemFile")
	}
	roots := x509util.NewPEMCertPool()
	if err := roots.AppendCertsFromPEMFile(cfg.RootsPEMFile); err != nil {
		return nil, fmt.Errorf("failed to read trusted roots: %v", err)
	}

	if cfg.RejectExpired && cfg.RejectUnexpired {
		return nil, errors.New("configuration would reject all certificates")
	}

	// Validate the time interval.
	if cfg.NotAfterStart != nil && cfg.NotAfterLimit != nil && (cfg.NotAfterLimit).Before(*cfg.NotAfterStart) {
		return nil, fmt.Errorf("'Not After' limit %q before start %q", cfg.NotAfterLimit.Format(time.RFC3339), cfg.NotAfterStart.Format(time.RFC3339))
	}

	var err error
	var extKeyUsages []x509.ExtKeyUsage
	// Filter which extended key usages are allowed.
	if cfg.ExtKeyUsages != "" {
		lExtKeyUsages := strings.Split(cfg.ExtKeyUsages, ",")
		extKeyUsages, err = scti.ParseExtKeyUsages(lExtKeyUsages)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ExtKeyUsages: %v", err)
		}
	}

	var rejectExtIds []asn1.ObjectIdentifier
	// Filter which extensions are rejected.
	if cfg.RejectExtensions != "" {
		lRejectExtensions := strings.Split(cfg.RejectExtensions, ",")
		rejectExtIds, err = scti.ParseOIDs(lRejectExtensions)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RejectExtensions: %v", err)
		}
	}

	vOpts := scti.NewChainValidationOpts(roots, cfg.RejectExpired, cfg.RejectUnexpired, cfg.NotAfterStart, cfg.NotAfterLimit, extKeyUsages, rejectExtIds)
	return &vOpts, nil
}

// NewLogHandler creates a Tessera based CT log pluged into HTTP handlers.
// The HTTP server handlers implement https://c2sp.org/static-ct-api write
// endpoints.
func NewLogHandler(ctx context.Context, origin string, signer crypto.Signer, cfg ChainValidationConfig, cs storage.CreateStorage, httpDeadline time.Duration, maskInternalErrors bool) (http.Handler, error) {
	cvOpts, err := newCertValidationOpts(cfg)
	if err != nil {
		return nil, fmt.Errorf("newCertValidationOpts(): %v", err)
	}
	log, err := scti.NewLog(ctx, origin, signer, *cvOpts, cs, sysTimeSource)
	if err != nil {
		return nil, fmt.Errorf("newLog(): %v", err)
	}

	opts := &scti.HandlerOptions{
		Deadline:           httpDeadline,
		RequestLog:         &scti.DefaultRequestLog{},
		MaskInternalErrors: maskInternalErrors,
		TimeSource:         sysTimeSource,
	}

	handlers := scti.NewPathHandlers(ctx, opts, log)
	mux := http.NewServeMux()
	// Register handlers for all the configured logs.
	for path, handler := range handlers {
		mux.Handle(path, handler)
	}

	return mux, nil
}
