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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/trillian/monitoring"
	tnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

type createStorageFunc func(context.Context, note.Signer, note.Verifier) (*CTStorage, error)

// InstanceOptions describes the options for a log instance.
type InstanceOptions struct {
	// Validated holds the original configuration options for the log, and some
	// of its fields parsed as a result of validating it.
	Validated *ValidatedLogConfig
	// CreateStorage instantiates a Tessera storage implementation with a signer option.
	CreateStorage createStorageFunc
	// Deadline is a timeout for Tessera requests.
	Deadline time.Duration
	// MetricFactory allows creating metrics.
	MetricFactory monitoring.MetricFactory
	// RequestLog provides structured logging of CTFE requests.
	RequestLog         RequestLog
	MaskInternalErrors bool
}

// Instance is a set up log/mirror instance. It must be created with the
// SetUpInstance call.
type Instance struct {
	Handlers PathHandlers
	li       *logInfo
}

// GetPublicKey returns the public key from the instance's signer.
func (i *Instance) GetPublicKey() crypto.PublicKey {
	if i.li != nil && i.li.signer != nil {
		return i.li.signer.Public()
	}
	return nil
}

// SetUpInstance sets up a log (or log mirror) instance using the provided
// configuration, and returns an object containing a set of handlers for this
// log, and an STH getter.
func SetUpInstance(ctx context.Context, opts InstanceOptions) (*Instance, error) {
	cfg := opts.Validated

	// Load the trusted roots.
	roots := x509util.NewPEMCertPool()
	if err := roots.AppendCertsFromPEMFile(cfg.RootsPemFile); err != nil {
		return nil, fmt.Errorf("failed to read trusted roots: %v", err)
	}

	validationOpts := CertValidationOpts{
		trustedRoots:    roots,
		rejectExpired:   cfg.RejectExpired,
		rejectUnexpired: cfg.RejectUnexpired,
		notAfterStart:   cfg.NotAfterStart,
		notAfterLimit:   cfg.NotAfterLimit,
		extKeyUsages:    cfg.KeyUsages,
	}
	var err error
	validationOpts.rejectExtIds, err = parseOIDs(cfg.RejectExtensions)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RejectExtensions: %v", err)
	}

	logID, err := GetCTLogID(cfg.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to get logID for signing: %v", err)
	}
	timeSource := new(SystemTimeSource)
	ctSigner := NewCpSigner(cfg.Signer, cfg.Origin, logID, timeSource)

	vkey, err := tnote.RFC6962VerifierString(cfg.Origin, cfg.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier key: %v", err)
	}
	ctVerifier, err := tnote.NewRFC6962Verifier(vkey)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %v", err)
	}

	if opts.CreateStorage == nil {
		return nil, fmt.Errorf("failed to initiate storage backend: nil createStorage")
	}
	storage, err := opts.CreateStorage(ctx, ctSigner, ctVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate storage backend: %v", err)
	}

	logInfo := newLogInfo(opts, validationOpts, cfg.Signer, timeSource, storage)

	handlers := logInfo.Handlers(opts.Validated.Origin)
	return &Instance{Handlers: handlers, li: logInfo}, nil
}

func parseOIDs(oids []string) ([]asn1.ObjectIdentifier, error) {
	ret := make([]asn1.ObjectIdentifier, 0, len(oids))
	for _, s := range oids {
		bits := strings.Split(s, ".")
		var oid asn1.ObjectIdentifier
		for _, n := range bits {
			p, err := strconv.Atoi(n)
			if err != nil {
				return nil, err
			}
			oid = append(oid, p)
		}
		ret = append(ret, oid)
	}
	return ret, nil
}
