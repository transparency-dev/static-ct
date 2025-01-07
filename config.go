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
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog/v2"
)

type ChainValidationConfig struct {
	// Path to the file containing root certificates that are acceptable to the
	// log. The certs are served through get-roots endpoint.
	RootsPemFile string
	// If RejectExpired is true then the certificate validity period will be
	// checked against the current time during the validation of submissions.
	// This will cause expired certificates to be rejected.
	RejectExpired bool
	// If RejectUnexpired is true then CTFE rejects certificates that are either
	// currently valid or not yet valid.
	RejectUnexpired bool
	// If set, ExtKeyUsages will restrict the set of such usages that the
	// server will accept. By default all are accepted. The values specified
	// must be ones known to the x509 package, comma separated.
	ExtKeyUsages string
	// A comma separated list of X.509 extension OIDs, in dotted string form
	// (e.g. "2.3.4.5") which, if present, should cause submissions to be
	// rejected.
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

// ValidatedLogConfig represents the LogConfig with the information that has
// been successfully parsed as a result of validating it.
type ValidatedLogConfig struct {
	// Origin identifies the log. It will be used in its checkpoint, and
	// is also its submission prefix, as per https://c2sp.org/static-ct-api.
	Origin string
	// Used to sign the checkpoint and SCTs.
	Signer crypto.Signer
	// CertValidationOpts contains various parameters for certificate chain
	// validation.
	CertValidationOpts CertValidationOpts
}

// ValidateLogConfig checks that a single log config is valid. In particular:
//   - A log has a private, and optionally a public key (both valid).
//   - Each of NotBeforeStart and NotBeforeLimit, if set, is a valid timestamp
//     proto. If both are set then NotBeforeStart <= NotBeforeLimit.
//   - Merge delays (if present) are correct.
//
// Returns the validated structures (useful to avoid double validation).
// TODO(phboneff): change the name of this function.
func ValidateLogConfig(cfg ChainValidationConfig, origin string, signer crypto.Signer) (*ValidatedLogConfig, error) {
	if origin == "" {
		return nil, errors.New("empty origin")
	}

	// Load the trusted roots.
	if cfg.RootsPemFile == "" {
		return nil, errors.New("empty rootsPemFile")
	}
	roots := x509util.NewPEMCertPool()
	if err := roots.AppendCertsFromPEMFile(cfg.RootsPemFile); err != nil {
		return nil, fmt.Errorf("failed to read trusted roots: %v", err)
	}

	// Validate signer that only ECDSA is supported.
	if signer == nil {
		return nil, errors.New("empty signer")
	}
	switch keyType := signer.Public().(type) {
	case *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	if cfg.RejectExpired && cfg.RejectUnexpired {
		return nil, errors.New("configuration would reject all certificates")
	}

	// Validate the time interval.
	if cfg.NotAfterStart != nil && cfg.NotAfterLimit != nil && (cfg.NotAfterLimit).Before(*cfg.NotAfterStart) {
		return nil, fmt.Errorf("'Not After' limit %q before start %q", cfg.NotAfterLimit.Format(time.RFC3339), cfg.NotAfterStart.Format(time.RFC3339))
	}

	validationOpts := CertValidationOpts{
		trustedRoots:    roots,
		rejectExpired:   cfg.RejectExpired,
		rejectUnexpired: cfg.RejectUnexpired,
		notAfterStart:   cfg.NotAfterStart,
		notAfterLimit:   cfg.NotAfterLimit,
	}

	// Filter which extended key usages are allowed.
	lExtKeyUsages := []string{}
	if cfg.ExtKeyUsages != "" {
		lExtKeyUsages = strings.Split(cfg.ExtKeyUsages, ",")
	}
	// Validate the extended key usages list.
	for _, kuStr := range lExtKeyUsages {
		if ku, ok := stringToKeyUsage[kuStr]; ok {
			// If "Any" is specified, then we can ignore the entire list and
			// just disable EKU checking.
			if ku == x509.ExtKeyUsageAny {
				klog.Infof("%s: Found ExtKeyUsageAny, allowing all EKUs", origin)
				validationOpts.extKeyUsages = nil
				break
			}
			validationOpts.extKeyUsages = append(validationOpts.extKeyUsages, ku)
		} else {
			return nil, fmt.Errorf("unknown extended key usage: %s", kuStr)
		}
	}
	// Filter which extensions are rejected.
	var err error
	if cfg.RejectExtensions != "" {
		lRejectExtensions := strings.Split(cfg.RejectExtensions, ",")
		validationOpts.rejectExtIds, err = parseOIDs(lRejectExtensions)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RejectExtensions: %v", err)
		}
	}

	vCfg := ValidatedLogConfig{
		Origin:             origin,
		Signer:             signer,
		CertValidationOpts: validationOpts,
	}

	return &vCfg, nil
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

var stringToKeyUsage = map[string]x509.ExtKeyUsage{
	"Any":                        x509.ExtKeyUsageAny,
	"ServerAuth":                 x509.ExtKeyUsageServerAuth,
	"ClientAuth":                 x509.ExtKeyUsageClientAuth,
	"CodeSigning":                x509.ExtKeyUsageCodeSigning,
	"EmailProtection":            x509.ExtKeyUsageEmailProtection,
	"IPSECEndSystem":             x509.ExtKeyUsageIPSECEndSystem,
	"IPSECTunnel":                x509.ExtKeyUsageIPSECTunnel,
	"IPSECUser":                  x509.ExtKeyUsageIPSECUser,
	"TimeStamping":               x509.ExtKeyUsageTimeStamping,
	"OCSPSigning":                x509.ExtKeyUsageOCSPSigning,
	"MicrosoftServerGatedCrypto": x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"NetscapeServerGatedCrypto":  x509.ExtKeyUsageNetscapeServerGatedCrypto,
}
