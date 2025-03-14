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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/transparency-dev/static-ct/internal/x509util"
	"k8s.io/klog/v2"
)

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

// ParseExtKeyUsages parses strings into x509ExtKeyUsage.
// Throws an error if the string does not match with a known key usage.
// TODO(phboneff): add tests
func ParseExtKeyUsages(kus []string) ([]x509.ExtKeyUsage, error) {
	lExtKeyUsages := make([]x509.ExtKeyUsage, 0, len(kus))
	// Validate the extended key usages list.
	for _, kuStr := range kus {
		if ku, ok := stringToKeyUsage[kuStr]; ok {
			// If "Any" is specified, then we can ignore the entire list and
			// just disable EKU checking.
			if ku == x509.ExtKeyUsageAny {
				klog.Info("Found ExtKeyUsageAny, allowing all EKUs")
				lExtKeyUsages = nil
				break
			}
			lExtKeyUsages = append(lExtKeyUsages, ku)
		} else {
			return nil, fmt.Errorf("unknown extended key usage: %s", kuStr)
		}
	}
	return lExtKeyUsages, nil
}

// ParseOIDs parses strings of dot seaparated numbers into OIDs.
// TODO(phboneff): add tests
func ParseOIDs(oids []string) ([]asn1.ObjectIdentifier, error) {
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

// ChainValidationOpts contains various parameters for certificate chain validation
type ChainValidationOpts struct {
	// trustedRoots is a pool of certificates that defines the roots the CT log will accept
	trustedRoots *x509util.PEMCertPool
	// currentTime is the time used for checking a certificate's validity period
	// against. If it's zero then time.Now() is used. Only for testing.
	// TODO(phboneff): check if I can remove this or align it with the other time definition.
	currentTime time.Time
	// rejectExpired indicates that expired certificates will be rejected.
	rejectExpired bool
	// rejectUnexpired indicates that certificates that are currently valid or not yet valid will be rejected.
	rejectUnexpired bool
	// notAfterStart is the earliest notAfter date which will be accepted.
	// nil means no lower bound on the accepted range.
	notAfterStart *time.Time
	// notAfterLimit defines the cut off point of notAfter dates - only notAfter
	// dates strictly *before* notAfterLimit will be accepted.
	// nil means no upper bound on the accepted range.
	notAfterLimit *time.Time
	// extKeyUsages contains the list of EKUs to use during chain verification
	extKeyUsages []x509.ExtKeyUsage
	// rejectExtIds contains a list of X.509 extension IDs to reject during chain verification.
	rejectExtIds []asn1.ObjectIdentifier
}

func NewChainValidationOpts(trustedRoots *x509util.PEMCertPool, rejectExpired, rejectUnexpired bool, notAfterStart, notAfterLimit *time.Time, extKeyUsages []x509.ExtKeyUsage, rejectExtIds []asn1.ObjectIdentifier) ChainValidationOpts {
	return ChainValidationOpts{
		trustedRoots:    trustedRoots,
		rejectExpired:   rejectExpired,
		rejectUnexpired: rejectUnexpired,
		notAfterStart:   notAfterStart,
		notAfterLimit:   notAfterLimit,
		extKeyUsages:    extKeyUsages,
		rejectExtIds:    rejectExtIds,
	}
}

// isPrecertificate tests if a certificate is a pre-certificate as defined in CT.
// An error is returned if the CT extension is present but is not ASN.1 NULL as defined
// by the spec.
func isPrecertificate(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, errors.New("nil certificate")
	}

	for _, ext := range cert.Extensions {
		if x509.OIDExtensionCTPoison.Equal(ext.Id) {
			if !ext.Critical || !bytes.Equal(asn1.NullBytes, ext.Value) {
				return false, fmt.Errorf("CT poison ext is not critical or invalid: %v", ext)
			}

			return true, nil
		}
	}

	return false, nil
}

// validateChain takes the certificate chain as it was parsed from a JSON request. Ensures all
// elements in the chain decode as X.509 certificates. Ensures that there is a valid path from the
// end entity certificate in the chain to a trusted root cert, possibly using the intermediates
// supplied in the chain. Then applies the RFC requirement that the path must involve all
// the submitted chain in the order of submission.
// TODO(phboneff): make this a method func([][]byte) ([]*x509.Certificate, error)
func validateChain(rawChain [][]byte, validationOpts ChainValidationOpts) ([]*x509.Certificate, error) {
	// First make sure the certs parse as X.509
	chain := make([]*x509.Certificate, 0, len(rawChain))
	intermediatePool := x509util.NewPEMCertPool()

	for i, certBytes := range rawChain {
		cert, err := x509.ParseCertificate(certBytes)
		if x509.IsFatal(err) {
			return nil, err
		}

		chain = append(chain, cert)

		// All but the first cert form part of the intermediate pool
		if i > 0 {
			intermediatePool.AddCert(cert)
		}
	}

	naStart := validationOpts.notAfterStart
	naLimit := validationOpts.notAfterLimit
	cert := chain[0]

	// Check whether the expiry date of the cert is within the acceptable range.
	if naStart != nil && cert.NotAfter.Before(*naStart) {
		return nil, fmt.Errorf("certificate NotAfter (%v) < %v", cert.NotAfter, *naStart)
	}
	if naLimit != nil && !cert.NotAfter.Before(*naLimit) {
		return nil, fmt.Errorf("certificate NotAfter (%v) >= %v", cert.NotAfter, *naLimit)
	}

	now := validationOpts.currentTime
	if now.IsZero() {
		now = time.Now()
	}
	expired := now.After(cert.NotAfter)
	if validationOpts.rejectExpired && expired {
		return nil, errors.New("rejecting expired certificate")
	}
	if validationOpts.rejectUnexpired && !expired {
		return nil, errors.New("rejecting unexpired certificate")
	}

	// Check for unwanted extension types, if required.
	// TODO(al): Refactor CertValidationOpts c'tor to a builder pattern and
	// pre-calc this in there
	if len(validationOpts.rejectExtIds) != 0 {
		badIDs := make(map[string]bool)
		for _, id := range validationOpts.rejectExtIds {
			badIDs[id.String()] = true
		}
		for idx, ext := range cert.Extensions {
			extOid := ext.Id.String()
			if _, ok := badIDs[extOid]; ok {
				return nil, fmt.Errorf("rejecting certificate containing extension %v at index %d", extOid, idx)
			}
		}
	}

	// TODO(al): Refactor CertValidationOpts c'tor to a builder pattern and
	// pre-calc this in there too.
	if len(validationOpts.extKeyUsages) > 0 {
		acceptEKUs := make(map[x509.ExtKeyUsage]bool)
		for _, eku := range validationOpts.extKeyUsages {
			acceptEKUs[eku] = true
		}
		good := false
		for _, certEKU := range cert.ExtKeyUsage {
			if _, ok := acceptEKUs[certEKU]; ok {
				good = true
				break
			}
		}
		if !good {
			return nil, fmt.Errorf("rejecting certificate without EKU in %v", validationOpts.extKeyUsages)
		}
	}

	// We can now do the verification.  Use fairly lax options for verification, as
	// CT is intended to observe certificates rather than police them.
	verifyOpts := x509.VerifyOptions{
		Roots:             validationOpts.trustedRoots.CertPool(),
		CurrentTime:       now,
		Intermediates:     intermediatePool.CertPool(),
		DisableTimeChecks: true,
		// Precertificates have the poison extension; also the Go library code does not
		// support the standard PolicyConstraints extension (which is required to be marked
		// critical, RFC 5280 s4.2.1.11), so never check unhandled critical extensions.
		DisableCriticalExtensionChecks: true,
		// Pre-issued precertificates have the Certificate Transparency EKU; also some
		// leaves have unknown EKUs that should not be bounced just because the intermediate
		// does not also have them (cf. https://github.com/golang/go/issues/24590) so
		// disable EKU checks inside the x509 library, but we've already done our own check
		// on the leaf above.
		DisableEKUChecks: true,
		// Path length checks get confused by the presence of an additional
		// pre-issuer intermediate, so disable them.
		DisablePathLenChecks:        true,
		DisableNameConstraintChecks: true,
		DisableNameChecks:           false,
		KeyUsages:                   validationOpts.extKeyUsages,
	}

	verifiedChains, err := cert.Verify(verifyOpts)
	if err != nil {
		return nil, err
	}

	if len(verifiedChains) == 0 {
		return nil, errors.New("no path to root found when trying to validate chains")
	}

	// Verify might have found multiple paths to roots. Now we check that we have a path that
	// uses all the certs in the order they were submitted so as to comply with RFC 6962
	// requirements detailed in Section 3.1.
	for _, verifiedChain := range verifiedChains {
		if chainsEquivalent(chain, verifiedChain) {
			return verifiedChain, nil
		}
	}

	return nil, errors.New("no RFC compliant path to root found when trying to validate chain")
}

func chainsEquivalent(inChain []*x509.Certificate, verifiedChain []*x509.Certificate) bool {
	// The verified chain includes a root, but the input chain may or may not include a
	// root (RFC 6962 s4.1/ s4.2 "the last [certificate] is either the root certificate
	// or a certificate that chains to a known root certificate").
	if len(inChain) != len(verifiedChain) && len(inChain) != (len(verifiedChain)-1) {
		return false
	}

	for i, certInChain := range inChain {
		if !certInChain.Equal(verifiedChain[i]) {
			return false
		}
	}
	return true
}
