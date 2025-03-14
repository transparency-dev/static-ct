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
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/transparency-dev/static-ct/internal/testdata"
	"github.com/transparency-dev/static-ct/internal/x509util"
)

func wipeExtensions(cert *x509.Certificate) *x509.Certificate {
	cert.Extensions = cert.Extensions[:0]
	return cert
}

func makePoisonNonCritical(cert *x509.Certificate) *x509.Certificate {
	// Invalid as a pre-cert because poison extension needs to be marked as critical.
	cert.Extensions = []pkix.Extension{{Id: x509.OIDExtensionCTPoison, Critical: false, Value: asn1.NullBytes}}
	return cert
}

func makePoisonNonNull(cert *x509.Certificate) *x509.Certificate {
	// Invalid as a pre-cert because poison extension is not ASN.1 NULL value.
	cert.Extensions = []pkix.Extension{{Id: x509.OIDExtensionCTPoison, Critical: false, Value: []byte{0x42, 0x42, 0x42}}}
	return cert
}

func TestIsPrecertificate(t *testing.T) {
	var tests = []struct {
		desc        string
		cert        *x509.Certificate
		wantPrecert bool
		wantErr     bool
	}{
		{
			desc:        "valid-precert",
			cert:        pemToCert(t, testdata.PrecertPEMValid),
			wantPrecert: true,
		},
		{
			desc:        "valid-cert",
			cert:        pemToCert(t, testdata.CACertPEM),
			wantPrecert: false,
		},
		{
			desc:        "remove-exts-from-precert",
			cert:        wipeExtensions(pemToCert(t, testdata.PrecertPEMValid)),
			wantPrecert: false,
		},
		{
			desc:        "poison-non-critical",
			cert:        makePoisonNonCritical(pemToCert(t, testdata.PrecertPEMValid)),
			wantPrecert: false,
			wantErr:     true,
		},
		{
			desc:        "poison-non-null",
			cert:        makePoisonNonNull(pemToCert(t, testdata.PrecertPEMValid)),
			wantPrecert: false,
			wantErr:     true,
		},
	}

	for _, test := range tests {
		gotPrecert, err := isPrecertificate(test.cert)
		t.Run(test.desc, func(t *testing.T) {
			if err != nil {
				if !test.wantErr {
					t.Errorf("IsPrecertificate()=%v,%v; want %v,nil", gotPrecert, err, test.wantPrecert)
				}
				return
			}
			if test.wantErr {
				t.Errorf("IsPrecertificate()=%v,%v; want _,%v", gotPrecert, err, test.wantErr)
			}
			if gotPrecert != test.wantPrecert {
				t.Errorf("IsPrecertificate()=%v,%v; want %v,nil", gotPrecert, err, test.wantPrecert)
			}
		})
	}
}

func TestValidateChain(t *testing.T) {
	fakeCARoots := x509util.NewPEMCertPool()
	if !fakeCARoots.AppendCertsFromPEM([]byte(testdata.FakeCACertPEM)) {
		t.Fatal("failed to load fake root")
	}
	if !fakeCARoots.AppendCertsFromPEM([]byte(testdata.FakeRootCACertPEM)) {
		t.Fatal("failed to load fake root")
	}
	if !fakeCARoots.AppendCertsFromPEM([]byte(testdata.CACertPEM)) {
		t.Fatal("failed to load CA root")
	}
	if !fakeCARoots.AppendCertsFromPEM([]byte(testdata.RealPrecertIntermediatePEM)) {
		t.Fatal("failed to load real intermediate")
	}
	validateOpts := ChainValidationOpts{
		trustedRoots: fakeCARoots,
	}

	var tests = []struct {
		desc        string
		chain       [][]byte
		wantErr     bool
		wantPathLen int
		modifyOpts  func(v *ChainValidationOpts)
	}{
		{
			desc:    "missing-intermediate-cert",
			chain:   pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM}),
			wantErr: true,
		},
		{
			desc:    "wrong-cert-order",
			chain:   pemsToDERChain(t, []string{testdata.FakeIntermediateCertPEM, testdata.LeafSignedByFakeIntermediateCertPEM}),
			wantErr: true,
		},
		{
			desc:    "unrelated-cert-in-chain",
			chain:   pemsToDERChain(t, []string{testdata.FakeIntermediateCertPEM, testdata.TestCertPEM}),
			wantErr: true,
		},
		{
			desc:    "unrelated-cert-after-chain",
			chain:   pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM, testdata.FakeIntermediateCertPEM, testdata.TestCertPEM}),
			wantErr: true,
		},
		{
			desc:        "valid-chain",
			chain:       pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM, testdata.FakeIntermediateCertPEM}),
			wantPathLen: 3,
		},
		{
			desc:        "valid-chain-with-policyconstraints",
			chain:       pemsToDERChain(t, []string{testdata.LeafCertPEM, testdata.FakeIntermediateWithPolicyConstraintsCertPEM}),
			wantPathLen: 3,
		},
		{
			desc:        "valid-chain-with-policyconstraints-inc-root",
			chain:       pemsToDERChain(t, []string{testdata.LeafCertPEM, testdata.FakeIntermediateWithPolicyConstraintsCertPEM, testdata.FakeRootCACertPEM}),
			wantPathLen: 3,
		},
		{
			desc:        "valid-chain-with-nameconstraints",
			chain:       pemsToDERChain(t, []string{testdata.LeafCertPEM, testdata.FakeIntermediateWithNameConstraintsCertPEM}),
			wantPathLen: 3,
		},
		{
			desc:        "chain-with-invalid-nameconstraints",
			chain:       pemsToDERChain(t, []string{testdata.LeafCertPEM, testdata.FakeIntermediateWithInvalidNameConstraintsCertPEM}),
			wantPathLen: 3,
		},
		{
			desc:        "chain-of-len-4",
			chain:       pemFileToDERChain(t, "../testdata/subleaf.chain"),
			wantPathLen: 4,
		},
		{
			desc:    "misordered-chain-of-len-4",
			chain:   pemFileToDERChain(t, "../testdata/subleaf.misordered.chain"),
			wantErr: true,
		},
		{
			desc:  "reject-non-existent-ext-id",
			chain: pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM, testdata.FakeIntermediateCertPEM}),
			modifyOpts: func(v *ChainValidationOpts) {
				// reject SubjectKeyIdentifier extension
				v.rejectExtIds = []asn1.ObjectIdentifier{[]int{99, 99, 99, 99}}
			},
			wantPathLen: 3,
		},
		{
			desc:  "reject-non-existent-ext-id-precert",
			chain: pemsToDERChain(t, []string{testdata.PrecertPEMValid}),
			modifyOpts: func(v *ChainValidationOpts) {
				// reject SubjectKeyIdentifier extension
				v.rejectExtIds = []asn1.ObjectIdentifier{[]int{99, 99, 99, 99}}
			},
			wantPathLen: 2,
		},
		{
			desc:    "reject-ext-id",
			chain:   pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM, testdata.FakeIntermediateCertPEM}),
			wantErr: true,
			modifyOpts: func(v *ChainValidationOpts) {
				// reject ExtendedKeyUsage extension
				v.rejectExtIds = []asn1.ObjectIdentifier{[]int{2, 5, 29, 37}}
			},
		},
		{
			desc:    "reject-ext-id-precert",
			chain:   pemsToDERChain(t, []string{testdata.PrecertPEMValid}),
			wantErr: true,
			modifyOpts: func(v *ChainValidationOpts) {
				// reject ExtendedKeyUsage extension
				v.rejectExtIds = []asn1.ObjectIdentifier{[]int{2, 5, 29, 37}}
			},
		},
		{
			desc:    "reject-eku-not-present-in-cert",
			chain:   pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM, testdata.FakeIntermediateCertPEM}),
			wantErr: true,
			modifyOpts: func(v *ChainValidationOpts) {
				// reject cert without ExtKeyUsageEmailProtection
				v.extKeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
			},
		},
		{
			desc:        "allow-eku-present-in-cert",
			chain:       pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM, testdata.FakeIntermediateCertPEM}),
			wantPathLen: 3,
			modifyOpts: func(v *ChainValidationOpts) {
				v.extKeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
		},
		{
			desc:    "reject-eku-not-present-in-precert",
			chain:   pemsToDERChain(t, []string{testdata.RealPrecertWithEKUPEM}),
			wantErr: true,
			modifyOpts: func(v *ChainValidationOpts) {
				// reject cert without ExtKeyUsageEmailProtection
				v.extKeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
			},
		},
		{
			desc:        "allow-eku-present-in-precert",
			chain:       pemsToDERChain(t, []string{testdata.RealPrecertWithEKUPEM}),
			wantPathLen: 2,
			modifyOpts: func(v *ChainValidationOpts) {
				v.extKeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
		},
		{
			desc:    "empty-chain",
			chain:   [][]byte{},
			wantErr: true,
		},
		{
			desc:    "nil-chain",
			chain:   nil,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			validateOpts := validateOpts
			if test.modifyOpts != nil {
				test.modifyOpts(&validateOpts)
			}
			gotPath, err := validateChain(test.chain, validateOpts)
			if err != nil {
				if !test.wantErr {
					t.Errorf("ValidateChain()=%v,%v; want _,nil", gotPath, err)
				}
				return
			}
			if test.wantErr {
				t.Errorf("ValidateChain()=%v,%v; want _,non-nil", gotPath, err)
				return
			}
			if len(gotPath) != test.wantPathLen {
				t.Errorf("|ValidateChain()|=%d; want %d", len(gotPath), test.wantPathLen)
				for _, c := range gotPath {
					t.Logf("Subject: %s Issuer: %s", x509util.NameToString(c.Subject), x509util.NameToString(c.Issuer))
				}
			}
		})
	}
}

func TestNotAfterRange(t *testing.T) {
	fakeCARoots := x509util.NewPEMCertPool()
	if !fakeCARoots.AppendCertsFromPEM([]byte(testdata.FakeCACertPEM)) {
		t.Fatal("failed to load fake root")
	}
	validateOpts := ChainValidationOpts{
		trustedRoots:  fakeCARoots,
		rejectExpired: false,
	}

	chain := pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM, testdata.FakeIntermediateCertPEM})

	var tests = []struct {
		desc          string
		chain         [][]byte
		notAfterStart time.Time
		notAfterLimit time.Time
		wantErr       bool
	}{
		{
			desc:  "valid-chain, no range",
			chain: chain,
		},
		{
			desc:          "valid-chain, valid range",
			chain:         chain,
			notAfterStart: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC),
			notAfterLimit: time.Date(2020, 7, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			desc:          "before valid range",
			chain:         chain,
			notAfterStart: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:       true,
		},
		{
			desc:          "after valid range",
			chain:         chain,
			notAfterLimit: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:       true,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			if !test.notAfterStart.IsZero() {
				validateOpts.notAfterStart = &test.notAfterStart
			}
			if !test.notAfterLimit.IsZero() {
				validateOpts.notAfterLimit = &test.notAfterLimit
			}
			gotPath, err := validateChain(test.chain, validateOpts)
			if err != nil {
				if !test.wantErr {
					t.Errorf("ValidateChain()=%v,%v; want _,nil", gotPath, err)
				}
				return
			}
			if test.wantErr {
				t.Errorf("ValidateChain()=%v,%v; want _,non-nil", gotPath, err)
			}
		})
	}
}

func TestRejectExpiredUnexpired(t *testing.T) {
	fakeCARoots := x509util.NewPEMCertPool()
	// Validity period: Jul 11, 2016 - Jul 11, 2017.
	if !fakeCARoots.AppendCertsFromPEM([]byte(testdata.FakeCACertPEM)) {
		t.Fatal("failed to load fake root")
	}
	// Validity period: May 13, 2016 - Jul 12, 2019.
	chain := pemsToDERChain(t, []string{testdata.LeafSignedByFakeIntermediateCertPEM, testdata.FakeIntermediateCertPEM})
	validateOpts := ChainValidationOpts{
		trustedRoots: fakeCARoots,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	beforeValidPeriod := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	currentValidPeriod := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	afterValidPeriod := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		desc            string
		rejectExpired   bool
		rejectUnexpired bool
		now             time.Time
		wantErr         string
	}{
		// No flags: accept anything.
		{
			desc: "no-reject-current",
			now:  currentValidPeriod,
		},
		{
			desc: "no-reject-after",
			now:  afterValidPeriod,
		},
		{
			desc: "no-reject-before",
			now:  beforeValidPeriod,
		},
		// Reject-Expired: only allow currently-valid and not yet valid
		{
			desc:          "reject-expired-current",
			rejectExpired: true,
			now:           currentValidPeriod,
		},
		{
			desc:          "reject-expired-after",
			rejectExpired: true,
			now:           afterValidPeriod,
			wantErr:       "rejecting expired certificate",
		},
		{
			desc:          "reject-expired-before",
			rejectExpired: true,
			now:           beforeValidPeriod,
		},
		// Reject-Unexpired: only allow expired
		{
			desc:            "reject-non-expired-after",
			rejectUnexpired: true,
			now:             afterValidPeriod,
		},
		{
			desc:            "reject-non-expired-before",
			rejectUnexpired: true,
			now:             beforeValidPeriod,
			wantErr:         "rejecting unexpired certificate",
		},
		{
			desc:            "reject-non-expired-current",
			rejectUnexpired: true,
			now:             currentValidPeriod,
			wantErr:         "rejecting unexpired certificate",
		},
		// Reject-Expired AND Reject-Unexpired: nothing allowed
		{
			desc:            "reject-all-after",
			rejectExpired:   true,
			rejectUnexpired: true,
			now:             afterValidPeriod,
			wantErr:         "rejecting expired certificate",
		},
		{
			desc:            "reject-all-before",
			rejectExpired:   true,
			rejectUnexpired: true,
			now:             beforeValidPeriod,
			wantErr:         "rejecting unexpired certificate",
		},
		{
			desc:            "reject-all-current",
			rejectExpired:   true,
			rejectUnexpired: true,
			now:             currentValidPeriod,
			wantErr:         "rejecting unexpired certificate",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			validateOpts.currentTime = tc.now
			validateOpts.rejectExpired = tc.rejectExpired
			validateOpts.rejectUnexpired = tc.rejectUnexpired
			_, err := validateChain(chain, validateOpts)
			if err != nil {
				if len(tc.wantErr) == 0 {
					t.Errorf("ValidateChain()=_,%v; want _,nil", err)
				} else if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("ValidateChain()=_,%v; want err containing %q", err, tc.wantErr)
				}
			} else if len(tc.wantErr) != 0 {
				t.Errorf("ValidateChain()=_,nil; want err containing %q", tc.wantErr)
			}
		})
	}
}

// Builds a chain of DER-encoded certs.
// Note: ordering is important
func pemsToDERChain(t *testing.T, pemCerts []string) [][]byte {
	t.Helper()
	chain := make([][]byte, 0, len(pemCerts))
	for _, pemCert := range pemCerts {
		cert := pemToCert(t, pemCert)
		chain = append(chain, cert.Raw)
	}
	return chain
}

func pemToCert(t *testing.T, pemData string) *x509.Certificate {
	t.Helper()
	bytes, rest := pem.Decode([]byte(pemData))
	if len(rest) > 0 {
		t.Fatalf("Extra data after PEM: %v", rest)
		return nil
	}

	cert, err := x509.ParseCertificate(bytes.Bytes)
	if x509.IsFatal(err) {
		t.Fatal(err)
	}

	return cert
}

func pemFileToDERChain(t *testing.T, filename string) [][]byte {
	t.Helper()
	rawChain, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
	if err != nil {
		t.Fatalf("failed to load testdata: %v", err)
	}
	return rawChain
}

// chainFromPEMs builds a chain from a list of PEMs.
func chainFromPEMs(t *testing.T, pems ...string) [][]byte {
	t.Helper()
	var chain [][]byte
	for _, p := range pems {
		pb := []byte(p)
		for len(p) > 0 {
			var block *pem.Block
			block, pb = pem.Decode(pb)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}
			chain = append(chain, block.Bytes)
		}
	}

	return chain
}

// Validate a chain including a pre-issuer.
func TestPreIssuedCert(t *testing.T) {
	// TODO(phboneff): add a test to make sure that a pre-isser can't sign an end cert.
	rawChain := chainFromPEMs(t, []string{
		testdata.PreCertFromPreIntermediate,
		testdata.PreIntermediateFromRoot,
		testdata.CACertPEM}...)

	roots := x509util.NewPEMCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(testdata.CACertPEM)); !ok {
		t.Fatalf("failed to parse root cert")
	}

	for _, tc := range []struct {
		desc string
		eku  []x509.ExtKeyUsage
	}{
		{
			desc: "no EKU specified",
		}, {
			desc: "EKU ServerAuth",
			eku:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			opts := ChainValidationOpts{
				trustedRoots: roots,
				extKeyUsages: tc.eku,
			}
			chain, err := validateChain(rawChain, opts)
			if err != nil {
				t.Fatalf("failed to ValidateChain: %v", err)
			}
			for i, c := range chain {
				t.Logf("chain[%d] = \n%s", i, x509util.CertificateToString(c))
			}
		})
	}
}
