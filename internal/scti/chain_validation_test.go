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
	"crypto/md5"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/static-ct/internal/testdata"
	"github.com/transparency-dev/static-ct/internal/types"
	"github.com/transparency-dev/static-ct/internal/x509util"
)

func wipeExtensions(cert *x509.Certificate) *x509.Certificate {
	cert.Extensions = cert.Extensions[:0]
	return cert
}

func makePoisonNonCritical(cert *x509.Certificate) *x509.Certificate {
	// Invalid as a pre-cert because poison extension needs to be marked as critical.
	cert.Extensions = []pkix.Extension{{Id: types.OIDExtensionCTPoison, Critical: false, Value: asn1.NullBytes}}
	return cert
}

func makePoisonNonNull(cert *x509.Certificate) *x509.Certificate {
	// Invalid as a pre-cert because poison extension is not ASN.1 NULL value.
	cert.Extensions = []pkix.Extension{{Id: types.OIDExtensionCTPoison, Critical: false, Value: []byte{0x42, 0x42, 0x42}}}
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
					t.Logf("Subject: %s Issuer: %s", c.Subject, c.Issuer)
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
	if err != nil {
		t.Fatalf("x509.ParseCertificate(): %v", err)
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

// Validate a chain including a pre-issuer.
func TestPreIssuedCert(t *testing.T) {
	// TODO(phboneff): define this chain in certificates.go
	// TODO(phboneff): add a test to make sure that a pre-isser can't sign an end cert.
	var b64Chain = []string{
		// certs come from internal/testadata
		"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",
	}
	rawChain := make([][]byte, len(b64Chain))
	for i, b64Data := range b64Chain {
		var err error
		rawChain[i], err = base64.StdEncoding.DecodeString(b64Data)
		if err != nil {
			t.Fatalf("failed to base64.Decode(chain[%d]): %v", i, err)
		}
	}

	root, err := x509.ParseCertificate(rawChain[len(rawChain)-1])
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}
	cmRoot := x509util.NewPEMCertPool()
	cmRoot.AddCert(root)

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
				trustedRoots: cmRoot,
				extKeyUsages: tc.eku,
			}
			chain, err := validateChain(rawChain, opts)
			if err != nil {
				t.Fatalf("failed to ValidateChain: %v", err)
			}
			for i, c := range chain {
				t.Logf("chain[%d] = \n%s", i, md5.Sum(c.Raw))
			}
		})
	}
}
