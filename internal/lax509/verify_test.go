// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lax509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

type verifyTest struct {
	name          string
	leaf          string
	intermediates []string
	roots         []string
	keyUsages     []x509.ExtKeyUsage

	errorCallback  func(*testing.T, error)
	expectedChains [][]string
}

var verifyTests = []verifyTest{
	{
		name:          "Valid",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},

		expectedChains: [][]string{
			{"www.google.com", "GTS CA 1C3", "GTS Root R1"},
		},
	},
	{
		name:          "Valid (fqdn)",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},

		expectedChains: [][]string{
			{"www.google.com", "GTS CA 1C3", "GTS Root R1"},
		},
	},
	{
		name:          "MixedCase",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},

		expectedChains: [][]string{
			{"www.google.com", "GTS CA 1C3", "GTS Root R1"},
		},
	},
	{
		name:  "MissingIntermediate",
		leaf:  googleLeaf,
		roots: []string{gtsRoot},

		// Skip when using systemVerify, since Windows
		// *will* find the missing intermediate cert.
		errorCallback: expectAuthorityUnknown,
	},
	{
		name:          "RootInIntermediates",
		leaf:          googleLeaf,
		intermediates: []string{gtsRoot, gtsIntermediate},
		roots:         []string{gtsRoot},

		expectedChains: [][]string{
			{"www.google.com", "GTS CA 1C3", "GTS Root R1"},
		},
	},
	{
		name:          "InvalidHash",
		leaf:          googleLeafWithInvalidHash,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},

		errorCallback: expectHashError,
	},
	{
		name:          "EKULeafValid",
		leaf:          smimeLeaf,
		intermediates: []string{smimeIntermediate},
		roots:         []string{smimeRoot},
		keyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},

		expectedChains: [][]string{
			{"CORPORATIVO FICTICIO ACTIVO", "EAEko Herri Administrazioen CA - CA AAPP Vascas (2)", "IZENPE S.A."},
		},
	},
	{
		// Check that a name constrained intermediate works even when
		// it lists multiple constraints.
		name:          "MultipleConstraints",
		leaf:          nameConstraintsLeaf,
		intermediates: []string{nameConstraintsIntermediate1, nameConstraintsIntermediate2},
		roots:         []string{globalSignRoot},

		expectedChains: [][]string{
			{
				"udctest.ads.vt.edu",
				"Virginia Tech Global Qualified Server CA",
				"Trusted Root CA SHA256 G2",
				"GlobalSign",
			},
		},
	},
	{
		// Check that SHA-384 intermediates (which are popping up)
		// work.
		name:          "SHA-384",
		leaf:          trustAsiaLeaf,
		intermediates: []string{trustAsiaSHA384Intermediate},
		roots:         []string{digicertRoot},

		expectedChains: [][]string{
			{
				"tm.cn",
				"TrustAsia ECC OV TLS Pro CA",
				"DigiCert Global Root CA",
			},
		},
	},
	{
		// Putting a certificate as a root directly should work as a
		// way of saying “exactly this”.
		name:  "LeafInRoots",
		leaf:  selfSigned,
		roots: []string{selfSigned},

		expectedChains: [][]string{
			{"Acme Co"},
		},
	},
	{
		// An X.509 v1 certificate should not be accepted as an
		// intermediate.
		name:          "X509v1Intermediate",
		leaf:          x509v1TestLeaf,
		intermediates: []string{x509v1TestIntermediate},
		roots:         []string{x509v1TestRoot},

		errorCallback: expectNotAuthorizedError,
	},
	{
		// A certificate with an AKID should still chain to a parent without SKID.
		// See Issue 30079.
		name:  "AKIDNoSKID",
		leaf:  leafWithAKID,
		roots: []string{rootWithoutSKID},

		expectedChains: [][]string{
			{"Acme LLC", "Acme Co"},
		},
	},
	{
		// When there are two parents, one with an incorrect subject but matching SKID
		// and one with a correct subject but missing SKID, the latter should be
		// considered as a possible parent.
		leaf:  leafMatchingAKIDMatchingIssuer,
		roots: []string{rootMatchingSKIDMismatchingSubject, rootMismatchingSKIDMatchingSubject},

		expectedChains: [][]string{
			{"Leaf", "Root B"},
		},
	},
}

func expectAuthorityUnknown(t *testing.T, err error) {
	e, ok := err.(UnknownAuthorityError)
	if !ok {
		t.Fatalf("error was not UnknownAuthorityError: %v", err)
	}
	if e.Cert == nil {
		t.Fatalf("error was UnknownAuthorityError, but missing Cert: %v", err)
	}
}

func expectHashError(t *testing.T, err error) {
	if err == nil {
		t.Fatalf("no error resulted from invalid hash")
	}
	if expected := "algorithm unimplemented"; !strings.Contains(err.Error(), expected) {
		t.Fatalf("error resulting from invalid hash didn't contain '%s', rather it was: %v", expected, err)
	}
}

func expectNotAuthorizedError(t *testing.T, err error) {
	if inval, ok := err.(x509.CertificateInvalidError); !ok || inval.Reason != x509.NotAuthorizedToSign {
		t.Fatalf("error was not a NotAuthorizedToSign: %v", err)
	}
}

func certificateFromPEM(pemBytes string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func testVerify(t *testing.T, test verifyTest, useSystemRoots bool) {
	opts := VerifyOptions{
		Intermediates: NewCertPool(),
		KeyUsages:     test.keyUsages,
	}

	if !useSystemRoots {
		opts.Roots = NewCertPool()
		for j, root := range test.roots {
			ok := opts.Roots.AppendCertsFromPEM([]byte(root))
			if !ok {
				t.Fatalf("failed to parse root #%d", j)
			}
		}
	}

	for j, intermediate := range test.intermediates {
		ok := opts.Intermediates.AppendCertsFromPEM([]byte(intermediate))
		if !ok {
			t.Fatalf("failed to parse intermediate #%d", j)
		}
	}

	leaf, err := certificateFromPEM(test.leaf)
	if err != nil {
		t.Fatalf("failed to parse leaf: %v", err)
	}

	chains, err := Verify(leaf, opts)

	if test.errorCallback == nil && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if test.errorCallback != nil {
		test.errorCallback(t, err)
	}

	doesMatch := func(expectedChain []string, chain []*x509.Certificate) bool {
		if len(chain) != len(expectedChain) {
			return false
		}

		for k, cert := range chain {
			if !strings.Contains(nameToKey(&cert.Subject), expectedChain[k]) {
				return false
			}
		}
		return true
	}

	// Every expected chain should match one (or more) returned chain. We tolerate multiple
	// matches, as due to root store semantics it is plausible that (at least on the system
	// verifiers) multiple identical (looking) chains may be returned when two roots with the
	// same subject are present.
	for _, expectedChain := range test.expectedChains {
		var match bool
		for _, chain := range chains {
			if doesMatch(expectedChain, chain) {
				match = true
				break
			}
		}

		if !match {
			t.Errorf("No match found for %v", expectedChain)
		}
	}

	// Every returned chain should match 1 expected chain (or <2 if testing against the system)
	for _, chain := range chains {
		nMatched := 0
		for _, expectedChain := range test.expectedChains {
			if doesMatch(expectedChain, chain) {
				nMatched++
			}
		}
	}
}

func TestGoVerify(t *testing.T) {
	for _, test := range verifyTests {
		t.Run(test.name, func(t *testing.T) {
			testVerify(t, test, false)
		})
	}
}

func nameToKey(name *pkix.Name) string {
	return strings.Join(name.Country, ",") + "/" + strings.Join(name.Organization, ",") + "/" + strings.Join(name.OrganizationalUnit, ",") + "/" + name.CommonName
}

const gtsIntermediate = `-----BEGIN CERTIFICATE-----
MIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw
MDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp
kgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX
lOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm
BA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA
gOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL
tmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD
VR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG
CCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw
AoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt
MCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG
A1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br
aS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN
AQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ
cSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL
RklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U
+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr
PxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER
lQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs
Yye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO
z23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG
AJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw
juDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl
1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd
-----END CERTIFICATE-----`

const gtsRoot = `-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----`

const googleLeaf = `-----BEGIN CERTIFICATE-----
MIIFUjCCBDqgAwIBAgIQERmRWTzVoz0SMeozw2RM3DANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMzAxMDIwODE5MTlaFw0yMzAzMjcw
ODE5MThaMBkxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAq30odrKMT54TJikMKL8S+lwoCMT5geP0u9pWjk6a
wdB6i3kO+UE4ijCAmhbcZKeKaLnGJ38weZNwB1ayabCYyX7hDiC/nRcZU49LX5+o
55kDVaNn14YKkg2kCeX25HDxSwaOsNAIXKPTqiQL5LPvc4Twhl8HY51hhNWQrTEr
N775eYbixEULvyVLq5BLbCOpPo8n0/MTjQ32ku1jQq3GIYMJC/Rf2VW5doF6t9zs
KleflAN8OdKp0ME9OHg0T1P3yyb67T7n0SpisHbeG06AmQcKJF9g/9VPJtRf4l1Q
WRPDC+6JUqzXCxAGmIRGZ7TNMxPMBW/7DRX6w8oLKVNb0wIDAQABo4ICZzCCAmMw
DgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQC
MAAwHQYDVR0OBBYEFBnboj3lf9+Xat4oEgo6ZtIMr8ZuMB8GA1UdIwQYMBaAFIp0
f6+Fze6VzT2c0OJGFPNxNR0nMGoGCCsGAQUFBwEBBF4wXDAnBggrBgEFBQcwAYYb
aHR0cDovL29jc3AucGtpLmdvb2cvZ3RzMWMzMDEGCCsGAQUFBzAChiVodHRwOi8v
cGtpLmdvb2cvcmVwby9jZXJ0cy9ndHMxYzMuZGVyMBkGA1UdEQQSMBCCDnd3dy5n
b29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkCBQMwPAYD
VR0fBDUwMzAxoC+gLYYraHR0cDovL2NybHMucGtpLmdvb2cvZ3RzMWMzL1FPdkow
TjFzVDJBLmNybDCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AHoyjFTYty22IOo4
4FIe6YQWcDIThU070ivBOlejUutSAAABhXHHOiUAAAQDAEcwRQIgBUkikUIXdo+S
3T8PP0/cvokhUlumRE3GRWGL4WRMLpcCIQDY+bwK384mZxyXGZ5lwNRTAPNzT8Fx
1+//nbaGK3BQMAB2AOg+0No+9QY1MudXKLyJa8kD08vREWvs62nhd31tBr1uAAAB
hXHHOfQAAAQDAEcwRQIgLoVydNfMFKV9IoZR+M0UuJ2zOqbxIRum7Sn9RMPOBGMC
IQD1/BgzCSDTvYvco6kpB6ifKSbg5gcb5KTnYxQYwRW14TANBgkqhkiG9w0BAQsF
AAOCAQEA2bQQu30e3OFu0bmvQHmcqYvXBu6tF6e5b5b+hj4O+Rn7BXTTmaYX3M6p
MsfRH4YVJJMB/dc3PROR2VtnKFC6gAZX+RKM6nXnZhIlOdmQnonS1ecOL19PliUd
VXbwKjXqAO0Ljd9y9oXaXnyPyHmUJNI5YXAcxE+XXiOZhcZuMYyWmoEKJQ/XlSga
zWfTn1IcKhA3IC7A1n/5bkkWD1Xi1mdWFQ6DQDMp//667zz7pKOgFMlB93aPDjvI
c78zEqNswn6xGKXpWF5xVwdFcsx9HKhJ6UAi2bQ/KQ1yb7LPUOR6wXXWrG1cLnNP
i8eNLnKL9PXQ+5SwJFCzfEhcIZuhzg==
-----END CERTIFICATE-----`

// googleLeafWithInvalidHash is the same as googleLeaf, but the signature
// algorithm in the certificate contains a nonsense OID.
const googleLeafWithInvalidHash = `-----BEGIN CERTIFICATE-----
MIIFUjCCBDqgAwIBAgIQERmRWTzVoz0SMeozw2RM3DANBgkqhkiG9w0BAQ4FADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMzAxMDIwODE5MTlaFw0yMzAzMjcw
ODE5MThaMBkxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAq30odrKMT54TJikMKL8S+lwoCMT5geP0u9pWjk6a
wdB6i3kO+UE4ijCAmhbcZKeKaLnGJ38weZNwB1ayabCYyX7hDiC/nRcZU49LX5+o
55kDVaNn14YKkg2kCeX25HDxSwaOsNAIXKPTqiQL5LPvc4Twhl8HY51hhNWQrTEr
N775eYbixEULvyVLq5BLbCOpPo8n0/MTjQ32ku1jQq3GIYMJC/Rf2VW5doF6t9zs
KleflAN8OdKp0ME9OHg0T1P3yyb67T7n0SpisHbeG06AmQcKJF9g/9VPJtRf4l1Q
WRPDC+6JUqzXCxAGmIRGZ7TNMxPMBW/7DRX6w8oLKVNb0wIDAQABo4ICZzCCAmMw
DgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQC
MAAwHQYDVR0OBBYEFBnboj3lf9+Xat4oEgo6ZtIMr8ZuMB8GA1UdIwQYMBaAFIp0
f6+Fze6VzT2c0OJGFPNxNR0nMGoGCCsGAQUFBwEBBF4wXDAnBggrBgEFBQcwAYYb
aHR0cDovL29jc3AucGtpLmdvb2cvZ3RzMWMzMDEGCCsGAQUFBzAChiVodHRwOi8v
cGtpLmdvb2cvcmVwby9jZXJ0cy9ndHMxYzMuZGVyMBkGA1UdEQQSMBCCDnd3dy5n
b29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkCBQMwPAYD
VR0fBDUwMzAxoC+gLYYraHR0cDovL2NybHMucGtpLmdvb2cvZ3RzMWMzL1FPdkow
TjFzVDJBLmNybDCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AHoyjFTYty22IOo4
4FIe6YQWcDIThU070ivBOlejUutSAAABhXHHOiUAAAQDAEcwRQIgBUkikUIXdo+S
3T8PP0/cvokhUlumRE3GRWGL4WRMLpcCIQDY+bwK384mZxyXGZ5lwNRTAPNzT8Fx
1+//nbaGK3BQMAB2AOg+0No+9QY1MudXKLyJa8kD08vREWvs62nhd31tBr1uAAAB
hXHHOfQAAAQDAEcwRQIgLoVydNfMFKV9IoZR+M0UuJ2zOqbxIRum7Sn9RMPOBGMC
IQD1/BgzCSDTvYvco6kpB6ifKSbg5gcb5KTnYxQYwRW14TANBgkqhkiG9w0BAQ4F
AAOCAQEA2bQQu30e3OFu0bmvQHmcqYvXBu6tF6e5b5b+hj4O+Rn7BXTTmaYX3M6p
MsfRH4YVJJMB/dc3PROR2VtnKFC6gAZX+RKM6nXnZhIlOdmQnonS1ecOL19PliUd
VXbwKjXqAO0Ljd9y9oXaXnyPyHmUJNI5YXAcxE+XXiOZhcZuMYyWmoEKJQ/XlSga
zWfTn1IcKhA3IC7A1n/5bkkWD1Xi1mdWFQ6DQDMp//667zz7pKOgFMlB93aPDjvI
c78zEqNswn6xGKXpWF5xVwdFcsx9HKhJ6UAi2bQ/KQ1yb7LPUOR6wXXWrG1cLnNP
i8eNLnKL9PXQ+5SwJFCzfEhcIZuhzg==
-----END CERTIFICATE-----`

const smimeLeaf = `-----BEGIN CERTIFICATE-----
MIIIPDCCBiSgAwIBAgIQaMDxFS0pOMxZZeOBxoTJtjANBgkqhkiG9w0BAQsFADCB
nTELMAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMTowOAYDVQQLDDFB
WlogWml1cnRhZ2lyaSBwdWJsaWtvYSAtIENlcnRpZmljYWRvIHB1YmxpY28gU0NB
MTwwOgYDVQQDDDNFQUVrbyBIZXJyaSBBZG1pbmlzdHJhemlvZW4gQ0EgLSBDQSBB
QVBQIFZhc2NhcyAoMikwHhcNMTcwNzEyMDg1MzIxWhcNMjEwNzEyMDg1MzIxWjCC
AQwxDzANBgNVBAoMBklaRU5QRTE4MDYGA1UECwwvWml1cnRhZ2lyaSBrb3Jwb3Jh
dGlib2EtQ2VydGlmaWNhZG8gY29ycG9yYXRpdm8xQzBBBgNVBAsMOkNvbmRpY2lv
bmVzIGRlIHVzbyBlbiB3d3cuaXplbnBlLmNvbSBub2xhIGVyYWJpbGkgamFraXRl
a28xFzAVBgNVBC4TDi1kbmkgOTk5OTk5ODlaMSQwIgYDVQQDDBtDT1JQT1JBVElW
TyBGSUNUSUNJTyBBQ1RJVk8xFDASBgNVBCoMC0NPUlBPUkFUSVZPMREwDwYDVQQE
DAhGSUNUSUNJTzESMBAGA1UEBRMJOTk5OTk5ODlaMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwVOMwUDfBtsH0XuxYnb+v/L774jMH8valX7RPH8cl2Lb
SiqSo0RchW2RGA2d1yuYHlpChC9jGmt0X/g66/E/+q2hUJlfJtqVDJFwtFYV4u2S
yzA3J36V4PRkPQrKxAsbzZriFXAF10XgiHQz9aVeMMJ9GBhmh9+DK8Tm4cMF6i8l
+AuC35KdngPF1x0ealTYrYZplpEJFO7CiW42aLi6vQkDR2R7nmZA4AT69teqBWsK
0DZ93/f0G/3+vnWwNTBF0lB6dIXoaz8OMSyHLqGnmmAtMrzbjAr/O/WWgbB/BqhR
qjJQ7Ui16cuDldXaWQ/rkMzsxmsAox0UF+zdQNvXUQIDAQABo4IDBDCCAwAwgccG
A1UdEgSBvzCBvIYVaHR0cDovL3d3dy5pemVucGUuY29tgQ9pbmZvQGl6ZW5wZS5j
b22kgZEwgY4xRzBFBgNVBAoMPklaRU5QRSBTLkEuIC0gQ0lGIEEwMTMzNzI2MC1S
TWVyYy5WaXRvcmlhLUdhc3RlaXogVDEwNTUgRjYyIFM4MUMwQQYDVQQJDDpBdmRh
IGRlbCBNZWRpdGVycmFuZW8gRXRvcmJpZGVhIDE0IC0gMDEwMTAgVml0b3JpYS1H
YXN0ZWl6MB4GA1UdEQQXMBWBE2ZpY3RpY2lvQGl6ZW5wZS5ldXMwDgYDVR0PAQH/
BAQDAgXgMCkGA1UdJQQiMCAGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYBBAGCNxQC
AjAdBgNVHQ4EFgQUyeoOD4cgcljKY0JvrNuX2waFQLAwHwYDVR0jBBgwFoAUwKlK
90clh/+8taaJzoLSRqiJ66MwggEnBgNVHSAEggEeMIIBGjCCARYGCisGAQQB8zkB
AQEwggEGMDMGCCsGAQUFBwIBFidodHRwOi8vd3d3Lml6ZW5wZS5jb20vcnBhc2Nh
Y29ycG9yYXRpdm8wgc4GCCsGAQUFBwICMIHBGoG+Wml1cnRhZ2lyaWEgRXVza2Fs
IEF1dG9ub21pYSBFcmtpZGVnb2tvIHNla3RvcmUgcHVibGlrb2tvIGVyYWt1bmRl
ZW4gYmFybmUtc2FyZWV0YW4gYmFrYXJyaWsgZXJhYmlsIGRhaXRla2UuIFVzbyBy
ZXN0cmluZ2lkbyBhbCBhbWJpdG8gZGUgcmVkZXMgaW50ZXJuYXMgZGUgRW50aWRh
ZGVzIGRlbCBTZWN0b3IgUHVibGljbyBWYXNjbzAyBggrBgEFBQcBAQQmMCQwIgYI
KwYBBQUHMAGGFmh0dHA6Ly9vY3NwLml6ZW5wZS5jb20wOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5pemVucGUuY29tL2NnaS1iaW4vY3JsaW50ZXJuYTIwDQYJ
KoZIhvcNAQELBQADggIBAIy5PQ+UZlCRq6ig43vpHwlwuD9daAYeejV0Q+ZbgWAE
GtO0kT/ytw95ZEJMNiMw3fYfPRlh27ThqiT0VDXZJDlzmn7JZd6QFcdXkCsiuv4+
ZoXAg/QwnA3SGUUO9aVaXyuOIIuvOfb9MzoGp9xk23SMV3eiLAaLMLqwB5DTfBdt
BGI7L1MnGJBv8RfP/TL67aJ5bgq2ri4S8vGHtXSjcZ0+rCEOLJtmDNMnTZxancg3
/H5edeNd+n6Z48LO+JHRxQufbC4mVNxVLMIP9EkGUejlq4E4w6zb5NwCQczJbSWL
i31rk2orsNsDlyaLGsWZp3JSNX6RmodU4KAUPor4jUJuUhrrm3Spb73gKlV/gcIw
bCE7mML1Kss3x1ySaXsis6SZtLpGWKkW2iguPWPs0ydV6RPhmsCxieMwPPIJ87vS
5IejfgyBae7RSuAIHyNFy4uI5xwvwUFf6OZ7az8qtW7ImFOgng3Ds+W9k1S2CNTx
d0cnKTfA6IpjGo8EeHcxnIXT8NPImWaRj0qqonvYady7ci6U4m3lkNSdXNn1afgw
mYust+gxVtOZs1gk2MUCgJ1V1X+g7r/Cg7viIn6TLkLrpS1kS1hvMqkl9M+7XqPo
Qd95nJKOkusQpy99X4dF/lfbYAQnnjnqh3DLD2gvYObXFaAYFaiBKTiMTV2X72F+
-----END CERTIFICATE-----`

const smimeIntermediate = `-----BEGIN CERTIFICATE-----
MIIHNzCCBSGgAwIBAgIQJMXIqlZvjuhMvqcFXOFkpDALBgkqhkiG9w0BAQswODEL
MAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMRMwEQYDVQQDDApJemVu
cGUuY29tMB4XDTEwMTAyMDA4MjMzM1oXDTM3MTIxMjIzMDAwMFowgZ0xCzAJBgNV
BAYTAkVTMRQwEgYDVQQKDAtJWkVOUEUgUy5BLjE6MDgGA1UECwwxQVpaIFppdXJ0
YWdpcmkgcHVibGlrb2EgLSBDZXJ0aWZpY2FkbyBwdWJsaWNvIFNDQTE8MDoGA1UE
AwwzRUFFa28gSGVycmkgQWRtaW5pc3RyYXppb2VuIENBIC0gQ0EgQUFQUCBWYXNj
YXMgKDIpMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoIM7nEdI0N1h
rR5T4xuV/usKDoMIasaiKvfLhbwxaNtTt+a7W/6wV5bv3svQFIy3sUXjjdzV1nG2
To2wo/YSPQiOt8exWvOapvL21ogiof+kelWnXFjWaKJI/vThHYLgIYEMj/y4HdtU
ojI646rZwqsb4YGAopwgmkDfUh5jOhV2IcYE3TgJAYWVkj6jku9PLaIsHiarAHjD
PY8dig8a4SRv0gm5Yk7FXLmW1d14oxQBDeHZ7zOEXfpafxdEDO2SNaRJjpkh8XRr
PGqkg2y1Q3gT6b4537jz+StyDIJ3omylmlJsGCwqT7p8mEqjGJ5kC5I2VnjXKuNn
soShc72khWZVUJiJo5SGuAkNE2ZXqltBVm5Jv6QweQKsX6bkcMc4IZok4a+hx8FM
8IBpGf/I94pU6HzGXqCyc1d46drJgDY9mXa+6YDAJFl3xeXOOW2iGCfwXqhiCrKL
MYvyMZzqF3QH5q4nb3ZnehYvraeMFXJXDn+Utqp8vd2r7ShfQJz01KtM4hgKdgSg
jtW+shkVVN5ng/fPN85ovfAH2BHXFfHmQn4zKsYnLitpwYM/7S1HxlT61cdQ7Nnk
3LZTYEgAoOmEmdheklT40WAYakksXGM5VrzG7x9S7s1Tm+Vb5LSThdHC8bxxwyTb
KsDRDNJ84N9fPDO6qHnzaL2upQ43PycCAwEAAaOCAdkwggHVMIHHBgNVHREEgb8w
gbyGFWh0dHA6Ly93d3cuaXplbnBlLmNvbYEPaW5mb0BpemVucGUuY29tpIGRMIGO
MUcwRQYDVQQKDD5JWkVOUEUgUy5BLiAtIENJRiBBMDEzMzcyNjAtUk1lcmMuVml0
b3JpYS1HYXN0ZWl6IFQxMDU1IEY2MiBTODFDMEEGA1UECQw6QXZkYSBkZWwgTWVk
aXRlcnJhbmVvIEV0b3JiaWRlYSAxNCAtIDAxMDEwIFZpdG9yaWEtR2FzdGVpejAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUwKlK90cl
h/+8taaJzoLSRqiJ66MwHwYDVR0jBBgwFoAUHRxlDqjyJXu0kc/ksbHmvVV0bAUw
OgYDVR0gBDMwMTAvBgRVHSAAMCcwJQYIKwYBBQUHAgEWGWh0dHA6Ly93d3cuaXpl
bnBlLmNvbS9jcHMwNwYIKwYBBQUHAQEEKzApMCcGCCsGAQUFBzABhhtodHRwOi8v
b2NzcC5pemVucGUuY29tOjgwOTQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
bC5pemVucGUuY29tL2NnaS1iaW4vYXJsMjALBgkqhkiG9w0BAQsDggIBAMbjc3HM
3DG9ubWPkzsF0QsktukpujbTTcGk4h20G7SPRy1DiiTxrRzdAMWGjZioOP3/fKCS
M539qH0M+gsySNie+iKlbSZJUyE635T1tKw+G7bDUapjlH1xyv55NC5I6wCXGC6E
3TEP5B/E7dZD0s9E4lS511ubVZivFgOzMYo1DO96diny/N/V1enaTCpRl1qH1OyL
xUYTijV4ph2gL6exwuG7pxfRcVNHYlrRaXWfTz3F6NBKyULxrI3P/y6JAtN1GqT4
VF/+vMygx22n0DufGepBwTQz6/rr1ulSZ+eMnuJiTXgh/BzQnkUsXTb8mHII25iR
0oYF2qAsk6ecWbLiDpkHKIDHmML21MZE13MS8NSvTHoqJO4LyAmDe6SaeNHtrPlK
b6mzE1BN2ug+ZaX8wLA5IMPFaf0jKhb/Cxu8INsxjt00brsErCc9ip1VNaH0M4bi
1tGxfiew2436FaeyUxW7Pl6G5GgkNbuUc7QIoRy06DdU/U38BxW3uyJMY60zwHvS
FlKAn0OvYp4niKhAJwaBVN3kowmJuOU5Rid+TUnfyxbJ9cttSgzaF3hP/N4zgMEM
5tikXUskeckt8LUK96EH0QyssavAMECUEb/xrupyRdYWwjQGvNLq6T5+fViDGyOw
k+lzD44wofy8paAy9uC9Owae0zMEzhcsyRm7
-----END CERTIFICATE-----`

const smimeRoot = `-----BEGIN CERTIFICATE-----
MIIF8TCCA9mgAwIBAgIQALC3WhZIX7/hy/WL1xnmfTANBgkqhkiG9w0BAQsFADA4
MQswCQYDVQQGEwJFUzEUMBIGA1UECgwLSVpFTlBFIFMuQS4xEzARBgNVBAMMCkl6
ZW5wZS5jb20wHhcNMDcxMjEzMTMwODI4WhcNMzcxMjEzMDgyNzI1WjA4MQswCQYD
VQQGEwJFUzEUMBIGA1UECgwLSVpFTlBFIFMuQS4xEzARBgNVBAMMCkl6ZW5wZS5j
b20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDJ03rKDx6sp4boFmVq
scIbRTJxldn+EFvMr+eleQGPicPK8lVx93e+d5TzcqQsRNiekpsUOqHnJJAKClaO
xdgmlOHZSOEtPtoKct2jmRXagaKH9HtuJneJWK3W6wyyQXpzbm3benhB6QiIEn6H
LmYRY2xU+zydcsC8Lv/Ct90NduM61/e0aL6i9eOBbsFGb12N4E3GVFWJGjMxCrFX
uaOKmMPsOzTFlUFpfnXCPCDFYbpRR6AgkJOhkEvzTnyFRVSa0QUmQbC1TR0zvsQD
yCV8wXDbO/QJLVQnSKwv4cSsPsjLkkxTOTcj7NMB+eAJRE1NZMDhDVqHIrytG6P+
JrUV86f8hBnp7KGItERphIPzidF0BqnMC9bC3ieFUCbKF7jJeodWLBoBHmy+E60Q
rLUk9TiRodZL2vG70t5HtfG8gfZZa88ZU+mNFctKy6lvROUbQc/hhqfK0GqfvEyN
BjNaooXlkDWgYlwWTvDjovoDGrQscbNYLN57C9saD+veIR8GdwYDsMnvmfzAuU8L
hij+0rnq49qlw0dpEuDb8PYZi+17cNcC1u2HGCgsBCRMd+RIihrGO5rUD8r6ddIB
QFqNeb+Lz0vPqhbBleStTIo+F5HUsWLlguWABKQDfo2/2n+iD5dPDNMN+9fR5XJ+
HMh3/1uaD7euBUbl8agW7EekFwIDAQABo4H2MIHzMIGwBgNVHREEgagwgaWBD2lu
Zm9AaXplbnBlLmNvbaSBkTCBjjFHMEUGA1UECgw+SVpFTlBFIFMuQS4gLSBDSUYg
QTAxMzM3MjYwLVJNZXJjLlZpdG9yaWEtR2FzdGVpeiBUMTA1NSBGNjIgUzgxQzBB
BgNVBAkMOkF2ZGEgZGVsIE1lZGl0ZXJyYW5lbyBFdG9yYmlkZWEgMTQgLSAwMTAx
MCBWaXRvcmlhLUdhc3RlaXowDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFB0cZQ6o8iV7tJHP5LGx5r1VdGwFMA0GCSqGSIb3DQEBCwUA
A4ICAQB4pgwWSp9MiDrAyw6lFn2fuUhfGI8NYjb2zRlrrKvV9pF9rnHzP7MOeIWb
laQnIUdCSnxIOvVFfLMMjlF4rJUT3sb9fbgakEyrkgPH7UIBzg/YsfqikuFgba56
awmqxinuaElnMIAkejEWOVt+8Rwu3WwJrfIxwYJOubv5vr8qhT/AQKM6WfxZSzwo
JNu0FXWuDYi6LnPAvViH5ULy617uHjAimcs30cQhbIHsvm0m5hzkQiCeR7Csg1lw
LDXWrzY0tM07+DKo7+N4ifuNRSzanLh+QBxh5z6ikixL8s36mLYp//Pye6kfLqCT
VyvehQP5aTfLnnhqBbTFMXiJ7HqnheG5ezzevh55hM6fcA5ZwjUukCox2eRFekGk
LhObNA5me0mrZJfQRsN5nXJQY6aYWwa9SG3YOYNw6DXwBdGqvOPbyALqfP2C2sJb
UjWumDqtujWTI6cfSN01RpiyEGjkpTHCClguGYEQyVB1/OpaFs4R1+7vUIgtYf8/
QnMFlEPVjjxOAToZpR9GTnfQXeWBIiGH/pR9hNiTrdZoQ0iy2+tzJOeRf1SktoA+
naM8THLCV8Sg1Mw4J87VBp6iSNnpn86CcDaTmjvfliHjWbcM2pE38P1ZWrOZyGls
QyYBNWNgVYkDOnXYukrZVP/u3oDYLdE41V4tC5h9Pmzb/CaIxw==
-----END CERTIFICATE-----`

var nameConstraintsLeaf = `-----BEGIN CERTIFICATE-----
MIIG+jCCBOKgAwIBAgIQWj9gbtPPkZs65N6TKyutRjANBgkqhkiG9w0BAQsFADCB
yzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFj
a3NidXJnMSMwIQYDVQQLExpHbG9iYWwgUXVhbGlmaWVkIFNlcnZlciBDQTE8MDoG
A1UEChMzVmlyZ2luaWEgUG9seXRlY2huaWMgSW5zdGl0dXRlIGFuZCBTdGF0ZSBV
bml2ZXJzaXR5MTEwLwYDVQQDEyhWaXJnaW5pYSBUZWNoIEdsb2JhbCBRdWFsaWZp
ZWQgU2VydmVyIENBMB4XDTE4MDQyNjE5NDU1M1oXDTE5MTIxMDAwMDAwMFowgZAx
CzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tz
YnVyZzE8MDoGA1UEChMzVmlyZ2luaWEgUG9seXRlY2huaWMgSW5zdGl0dXRlIGFu
ZCBTdGF0ZSBVbml2ZXJzaXR5MRswGQYDVQQDExJ1ZGN0ZXN0LmFkcy52dC5lZHUw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCcoVBeV3AzdSGMzRWH0tuM
VluEj+sq4r9PuLDBAdgjjHi4ED8npT2/fgOalswInXspRvFS+pkEwTrmeZ7HPzRJ
HUE5YlX5Nc6WI8ZXPVg5E6GyoMy6gNlALwqsIvDCvqxBMc39oG6yOuGmQXdF6s0N
BJMrXc4aPz60s4QMWNO2OHL0pmnZqE1TxYRBHUY/dk3cfsIepIDDuSxRsNE/P/MI
pxm/uVOyiLEnPmOMsL430SZ7nC8PxUMqya9ok6Zaf7k54g7JJXDjE96VMCjMszIv
Ud9qe1PbokTOxlG/4QW7Qm0dPbiJhTUuoBzVAxzlOOkSFdXqSYKjC9tFcbr8y+pT
AgMBAAGjggIRMIICDTCBtgYIKwYBBQUHAQEEgakwgaYwXwYIKwYBBQUHMAKGU2h0
dHA6Ly93d3cucGtpLnZ0LmVkdS9nbG9iYWxxdWFsaWZpZWRzZXJ2ZXIvY2FjZXJ0
L2dsb2JhbHF1YWxpZmllZHNlcnZlcl9zaGEyNTYuY3J0MEMGCCsGAQUFBzABhjdo
dHRwOi8vdnRjYS5wa2kudnQuZWR1OjgwODAvZWpiY2EvcHVibGljd2ViL3N0YXR1
cy9vY3NwMB0GA1UdDgQWBBSzDLXee0wbgXpVQxvBQCophQDZbTAMBgNVHRMBAf8E
AjAAMB8GA1UdIwQYMBaAFLxiYCfV4zVIF+lLq0Vq0Miod3GMMGoGA1UdIARjMGEw
DgYMKwYBBAG0aAUCAgIBMA4GDCsGAQQBtGgFAgIBATA/BgwrBgEEAbRoBQICAwEw
LzAtBggrBgEFBQcCARYhaHR0cDovL3d3dy5wa2kudnQuZWR1L2dsb2JhbC9jcHMv
MEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly93d3cucGtpLnZ0LmVkdS9nbG9iYWxx
dWFsaWZpZWRzZXJ2ZXIvY3JsL2NhY3JsLmNybDAOBgNVHQ8BAf8EBAMCBeAwHQYD
VR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdEQQWMBSCEnVkY3Rlc3Qu
YWRzLnZ0LmVkdTANBgkqhkiG9w0BAQsFAAOCAgEAD79kuyZbwQJCSBOVq9lA0lj4
juHM7RMBfp2GuWvhk5F90OMKQCNdITva3oq4uQzt013TtwposYXq/d0Jobk6RHxj
OJzRZVvEPsXLvKm8oLhz7/qgI8gcVeJFR9WgdNhjN1upn++EnABHUdDR77fgixuH
FFwNC0WSZ6G0+WgYV7MKD4jYWh1DXEaJtQCN763IaWGxgvQaLUwS423xgwsx+8rw
hCRYns5u8myTbUlEu2b+GYimiogtDFMT01A7y88vKl9g+3bx42dJHQNNmSzmYPfs
IljtQbVwJIyNL/rwjoz7BTk8e9WY0qUK7ZYh+oGK8kla8yfPKtkvOJV29KdFKzTm
42kNm6cH+U5gGwEEg+Xj66Q2yFH5J9kAoBazTepgQ/13wwTY0mU9PtKVBtMH5Y/u
MoNVZz6p7vWWRrY5qSXIaW9qyF3bZnmPEHHYTplWsyAyh8blGlqPnpayDflPiQF/
9y37kax5yhT0zPZW1ZwIZ5hDTO7pu5i83bYh3pzhvJNHtv74Nn/SX1dTZrWBi/HG
OSWK3CLz8qAEBe72XGoBjBzuk9VQxg6k52qjxCyYf7CBSQpTZhsNMf0gzu+JNATc
b+XaOqJT6uI/RfqAJVe16ZeXZIFZgQlzIwRS9vobq9fqTIpH/QxqgXROGqAlbBVp
/ByH6FEe6+oH1UCklhg=
-----END CERTIFICATE-----`

var nameConstraintsIntermediate1 = `-----BEGIN CERTIFICATE-----
MIIHVTCCBj2gAwIBAgINAecHzcaPEeFvu7X4TTANBgkqhkiG9w0BAQsFADBjMQsw
CQYDVQQGEwJCRTEVMBMGA1UECxMMVHJ1c3RlZCBSb290MRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMSIwIAYDVQQDExlUcnVzdGVkIFJvb3QgQ0EgU0hBMjU2IEcy
MB4XDTE3MTIwNjAwMDAwMFoXDTIyMTIwNjAwMDAwMFowgcsxCzAJBgNVBAYTAlVT
MREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEjMCEGA1UE
CxMaR2xvYmFsIFF1YWxpZmllZCBTZXJ2ZXIgQ0ExPDA6BgNVBAoTM1Zpcmdpbmlh
IFBvbHl0ZWNobmljIEluc3RpdHV0ZSBhbmQgU3RhdGUgVW5pdmVyc2l0eTExMC8G
A1UEAxMoVmlyZ2luaWEgVGVjaCBHbG9iYWwgUXVhbGlmaWVkIFNlcnZlciBDQTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALgIZhEaptBWADBqdJ45ueFG
zMXaGHnzNxoxR1fQIaaRQNdCg4cw3A4dWKMeEgYLtsp65ai3Xfw62Qaus0+KJ3Rh
gV+rihqK81NUzkls78fJlADVDI4fCTlothsrE1CTOMiy97jKHai5mVTiWxmcxpmj
v7fm5Nhc+uHgh2hIz6npryq495mD51ZrUTIaqAQN6Pw/VHfAmR524vgriTOjtp1t
4lA9pXGWjF/vkhAKFFheOQSQ00rngo2wHgCqMla64UTN0oz70AsCYNZ3jDLx0kOP
0YmMR3Ih91VA63kLqPXA0R6yxmmhhxLZ5bcyAy1SLjr1N302MIxLM/pSy6aquEnb
ELhzqyp9yGgRyGJay96QH7c4RJY6gtcoPDbldDcHI9nXngdAL4DrZkJ9OkDkJLyq
G66WZTF5q4EIs6yMdrywz0x7QP+OXPJrjYpbeFs6tGZCFnWPFfmHCRJF8/unofYr
heq+9J7Jx3U55S/k57NXbAM1RAJOuMTlfn9Etf9Dpoac9poI4Liav6rBoUQk3N3J
WqnVHNx/NdCyJ1/6UbKMJUZsStAVglsi6lVPo289HHOE4f7iwl3SyekizVOp01wU
in3ycnbZB/rXmZbwapSxTTSBf0EIOr9i4EGfnnhCAVA9U5uLrI5OEB69IY8PNX00
71s3Z2a2fio5c8m3JkdrAgMBAAGjggKdMIICmTAOBgNVHQ8BAf8EBAMCAQYwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAw
HQYDVR0OBBYEFLxiYCfV4zVIF+lLq0Vq0Miod3GMMB8GA1UdIwQYMBaAFMhjmwhp
VMKYyNnN4zO3UF74yQGbMIGNBggrBgEFBQcBAQSBgDB+MDcGCCsGAQUFBzABhito
dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vdHJ1c3Ryb290c2hhMmcyMEMGCCsG
AQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC90cnVz
dHJvb3RzaGEyZzIuY3J0MIHyBgNVHR4EgeowgeeggbIwCIEGdnQuZWR1MAmCB2Jl
di5uZXQwCoIIdmNvbS5lZHUwCIIGdnQuZWR1MAyCCnZ0Y2dpdC5jb20wd6R1MHMx
CzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tz
YnVyZzE8MDoGA1UEChMzVmlyZ2luaWEgUG9seXRlY2huaWMgSW5zdGl0dXRlIGFu
ZCBTdGF0ZSBVbml2ZXJzaXR5oTAwCocIAAAAAAAAAAAwIocgAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2Ny
bC5nbG9iYWxzaWduLmNvbS9ncy90cnVzdHJvb3RzaGEyZzIuY3JsMEwGA1UdIARF
MEMwQQYJKwYBBAGgMgE8MDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh
bHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQArHocpEKTv
DW1Hw0USj60KN96aLJXTLm05s0LbjloeTePtDFtuisrbE85A0IhCwxdIl/VsQMZB
7mQZBEmLzR+NK1/Luvs7C6WTmkqrE8H7D73dSOab5fMZIXS91V/aEtEQGpJMhwi1
svd9TiiQrVkagrraeRWmTTz9BtUA3CeujuW2tShxF1ew4Q4prYw97EsE4HnKDJtu
RtyTqKsuh/rRvKMmgUdEPZbVI23yzUKhi/mTbyml/35x/f6f5p7OYIKcQ/34sts8
xoW9dfkWBQKAXCstXat3WJVilGXBFub6GoVZdnxTDipyMZhUT/vzXq2bPphjcdR5
YGbmwyYmChfa
-----END CERTIFICATE-----`

var nameConstraintsIntermediate2 = `-----BEGIN CERTIFICATE-----
MIIEXDCCA0SgAwIBAgILBAAAAAABNumCOV0wDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTIwNDI1MTEwMDAwWhcNMjcwNDI1
MTEwMDAwWjBjMQswCQYDVQQGEwJCRTEVMBMGA1UECxMMVHJ1c3RlZCBSb290MRkw
FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSIwIAYDVQQDExlUcnVzdGVkIFJvb3Qg
Q0EgU0hBMjU2IEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz80+
/Q2PAhLuYwe04YTLBLGKr1/JScHtDvAY5E94GjGxCbSR1/1VhL880UPJyN85tddO
oxZPgtIyZixDvvK+CgpT5webyBBbqK/ap7aoByghAJ7X520XZMRwKA6cEWa6tjCL
WH1zscxQxGzgtV50rn2ux2SapoCPxMpM4+tpEVwWJf3KP3NT+jd9GRaXWgNei5JK
Quo9l+cZkSeuoWijvaer5hcLCufPywMMQd0r6XXIM/l7g9DjMaE24d+fa2bWxQXC
8WT/PZ+D1KUEkdtn/ixADqsoiIibGn7M84EE9/NLjbzPrwROlBUJFz6cuw+II0rZ
8OFFeZ/OkHHYZq2h9wIDAQABo4IBJjCCASIwDgYDVR0PAQH/BAQDAgEGMA8GA1Ud
EwEB/wQFMAMBAf8wRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMB0GA1UdDgQWBBTI
Y5sIaVTCmMjZzeMzt1Be+MkBmzA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3Js
Lmdsb2JhbHNpZ24ubmV0L3Jvb3QtcjMuY3JsMD4GCCsGAQUFBwEBBDIwMDAuBggr
BgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzAfBgNV
HSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDANBgkqhkiG9w0BAQsFAAOCAQEA
XzbLwBjJiY6j3WEcxD3eVnsIY4pY3bl6660tgpxCuLVx4o1xyiVkS/BcQFD7GIoX
FBRrf5HibO1uSEOw0QZoRwlsio1VPg1PRaccG5C1sB51l/TL1XH5zldZBCnRYrrF
qCPorxi0xoRogj8kqkS2xyzYLElhx9X7jIzfZ8dC4mgOeoCtVvwM9xvmef3n6Vyb
7/hl3w/zWwKxWyKJNaF7tScD5nvtLUzyBpr++aztiyJ1WliWcS6W+V2gKg9rxEC/
rc2yJS70DvfkPiEnBJ2x2AHZV3yKTALUqurkV705JledqUT9I5frAwYNXZ8pNzde
n+DIcSIo7yKy6MX9czbFWQ==
-----END CERTIFICATE-----`

var globalSignRoot = `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----`

const digicertRoot = `-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----`

const trustAsiaSHA384Intermediate = `-----BEGIN CERTIFICATE-----
MIID9zCCAt+gAwIBAgIQC965p4OR4AKrGlsyW0XrDzANBgkqhkiG9w0BAQwFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0xODA0MjcxMjQyNTlaFw0yODA0MjcxMjQyNTlaMFoxCzAJBgNVBAYTAkNO
MSUwIwYDVQQKExxUcnVzdEFzaWEgVGVjaG5vbG9naWVzLCBJbmMuMSQwIgYDVQQD
ExtUcnVzdEFzaWEgRUNDIE9WIFRMUyBQcm8gQ0EwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAQPIUn75M5BCQLKoPsSU2KTr3mDMh13usnAQ38XfKOzjXiyQ+W0inA7meYR
xS+XMQgvnbCigEsKj3ErPIzO68uC9V/KdqMaXWBJp85Ws9A4KL92NB4Okbn5dp6v
Qzy08PajggFeMIIBWjAdBgNVHQ4EFgQULdRyBx6HyIH/+LOvuexyH5p/3PwwHwYD
VR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUwDgYDVR0PAQH/BAQDAgGGMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEA
MDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYbaHR0cDovL29jc3AuZGlnaWNl
cnQtY24uY29tMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuZGlnaWNlcnQt
Y24uY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdENBLmNybDBWBgNVHSAETzBNMDcGCWCG
SAGG/WwBATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20v
Q1BTMAgGBmeBDAECAjAIBgZngQwBAgMwDQYJKoZIhvcNAQEMBQADggEBACVRufYd
j81xUqngFCO+Pk8EYXie0pxHKsBZnOPygAyXKx+awUasKBAnHjmhoFPXaDGAP2oV
OeZTWgwnURVr6wUCuTkz2/8Tgl1egC7OrVcHSa0fIIhaVo9/zRA/hr31xMG7LFBk
GNd7jd06Up4f/UOGbcJsqJexc5QRcUeSwe1MiUDcTNiyCjZk74QCPdcfdFYM4xsa
SlUpboB5vyT7jFePZ2v95CKjcr0EhiQ0gwxpdgoipZdfYTiMFGxCLsk6v8pUv7Tq
PT/qadOGyC+PfLuZh1PtLp20mF06K+MzheCiv+w1NT5ofhmcObvukc68wvbvRFL6
rRzZxAYN36q1SX8=
-----END CERTIFICATE-----`

const trustAsiaLeaf = `-----BEGIN CERTIFICATE-----
MIIEwTCCBEegAwIBAgIQBOjomZfHfhgz2bVYZVuf2DAKBggqhkjOPQQDAzBaMQsw
CQYDVQQGEwJDTjElMCMGA1UEChMcVHJ1c3RBc2lhIFRlY2hub2xvZ2llcywgSW5j
LjEkMCIGA1UEAxMbVHJ1c3RBc2lhIEVDQyBPViBUTFMgUHJvIENBMB4XDTE5MDUx
NzAwMDAwMFoXDTIwMDcyODEyMDAwMFowgY0xCzAJBgNVBAYTAkNOMRIwEAYDVQQI
DAnnpo/lu7rnnIExEjAQBgNVBAcMCeWOpumXqOW4gjEqMCgGA1UECgwh5Y6m6Zeo
5Y+B546W5Y+B56eR5oqA5pyJ6ZmQ5YWs5Y+4MRgwFgYDVQQLDA/nn6Xor4bkuqfm
nYPpg6gxEDAOBgNVBAMMByoudG0uY24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARx/MDQ0oGnCLagQIzjIz57iqFYFmz4/W6gaU6N+GHBkzyvQU8aX02QkdlTTNYL
TCoGFJxHB0XlZVSxrqoIPlNKo4ICuTCCArUwHwYDVR0jBBgwFoAULdRyBx6HyIH/
+LOvuexyH5p/3PwwHQYDVR0OBBYEFGTyf5adc5smW8NvDZyummJwZRLEMBkGA1Ud
EQQSMBCCByoudG0uY26CBXRtLmNuMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2Ny
bC5kaWdpY2VydC1jbi5jb20vVHJ1c3RBc2lhRUNDT1ZUTFNQcm9DQS5jcmwwTAYD
VR0gBEUwQzA3BglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cu
ZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgIwfgYIKwYBBQUHAQEEcjBwMCcGCCsG
AQUFBzABhhtodHRwOi8vb2NzcC5kaWdpY2VydC1jbi5jb20wRQYIKwYBBQUHMAKG
OWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LWNuLmNvbS9UcnVzdEFzaWFFQ0NPVlRM
U1Byb0NBLmNydDAMBgNVHRMBAf8EAjAAMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDv
AHUA7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/csAAAFqxGMTnwAABAMA
RjBEAiAz13zKEoyqd4e/96SK/fxfjl7uR+xhfoDZeyA1BvtfOwIgTY+8nJMGekv8
leIVdW6AGh7oqH31CIGTAbNJJWzaSFYAdgCHdb/nWXz4jEOZX73zbv9WjUdWNv9K
tWDBtOr/XqCDDwAAAWrEYxTCAAAEAwBHMEUCIQDlWm7+limbRiurcqUwXav3NSmx
x/aMnolLbh6+f+b1XAIgQfinHwLw6pDr4R9UkndUsX8QFF4GXS3/IwRR8HCp+pIw
CgYIKoZIzj0EAwMDaAAwZQIwHg8JmjRtcq+OgV0vVmdVBPqehi1sQJ9PZ+51CG+Z
0GOu+2HwS/fyLRViwSc/MZoVAjEA7NgbgpPN4OIsZn2XjMGxemtVxGFS6ZR+1364
EEeHB9vhZAEjQSePAfjR9aAGhXRa
-----END CERTIFICATE-----`

const selfSigned = `-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIRAK0SWRVmi67xU3z0gkgY+PkwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjA4MTkxNjMzNDdaFw0xNzA4MTkxNjMz
NDdaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDWkm1kdCwxyKEt6OTmZitkmLGH8cQu9z7rUdrhW8lWNm4kh2SuaUWP
pscBjda5iqg51aoKuWJR2rw6ElDne+X5eit2FT8zJgAU8v39lMFjbaVZfS9TFOYF
w0Tk0Luo/PyKJpZnwhsP++iiGQiteJbndy8aLKmJ2MpLfpDGIgxEIyNb5dgoDi0D
WReDCpE6K9WDYqvKVGnQ2Jvqqra6Gfx0tFkuqJxQuqA8aUOlPHcCH4KBZdNEoXdY
YL3E4dCAh0YiDs80wNZx4cHqEM3L8gTEFqW2Tn1TSuPZO6gjJ9QPsuUZVjaMZuuO
NVxqLGujZkDzARhC3fBpptMuaAfi20+BAgMBAAGjTTBLMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBYGA1UdEQQPMA2C
C2Zvby5leGFtcGxlMA0GCSqGSIb3DQEBCwUAA4IBAQBPvvfnDhsHWt+/cfwdAVim
4EDn+hYOMkTQwU0pouYIvY8QXYkZ8MBxpBtBMK4JhFU+ewSWoBAEH2dCCvx/BDxN
UGTSJHMbsvJHcFvdmsvvRxOqQ/cJz7behx0cfoeHMwcs0/vWv8ms5wHesb5Ek7L0
pl01FCBGTcncVqr6RK1r4fTpeCCfRIERD+YRJz8TtPH6ydesfLL8jIV40H8NiDfG
vRAvOtNiKtPzFeQVdbRPOskC4rcHyPeiDAMAMixeLi63+CFty4da3r5lRezeedCE
cw3ESZzThBwWqvPOtJdpXdm+r57pDW8qD+/0lY8wfImMNkQAyCUCLg/1Lxt/hrBj
-----END CERTIFICATE-----`

const x509v1TestRoot = `-----BEGIN CERTIFICATE-----
MIICIDCCAYmgAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwIzEPMA0GA1UE
ChMGR29sYW5nMRAwDgYDVQQDEwdSb290IENBMB4XDTE1MDEwMTAwMDAwMFoXDTI1
MDEwMTAwMDAwMFowIzEPMA0GA1UEChMGR29sYW5nMRAwDgYDVQQDEwdSb290IENB
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDpDn8RDOZa5oaDcPZRBy4CeBH1
siSSOO4mYgLHlPE+oXdqwI/VImi2XeJM2uCFETXCknJJjYG0iJdrt/yyRFvZTQZw
+QzGj+mz36NqhGxDWb6dstB2m8PX+plZw7jl81MDvUnWs8yiQ/6twgu5AbhWKZQD
JKcNKCEpqa6UW0r5nwIDAQABo10wWzAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIE
EEA31wH7QC+4HH5UBCeMWQEwDQYJKoZIhvcNAQELBQADgYEAcIwqeNUpQr9cOcYm
YjpGpYkQ6b248xijCK7zI+lOeWN89zfSXn1AvfsC9pSdTMeDklWktbF/Ad0IN8Md
h2NtN34ard0hEfHc8qW8mkXdsysVmq6cPvFYaHz+dBtkHuHDoy8YQnC0zdN/WyYB
/1JmacUUofl+HusHuLkDxmadogI=
-----END CERTIFICATE-----`

const x509v1TestIntermediate = `-----BEGIN CERTIFICATE-----
MIIByjCCATMCCQCCdEMsT8ykqTANBgkqhkiG9w0BAQsFADAjMQ8wDQYDVQQKEwZH
b2xhbmcxEDAOBgNVBAMTB1Jvb3QgQ0EwHhcNMTUwMTAxMDAwMDAwWhcNMjUwMTAx
MDAwMDAwWjAwMQ8wDQYDVQQKEwZHb2xhbmcxHTAbBgNVBAMTFFguNTA5djEgaW50
ZXJtZWRpYXRlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJ2QyniAOT+5YL
jeinEBJr3NsC/Q2QJ/VKmgvp+xRxuKTHJiVmxVijmp0vWg8AWfkmuE4p3hXQbbqM
k5yxrk1n60ONhim2L4VXriEvCE7X2OXhTmBls5Ufr7aqIgPMikwjScCXwz8E8qI8
UxyAhnjeJwMYBU8TuwBImSd4LBHoQQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAIab
DRG6FbF9kL9jb/TDHkbVBk+sl/Pxi4/XjuFyIALlARgAkeZcPmL5tNW1ImHkwsHR
zWE77kJDibzd141u21ZbLsKvEdUJXjla43bdyMmEqf5VGpC3D4sFt3QVH7lGeRur
x5Wlq1u3YDL/j6s1nU2dQ3ySB/oP7J+vQ9V4QeM+
-----END CERTIFICATE-----`

const x509v1TestLeaf = `-----BEGIN CERTIFICATE-----
MIICMzCCAZygAwIBAgIJAPo99mqJJrpJMA0GCSqGSIb3DQEBCwUAMDAxDzANBgNV
BAoTBkdvbGFuZzEdMBsGA1UEAxMUWC41MDl2MSBpbnRlcm1lZGlhdGUwHhcNMTUw
MTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjArMQ8wDQYDVQQKEwZHb2xhbmcxGDAW
BgNVBAMTD2Zvby5leGFtcGxlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEApUh60Z+a5/oKJxG//Dn8CihSo2CJHNIIO3zEJZ1EeNSMZCynaIR6D3IPZEIR
+RG2oGt+f5EEukAPYxwasp6VeZEezoQWJ+97nPCT6DpwLlWp3i2MF8piK2R9vxkG
Z5n0+HzYk1VM8epIrZFUXSMGTX8w1y041PX/yYLxbdEifdcCAwEAAaNaMFgwDgYD
VR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNV
HRMBAf8EAjAAMBkGA1UdDgQSBBBFozXe0SnzAmjy+1U6M/cvMA0GCSqGSIb3DQEB
CwUAA4GBADYzYUvaToO/ucBskPdqXV16AaakIhhSENswYVSl97/sODaxsjishKq9
5R7siu+JnIFotA7IbBe633p75xEnLN88X626N/XRFG9iScLzpj0o0PWXBUiB+fxL
/jt8qszOXCv2vYdUTPNuPqufXLWMoirpuXrr1liJDmedCcAHepY/
-----END CERTIFICATE-----`

const rootWithoutSKID = `-----BEGIN CERTIFICATE-----
MIIBbzCCARSgAwIBAgIQeCkq3C8SOX/JM5PqYTl9cDAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE5MDIwNDIyNTYzNFoXDTI5MDIwMTIyNTYzNFow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABISm
jGlTr4dLOWT+BCTm2PzWRjk1DpLcSAh+Al8eB1Nc2eBWxYIH9qPirfatvqBOA4c5
ZwycRpFoaw6O+EmXnVujTDBKMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBIGA1UdEQQLMAmCB2V4YW1wbGUwCgYI
KoZIzj0EAwIDSQAwRgIhAMaBYWFCjTfn0MNyQ0QXvYT/iIFompkIqzw6wB7qjLrA
AiEA3sn65V7G4tsjZEOpN0Jykn9uiTjqniqn/S/qmv8gIec=
-----END CERTIFICATE-----`

const leafWithAKID = `-----BEGIN CERTIFICATE-----
MIIBjTCCATSgAwIBAgIRAPCKYvADhKLPaWOtcTu2XYwwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHQWNtZSBDbzAeFw0xOTAyMDQyMzA2NTJaFw0yOTAyMDEyMzA2NTJa
MBMxETAPBgNVBAoTCEFjbWUgTExDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
Wk5N+/8X97YT6ClFNIE5/4yc2YwKn921l0wrIJEcT2u+Uydm7EqtCJNtZjYMAnBd
Acp/wynpTwC6tBTsxcM0s6NqMGgwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG
CCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUwitfkXg0JglCjW9R
ssWvTAveakIwEgYDVR0RBAswCYIHZXhhbXBsZTAKBggqhkjOPQQDAgNHADBEAiBk
4LpWiWPOIl5PIhX9PDVkmjpre5oyoH/3aYwG8ABYuAIgCeSfbYueOOG2AdXuMqSU
ZZMqeJS7JldLx91sPUArY5A=
-----END CERTIFICATE-----`

const rootMatchingSKIDMismatchingSubject = `-----BEGIN CERTIFICATE-----
MIIBQjCB6aADAgECAgEAMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBlJvb3QgQTAe
Fw0wOTExMTAyMzAwMDBaFw0xOTExMDgyMzAwMDBaMBExDzANBgNVBAMTBlJvb3Qg
QTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPK4p1uXq2aAeDtKDHIokg2rTcPM
2gq3N9Y96wiW6/7puBK1+INEW//cO9x6FpzkcsHw/TriAqy4sck/iDAvf9WjMjAw
MA8GA1UdJQQIMAYGBFUdJQAwDwYDVR0TAQH/BAUwAwEB/zAMBgNVHQ4EBQQDAQID
MAoGCCqGSM49BAMCA0gAMEUCIQDgtAp7iVHxMnKxZPaLQPC+Tv2r7+DJc88k2SKH
MPs/wQIgFjjNvBoQEl7vSHTcRGCCcFMdlN4l0Dqc9YwGa9fyrQs=
-----END CERTIFICATE-----`

const rootMismatchingSKIDMatchingSubject = `-----BEGIN CERTIFICATE-----
MIIBNDCB26ADAgECAgEAMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBlJvb3QgQjAe
Fw0wOTExMTAyMzAwMDBaFw0xOTExMDgyMzAwMDBaMBExDzANBgNVBAMTBlJvb3Qg
QjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1YRFcIlkWzm9BdEVrIsEQJ2dT6
qiW8/WV9GoIhmDtX9SEDHospc0Cgm+TeD2QYW2iMrS5mvNe4GSw0Jezg/bOjJDAi
MA8GA1UdJQQIMAYGBFUdJQAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNI
ADBFAiEAukWOiuellx8bugRiwCS5XQ6IOJ1SZcjuZxj76WojwxkCIHqa71qNw8FM
DtA5yoL9M2pDFF6ovFWnaCe+KlzSwAW/
-----END CERTIFICATE-----`

const leafMatchingAKIDMatchingIssuer = `-----BEGIN CERTIFICATE-----
MIIBNTCB26ADAgECAgEAMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBlJvb3QgQjAe
Fw0wOTExMTAyMzAwMDBaFw0xOTExMDgyMzAwMDBaMA8xDTALBgNVBAMTBExlYWYw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNWERXCJZFs5vQXRFayLBECdnU+qol
vP1lfRqCIZg7V/UhAx6LKXNAoJvk3g9kGFtojK0uZrzXuBksNCXs4P2zoyYwJDAO
BgNVHSMEBzAFgAMBAgMwEgYDVR0RBAswCYIHZXhhbXBsZTAKBggqhkjOPQQDAgNJ
ADBGAiEAnV9XV7a4h0nfJB8pWv+pBUXRlRFA2uZz3mXEpee8NYACIQCWa+wL70GL
ePBQCV1F9sE2q4ZrnsT9TZoNrSe/bMDjzA==
-----END CERTIFICATE-----`

var unknownAuthorityErrorTests = []struct {
	name     string
	cert     string
	expected string
}{
	{"self-signed, cn", selfSignedWithCommonName, "x509: certificate signed by unknown authority (possibly because of \"empty\" while trying to verify candidate authority certificate \"test\")"},
	{"self-signed, no cn, org", selfSignedNoCommonNameWithOrgName, "x509: certificate signed by unknown authority (possibly because of \"empty\" while trying to verify candidate authority certificate \"ca\")"},
	{"self-signed, no cn, no org", selfSignedNoCommonNameNoOrgName, "x509: certificate signed by unknown authority (possibly because of \"empty\" while trying to verify candidate authority certificate \"serial:0\")"},
}

func TestUnknownAuthorityError(t *testing.T) {
	for i, tt := range unknownAuthorityErrorTests {
		t.Run(tt.name, func(t *testing.T) {
			der, _ := pem.Decode([]byte(tt.cert))
			if der == nil {
				t.Fatalf("#%d: Unable to decode PEM block", i)
			}
			c, err := x509.ParseCertificate(der.Bytes)
			if err != nil {
				t.Fatalf("#%d: Unable to parse certificate -> %v", i, err)
			}
			uae := &UnknownAuthorityError{
				Cert:     c,
				hintErr:  fmt.Errorf("empty"),
				hintCert: c,
			}
			actual := uae.Error()
			if actual != tt.expected {
				t.Errorf("#%d: UnknownAuthorityError.Error() response invalid actual: %s expected: %s", i, actual, tt.expected)
			}
		})
	}
}

const selfSignedWithCommonName = `-----BEGIN CERTIFICATE-----
MIIDCjCCAfKgAwIBAgIBADANBgkqhkiG9w0BAQsFADAaMQswCQYDVQQKEwJjYTEL
MAkGA1UEAxMCY2EwHhcNMTYwODI4MTcwOTE4WhcNMjEwODI3MTcwOTE4WjAcMQsw
CQYDVQQKEwJjYTENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAOH55PfRsbvmcabfLLko1w/yuapY/hk13Cgmc3WE/Z1ZStxGiVxY
gQVH9n4W/TbUsrep/TmcC4MV7xEm5252ArcgaH6BeQ4QOTFj/6Jx0RT7U/ix+79x
8RRysf7OlzNpGIctwZEM7i/G+0ZfqX9ULxL/EW9tppSxMX1jlXZQarnU7BERL5cH
+G2jcbU9H28FXYishqpVYE9L7xrXMm61BAwvGKB0jcVW6JdhoAOSfQbbgp7JjIlq
czXqUsv1UdORO/horIoJptynTvuARjZzyWatya6as7wyOgEBllE6BjPK9zpn+lp3
tQ8dwKVqm/qBPhIrVqYG/Ec7pIv8mJfYabMCAwEAAaNZMFcwDgYDVR0PAQH/BAQD
AgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA
MAoGA1UdDgQDBAEAMAwGA1UdIwQFMAOAAQAwDQYJKoZIhvcNAQELBQADggEBAAAM
XMFphzq4S5FBcRdB2fRrmcoz+jEROBWvIH/1QUJeBEBz3ZqBaJYfBtQTvqCA5Rjw
dxyIwVd1W3q3aSulM0tO62UCU6L6YeeY/eq8FmpD7nMJo7kCrXUUAMjxbYvS3zkT
v/NErK6SgWnkQiPJBZNX1Q9+aSbLT/sbaCTdbWqcGNRuLGJkmqfIyoxRt0Hhpqsx
jP5cBaVl50t4qoCuVIE9cOucnxYXnI7X5HpXWvu8Pfxo4SwVjb1az8Fk5s8ZnxGe
fPB6Q3L/pKBe0SEe5GywpwtokPLB3lAygcuHbxp/1FlQ1NQZqq+vgXRIla26bNJf
IuYkJwt6w+LH/9HZgf8=
-----END CERTIFICATE-----`
const selfSignedNoCommonNameWithOrgName = `-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIBADANBgkqhkiG9w0BAQsFADAaMQswCQYDVQQKEwJjYTEL
MAkGA1UEAxMCY2EwHhcNMTYwODI4MTgxMzQ4WhcNMjEwODI3MTgxMzQ4WjANMQsw
CQYDVQQKEwJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5EjrUa
7EtOMxWiIgTzp2FlQvncPsG329O3l3uNGnbigb8TmNMw2M8UhoDjd84pnU5RAfqd
8t5TJyw/ybnIKBN131Q2xX+gPQ0dFyMvcO+i1CUgCxmYZomKVA2MXO1RD1hLTYGS
gOVjc3no3MBwd8uVQp0NStqJ1QvLtNG4Uy+B28qe+ZFGGbjGqx8/CU4A8Szlpf7/
xAZR8w5qFUUlpA2LQYeHHJ5fQVXw7kyL1diNrKNi0G3qcY0IrBh++hT+hnEEXyXu
g8a0Ux18hoE8D6rAr34rCZl6AWfqW5wjwm+N5Ns2ugr9U4N8uCKJYMPHb2CtdubU
46IzVucpTfGLdaMCAwEAAaNZMFcwDgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQG
CCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMAoGA1UdDgQDBAEAMAwG
A1UdIwQFMAOAAQAwDQYJKoZIhvcNAQELBQADggEBAEn5SgVpJ3zjsdzPqK7Qd/sB
bYd1qtPHlrszjhbHBg35C6mDgKhcv4o6N+fuC+FojZb8lIxWzJtvT9pQbfy/V6u3
wOb816Hm71uiP89sioIOKCvSAstj/p9doKDOUaKOcZBTw0PS2m9eja8bnleZzBvK
rD8cNkHf74v98KvBhcwBlDifVzmkWzMG6TL1EkRXUyLKiWgoTUFSkCDV927oXXMR
DKnszq+AVw+K8hbeV2A7GqT7YfeqOAvSbatTDnDtKOPmlCnQui8A149VgZzXv7eU
29ssJSqjUPyp58dlV6ZuynxPho1QVZUOQgnJToXIQ3/5vIvJRXy52GJCs4/Gh/w=
-----END CERTIFICATE-----`
const selfSignedNoCommonNameNoOrgName = `-----BEGIN CERTIFICATE-----
MIIC7jCCAdagAwIBAgIBADANBgkqhkiG9w0BAQsFADAaMQswCQYDVQQKEwJjYTEL
MAkGA1UEAxMCY2EwHhcNMTYwODI4MTgxOTQ1WhcNMjEwODI3MTgxOTQ1WjAAMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp3E+Jl6DpgzogHUW/i/AAcCM
fnNJLOamNVKFGmmxhb4XTHxRaWoTzrlsyzIMS0WzivvJeZVe6mWbvuP2kZanKgIz
35YXRTR9HbqkNTMuvnpUESzWxbGWE2jmt2+a/Jnz89FS4WIYRhF7nI2z8PvZOfrI
2gETTT2tEpoF2S4soaYfm0DBeT8K0/rogAaf+oeUS6V+v3miRcAooJgpNJGu9kqm
S0xKPn1RCFVjpiRd6YNS0xZirjYQIBMFBvoSoHjaOdgJptNRBprYPOxVJ/ItzGf0
kPmzPFCx2tKfxV9HLYBPgxi+fP3IIx8aIYuJn8yReWtYEMYU11hDPeAFN5Gm+wID
AQABo1kwVzAOBgNVHQ8BAf8EBAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsG
AQUFBwMBMAwGA1UdEwEB/wQCMAAwCgYDVR0OBAMEAQAwDAYDVR0jBAUwA4ABADAN
BgkqhkiG9w0BAQsFAAOCAQEATZVOFeiCpPM5QysToLv+8k7Rjoqt6L5IxMUJGEpq
4ENmldmwkhEKr9VnYEJY3njydnnTm97d9vOfnLj9nA9wMBODeOO3KL2uJR2oDnmM
9z1NSe2aQKnyBb++DM3ZdikpHn/xEpGV19pYKFQVn35x3lpPh2XijqRDO/erKemb
w67CoNRb81dy+4Q1lGpA8ORoLWh5fIq2t2eNGc4qB8vlTIKiESzAwu7u3sRfuWQi
4R+gnfLd37FWflMHwztFbVTuNtPOljCX0LN7KcuoXYlr05RhQrmoN7fQHsrZMNLs
8FVjHdKKu+uPstwd04Uy4BR/H2y1yerN9j/L6ZkMl98iiA==
-----END CERTIFICATE-----`

func generateCert(cn string, isCA bool, issuer *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if issuer == nil {
		issuer = template
		issuerKey = priv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, priv.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func TestPathologicalChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping generation of a long chain of certificates in short mode")
	}

	// Build a chain where all intermediates share the same subject, to hit the
	// path building worst behavior.
	roots, intermediates := NewCertPool(), NewCertPool()

	parent, parentKey, err := generateCert("Root CA", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parent)

	for i := 1; i < 100; i++ {
		parent, parentKey, err = generateCert("Intermediate CA", true, parent, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parent)
	}

	leaf, _, err := generateCert("Leaf", false, parent, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = Verify(leaf, VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	t.Logf("verification took %v", time.Since(start))

	if err == nil || !strings.Contains(err.Error(), "signature check attempts limit") {
		t.Errorf("expected verification to fail with a signature checks limit error; got %v", err)
	}
}

func TestLongChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping generation of a long chain of certificates in short mode")
	}

	roots, intermediates := NewCertPool(), NewCertPool()

	parent, parentKey, err := generateCert("Root CA", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parent)

	for i := 1; i < 15; i++ {
		name := fmt.Sprintf("Intermediate CA #%d", i)
		parent, parentKey, err = generateCert(name, true, parent, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parent)
	}

	leaf, _, err := generateCert("Leaf", false, parent, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := Verify(leaf, VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		t.Error(err)
	}
	t.Logf("verification took %v", time.Since(start))
}

type trustGraphEdge struct {
	Issuer         string
	Subject        string
	Type           int
	MutateTemplate func(*x509.Certificate)
	Constraint     func([]*x509.Certificate) error
}

type rootDescription struct {
	Subject        string
	MutateTemplate func(*x509.Certificate)
	Constraint     func([]*x509.Certificate) error
}

type trustGraphDescription struct {
	Roots []rootDescription
	Leaf  string
	Graph []trustGraphEdge
}

func genCertEdge(t *testing.T, subject string, key crypto.Signer, mutateTmpl func(*x509.Certificate), certType int, issuer *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		t.Fatalf("failed to generate test serial: %s", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	switch certType {
	case rootCertificate, intermediateCertificate:
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage = x509.KeyUsageCertSign
	case leafCertificate:
		tmpl.DNSNames = []string{"localhost"}
	}
	if mutateTmpl != nil {
		mutateTmpl(tmpl)
	}

	if certType == rootCertificate {
		issuer = tmpl
		signer = key
	}

	d, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatalf("failed to generate test cert: %s", err)
	}
	c, err := x509.ParseCertificate(d)
	if err != nil {
		t.Fatalf("failed to parse test cert: %s", err)
	}
	return c
}

func buildTrustGraph(t *testing.T, d trustGraphDescription) (*CertPool, *CertPool, *x509.Certificate) {
	t.Helper()

	certs := map[string]*x509.Certificate{}
	keys := map[string]crypto.Signer{}
	rootPool := NewCertPool()
	for _, r := range d.Roots {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate test key: %s", err)
		}
		root := genCertEdge(t, r.Subject, k, r.MutateTemplate, rootCertificate, nil, nil)
		if r.Constraint != nil {
			rootPool.AddCertWithConstraint(root, r.Constraint)
		} else {
			rootPool.AddCert(root)
		}
		certs[r.Subject] = root
		keys[r.Subject] = k
	}

	intermediatePool := NewCertPool()
	var leaf *x509.Certificate
	for _, e := range d.Graph {
		issuerCert, ok := certs[e.Issuer]
		if !ok {
			t.Fatalf("unknown issuer %s", e.Issuer)
		}
		issuerKey, ok := keys[e.Issuer]
		if !ok {
			t.Fatalf("unknown issuer %s", e.Issuer)
		}

		k, ok := keys[e.Subject]
		if !ok {
			var err error
			k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate test key: %s", err)
			}
			keys[e.Subject] = k
		}
		cert := genCertEdge(t, e.Subject, k, e.MutateTemplate, e.Type, issuerCert, issuerKey)
		certs[e.Subject] = cert
		if e.Subject == d.Leaf {
			leaf = cert
		} else {
			if e.Constraint != nil {
				intermediatePool.AddCertWithConstraint(cert, e.Constraint)
			} else {
				intermediatePool.AddCert(cert)
			}
		}
	}

	return rootPool, intermediatePool, leaf
}

func chainsToStrings(chains [][]*x509.Certificate) []string {
	chainStrings := []string{}
	for _, chain := range chains {
		names := []string{}
		for _, c := range chain {
			names = append(names, c.Subject.String())
		}
		chainStrings = append(chainStrings, strings.Join(names, " -> "))
	}
	slices.Sort(chainStrings)
	return chainStrings
}

func TestPathBuilding(t *testing.T) {
	tests := []struct {
		name           string
		graph          trustGraphDescription
		expectedChains []string
		expectedErr    string
	}{
		{
			// Build the following graph from RFC 4158, figure 7 (note that in this graph edges represent
			// certificates where the parent is the issuer and the child is the subject.) For the certificate
			// C->B, use an unsupported ExtKeyUsage (in this case ExtKeyUsageCodeSigning) which invalidates
			// the path Trust Anchor -> C -> B -> EE. The remaining valid paths should be:
			//   * Trust Anchor -> A -> B -> EE
			//   * Trust Anchor -> C -> A -> B -> EE
			//
			// [lax509 edit]: These paths should also be valid since EKU checks have been disabled.
			//   * Trust Anchor -> A -> C -> B -> EE
			//   * Trust Anchor -> C -> B -> EE
			//
			//
			//     +---------+
			//     |  Trust  |
			//     | Anchor  |
			//     +---------+
			//      |       |
			//      v       v
			//   +---+    +---+
			//   | A |<-->| C |
			//   +---+    +---+
			//    |         |
			//    |  +---+  |
			//    +->| B |<-+
			//       +---+
			//         |
			//         v
			//       +----+
			//       | EE |
			//       +----+
			name: "bad EKU",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter b",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
						},
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=inter c -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=root",
			},
		},
		{
			// Build the following graph from RFC 4158, figure 7 (note that in this graph edges represent
			// certificates where the parent is the issuer and the child is the subject.) For the certificate
			// C->B, use a unconstrained SAN which invalidates the path Trust Anchor -> C -> B -> EE. The
			// remaining valid paths should be:
			//   * Trust Anchor -> A -> B -> EE
			//   * Trust Anchor -> C -> A -> B -> EE
			//
			// [lax509 edit]: These paths should also be valid since EKU checks have been disabled.
			//   * Trust Anchor -> C -> B -> EE
			//   * Trust Anchor -> A -> C -> B -> EE
			//
			//     +---------+
			//     |  Trust  |
			//     | Anchor  |
			//     +---------+
			//      |       |
			//      v       v
			//   +---+    +---+
			//   | A |<-->| C |
			//   +---+    +---+
			//    |         |
			//    |  +---+  |
			//    +->| B |<-+
			//       +---+
			//         |
			//         v
			//       +----+
			//       | EE |
			//       +----+
			name: "bad EKU",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter b",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.PermittedDNSDomains = []string{"good"}
							t.DNSNames = []string{"bad"}
						},
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=inter c -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=root",
			},
		},
		{
			// Build the following graph, we should find both paths:
			//   * Trust Anchor -> A -> C -> EE
			//   * Trust Anchor -> A -> B -> C -> EE
			//
			//	       +---------+
			//	       |  Trust  |
			//	       | Anchor  |
			//	       +---------+
			//	            |
			//	            v
			//	          +---+
			//	          | A |
			//	          +---+
			//	           | |
			//	           | +----+
			//	           |      v
			//	           |    +---+
			//	           |    | B |
			//	           |    +---+
			//	           |      |
			//	           |  +---v
			//	           v  v
			//            +---+
			//            | C |
			//            +---+
			//              |
			//              v
			//            +----+
			//            | EE |
			//            +----+
			name: "all paths",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter c -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter c -> CN=inter b -> CN=inter a -> CN=root",
			},
		},
		{
			// Build the following graph, which contains a cross-signature loop
			// (A and C cross sign each other). Paths that include the A -> C -> A
			// (and vice versa) loop should be ignored, resulting in the paths:
			//   * Trust Anchor -> A -> B -> EE
			//   * Trust Anchor -> C -> B -> EE
			//   * Trust Anchor -> A -> C -> B -> EE
			//   * Trust Anchor -> C -> A -> B -> EE
			//
			//     +---------+
			//     |  Trust  |
			//     | Anchor  |
			//     +---------+
			//      |       |
			//      v       v
			//   +---+    +---+
			//   | A |<-->| C |
			//   +---+    +---+
			//    |         |
			//    |  +---+  |
			//    +->| B |<-+
			//       +---+
			//         |
			//         v
			//       +----+
			//       | EE |
			//       +----+
			name: "ignore cross-sig loops",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=inter c -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=root",
			},
		},
		{
			// Build a simple two node graph, where the leaf is directly issued from
			// the root and both certificates have matching subject and public key, but
			// the leaf has SANs.
			name: "leaf with same subject, key, as parent but with SAN",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "root",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "root",
						Type:    leafCertificate,
						MutateTemplate: func(c *x509.Certificate) {
							c.DNSNames = []string{"localhost"}
						},
					},
				},
			},
			expectedChains: []string{
				"CN=root -> CN=root",
			},
		},
		{
			// Build a basic graph with two paths from leaf to root, but the path passing
			// through C should be ignored, because it has invalid EKU nesting.
			//
			// [lax509 edit]: the second path should not be ignored since EKU checks
			// have been disabled.
			name: "ignore invalid EKU path",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter b",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
						},
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
						},
					},
					{
						Issuer:  "inter b",
						Subject: "leaf",
						Type:    leafCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
						},
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=root",
			},
		},
		{
			// A name constraint on the root should apply to any names that appear
			// on the intermediate, meaning there is no valid chain.
			name: "constrained root, invalid intermediate",
			graph: trustGraphDescription{
				Roots: []rootDescription{
					{
						Subject: "root",
						MutateTemplate: func(t *x509.Certificate) {
							t.PermittedDNSDomains = []string{"example.com"}
						},
					},
				},
				Leaf: "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.DNSNames = []string{"beep.com"}
						},
					},
					{
						Issuer:  "inter",
						Subject: "leaf",
						Type:    leafCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.DNSNames = []string{"www.example.com"}
						},
					},
				},
			},
			expectedErr: "x509: a root or intermediate certificate is not authorized to sign for this name: DNS name \"beep.com\" is not permitted by any constraint",
		},
		{
			// A name constraint on the intermediate does not apply to the intermediate
			// itself, so this is a valid chain.
			name: "constrained intermediate, non-matching SAN",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.DNSNames = []string{"beep.com"}
							t.PermittedDNSDomains = []string{"example.com"}
						},
					},
					{
						Issuer:  "inter",
						Subject: "leaf",
						Type:    leafCertificate,
						MutateTemplate: func(t *x509.Certificate) {
							t.DNSNames = []string{"www.example.com"}
						},
					},
				},
			},
			expectedChains: []string{"CN=leaf -> CN=inter -> CN=root"},
		},
		{
			// A code constraint on the root, applying to one of two intermediates in the graph, should
			// result in only one valid chain.
			name: "code constrained root, two paths, one valid",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root", Constraint: func(chain []*x509.Certificate) error {
					for _, c := range chain {
						if c.Subject.CommonName == "inter a" {
							return errors.New("bad")
						}
					}
					return nil
				}}},
				Leaf: "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{"CN=leaf -> CN=inter c -> CN=inter b -> CN=root"},
		},
		{
			// A code constraint on the root, applying to the only path, should result in an error.
			name: "code constrained root, one invalid path",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root", Constraint: func(chain []*x509.Certificate) error {
					for _, c := range chain {
						if c.Subject.CommonName == "leaf" {
							return errors.New("bad")
						}
					}
					return nil
				}}},
				Leaf: "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedErr: "x509: certificate signed by unknown authority (possibly because of \"bad\" while trying to verify candidate authority certificate \"root\")",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			roots, intermediates, leaf := buildTrustGraph(t, tc.graph)
			chains, err := Verify(leaf, VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
			})
			if err != nil && err.Error() != tc.expectedErr {
				t.Fatalf("unexpected error: got %q, want %q", err, tc.expectedErr)
			}
			if len(tc.expectedChains) == 0 {
				return
			}
			gotChains := chainsToStrings(chains)
			if !slices.Equal(gotChains, tc.expectedChains) {
				t.Errorf("unexpected chains returned:\ngot:\n\t%s\nwant:\n\t%s", strings.Join(gotChains, "\n\t"), strings.Join(tc.expectedChains, "\n\t"))
			}
		})
	}
}

func TestVerifyNilPubKey(t *testing.T) {
	c := &x509.Certificate{
		RawIssuer:      []byte{1, 2, 3},
		AuthorityKeyId: []byte{1, 2, 3},
	}
	opts := &VerifyOptions{}
	opts.Roots = NewCertPool()
	r := &x509.Certificate{
		RawSubject:   []byte{1, 2, 3},
		SubjectKeyId: []byte{1, 2, 3},
	}
	opts.Roots.AddCert(r)

	_, err := buildChains(c, []*x509.Certificate{r}, nil, opts)
	if _, ok := err.(UnknownAuthorityError); !ok {
		t.Fatalf("buildChains returned unexpected error, got: %v, want %v", err, UnknownAuthorityError{})
	}
}
