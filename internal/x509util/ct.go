// Copyright 2024 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	oidExtensionAuthorityKeyId = asn1.ObjectIdentifier{2, 5, 29, 35}
	// These extensions are defined in RFC 6962 s3.1.
	oidExtensionCTPoison                        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidExtensionKeyUsageCertificateTransparency = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
)

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// removeExtension takes a DER-encoded TBSCertificate, removes the extension
// specified by oid (preserving the order of other extensions), and returns the
// result still as a DER-encoded TBSCertificate.  This function will fail if
// there is not exactly 1 extension of the type specified by the oid present.
func removeExtension(tbsData []byte, oid asn1.ObjectIdentifier) ([]byte, error) {
	var tbs tbsCertificate
	rest, err := asn1.Unmarshal(tbsData, &tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TBSCertificate: %v", err)
	} else if rLen := len(rest); rLen > 0 {
		return nil, fmt.Errorf("trailing data (%d bytes) after TBSCertificate", rLen)
	}
	extAt := -1
	for i, ext := range tbs.Extensions {
		if ext.Id.Equal(oid) {
			if extAt != -1 {
				return nil, errors.New("multiple extensions of specified type present")
			}
			extAt = i
		}
	}
	if extAt == -1 {
		return nil, errors.New("no extension of specified type present")
	}
	tbs.Extensions = append(tbs.Extensions[:extAt], tbs.Extensions[extAt+1:]...)
	// Clear out the asn1.RawContent so the re-marshal operation sees the
	// updated structure (rather than just copying the out-of-date DER data).
	tbs.Raw = nil

	data, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal TBSCertificate: %v", err)
	}
	return data, nil
}

// BuildPrecertTBS builds a Certificate Transparency pre-certificate (RFC 6962
// s3.1) from the given DER-encoded TBSCertificate, returning a DER-encoded
// TBSCertificate.
//
// This function removes the CT poison extension (there must be exactly 1 of
// these), preserving the order of other extensions.
//
// If preIssuer is provided, this should be a special intermediate certificate
// that was used to sign the precert (indicated by having the special
// CertificateTransparency extended key usage).  In this case, the issuance
// information of the pre-cert is updated to reflect the next issuer in the
// chain, i.e. the issuer of this special intermediate:
//   - The precert's Issuer is changed to the Issuer of the intermediate
//   - The precert's AuthorityKeyId is changed to the AuthorityKeyId of the
//     intermediate.
func BuildPrecertTBS(tbsData []byte, preIssuer *x509.Certificate) ([]byte, error) {
	data, err := removeExtension(tbsData, oidExtensionCTPoison)
	if err != nil {
		return nil, err
	}

	var tbs tbsCertificate
	rest, err := asn1.Unmarshal(data, &tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TBSCertificate: %v", err)
	} else if rLen := len(rest); rLen > 0 {
		return nil, fmt.Errorf("trailing data (%d bytes) after TBSCertificate", rLen)
	}

	if preIssuer != nil {
		// Update the precert's Issuer field.  Use the RawIssuer rather than the
		// parsed Issuer to avoid any chance of ASN.1 differences (e.g. switching
		// from UTF8String to PrintableString).
		tbs.Issuer.FullBytes = preIssuer.RawIssuer

		// Also need to update the cert's AuthorityKeyID extension
		// to that of the preIssuer.
		var issuerKeyID []byte
		for _, ext := range preIssuer.Extensions {
			if ext.Id.Equal(oidExtensionAuthorityKeyId) {
				issuerKeyID = ext.Value
				break
			}
		}

		// The x509 package does not parse CT EKU, so look for it in
		// extensions directly.
		seenCTEKU := false
		for _, ext := range preIssuer.Extensions {
			if ext.Id.Equal(oidExtensionKeyUsageCertificateTransparency) {
				seenCTEKU = true
				break
			}
		}
		if !seenCTEKU {
			return nil, fmt.Errorf("issuer does not have CertificateTransparency extended key usage")
		}

		keyAt := -1
		for i, ext := range tbs.Extensions {
			if ext.Id.Equal(oidExtensionAuthorityKeyId) {
				keyAt = i
				break
			}
		}
		if keyAt >= 0 {
			// PreCert has an auth-key-id; replace it with the value from the preIssuer
			if issuerKeyID != nil {
				tbs.Extensions[keyAt].Value = issuerKeyID
			} else {
				tbs.Extensions = append(tbs.Extensions[:keyAt], tbs.Extensions[keyAt+1:]...)
			}
		} else if issuerKeyID != nil {
			// PreCert did not have an auth-key-id, but the preIssuer does, so add it at the end.
			authKeyIDExt := pkix.Extension{
				Id:       oidExtensionAuthorityKeyId,
				Critical: false,
				Value:    issuerKeyID,
			}
			tbs.Extensions = append(tbs.Extensions, authKeyIDExt)
		}

		// Clear out the asn1.RawContent so the re-marshal operation sees the
		// updated structure (rather than just copying the out-of-date DER data).
		tbs.Raw = nil
	}

	data, err = asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal TBSCertificate: %v", err)
	}
	return data, nil
}

// RemoveCTPoison takes a DER-encoded TBSCertificate and removes the CT poison
// extension (preserving the order of other extensions), and returns the result
// still as a DER-encoded TBSCertificate.  This function will fail if there is
// not exactly 1 CT poison extension present.
func RemoveCTPoison(tbsData []byte) ([]byte, error) {
	return BuildPrecertTBS(tbsData, nil)
}
