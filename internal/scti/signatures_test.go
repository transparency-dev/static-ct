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
	"crypto"
	"crypto/sha256"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/kylelemons/godebug/pretty"
	"github.com/transparency-dev/static-ct/testdata"

	ct "github.com/google/certificate-transparency-go"
)

var (
	fixedTime       = time.Date(2017, 9, 7, 12, 15, 23, 0, time.UTC)
	fixedTimeMillis = uint64(fixedTime.UnixNano() / nanosPerMilli)
	demoLogID       = [32]byte{19, 56, 222, 93, 229, 36, 102, 128, 227, 214, 3, 121, 93, 175, 126, 236, 97, 217, 34, 32, 40, 233, 98, 27, 46, 179, 164, 251, 84, 10, 60, 57}
	fakeSignature   = []byte("signed")
)

func TestBuildV1MerkleTreeLeafForCert(t *testing.T) {
	cert, err := x509util.CertificateFromPEM([]byte(testdata.LeafSignedByFakeIntermediateCertPEM))
	if x509.IsFatal(err) {
		t.Fatalf("failed to set up test cert: %v", err)
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("could not create signer: %v", err)
	}

	leaf, err := ct.MerkleTreeLeafFromChain([]*x509.Certificate{cert}, ct.X509LogEntryType, fixedTimeMillis)
	if err != nil {
		t.Fatalf("buildV1MerkleTreeLeafForCert()=nil,%v; want _,nil", err)
	}
	got, err := BuildV1SCT(signer, leaf)
	if err != nil {
		t.Fatalf("buildV1SCT()=nil,%v; want _,nil", err)
	}

	expected := ct.SignedCertificateTimestamp{
		SCTVersion: 0,
		LogID:      ct.LogID{KeyID: demoLogID},
		Timestamp:  fixedTimeMillis,
		Extensions: ct.CTExtensions{},
		Signature: ct.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.ECDSA},
			Signature: fakeSignature,
		},
	}

	if diff := pretty.Compare(*got, expected); diff != "" {
		t.Fatalf("Mismatched SCT (cert), diff:\n%v", diff)
	}

	// Additional checks that the MerkleTreeLeaf we built is correct
	if got, want := leaf.Version, ct.V1; got != want {
		t.Fatalf("Got a %v leaf, expected a %v leaf", got, want)
	}
	if got, want := leaf.LeafType, ct.TimestampedEntryLeafType; got != want {
		t.Fatalf("Got leaf type %v, expected %v", got, want)
	}
	if got, want := leaf.TimestampedEntry.EntryType, ct.X509LogEntryType; got != want {
		t.Fatalf("Got entry type %v, expected %v", got, want)
	}
	if got, want := leaf.TimestampedEntry.Timestamp, got.Timestamp; got != want {
		t.Fatalf("Entry / sct timestamp mismatch; got %v, expected %v", got, want)
	}
	if got, want := leaf.TimestampedEntry.X509Entry.Data, cert.Raw; !bytes.Equal(got, want) {
		t.Fatalf("Cert bytes mismatch, got %x, expected %x", got, want)
	}
}

func TestSignV1SCTForPrecertificate(t *testing.T) {
	cert, err := x509util.CertificateFromPEM([]byte(testdata.PrecertPEMValid))
	if x509.IsFatal(err) {
		t.Fatalf("failed to set up test precert: %v", err)
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("could not create signer: %v", err)
	}

	// Use the same cert as the issuer for convenience.
	leaf, err := ct.MerkleTreeLeafFromChain([]*x509.Certificate{cert, cert}, ct.PrecertLogEntryType, fixedTimeMillis)
	if err != nil {
		t.Fatalf("buildV1MerkleTreeLeafForCert()=nil,%v; want _,nil", err)
	}
	got, err := BuildV1SCT(signer, leaf)
	if err != nil {
		t.Fatalf("buildV1SCT()=nil,%v; want _,nil", err)
	}

	expected := ct.SignedCertificateTimestamp{
		SCTVersion: 0,
		LogID:      ct.LogID{KeyID: demoLogID},
		Timestamp:  fixedTimeMillis,
		Extensions: ct.CTExtensions{},
		Signature: ct.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.ECDSA},
			Signature: fakeSignature}}

	if diff := pretty.Compare(*got, expected); diff != "" {
		t.Fatalf("Mismatched SCT (precert), diff:\n%v", diff)
	}

	// Additional checks that the MerkleTreeLeaf we built is correct
	if got, want := leaf.Version, ct.V1; got != want {
		t.Fatalf("Got a %v leaf, expected a %v leaf", got, want)
	}
	if got, want := leaf.LeafType, ct.TimestampedEntryLeafType; got != want {
		t.Fatalf("Got leaf type %v, expected %v", got, want)
	}
	if got, want := leaf.TimestampedEntry.EntryType, ct.PrecertLogEntryType; got != want {
		t.Fatalf("Got entry type %v, expected %v", got, want)
	}
	if got, want := got.Timestamp, leaf.TimestampedEntry.Timestamp; got != want {
		t.Fatalf("Entry / sct timestamp mismatch; got %v, expected %v", got, want)
	}
	keyHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if got, want := keyHash[:], leaf.TimestampedEntry.PrecertEntry.IssuerKeyHash[:]; !bytes.Equal(got, want) {
		t.Fatalf("Issuer key hash bytes mismatch, got %v, expected %v", got, want)
	}
	defangedTBS, _ := x509.RemoveCTPoison(cert.RawTBSCertificate)
	if got, want := leaf.TimestampedEntry.PrecertEntry.TBSCertificate, defangedTBS; !bytes.Equal(got, want) {
		t.Fatalf("TBS cert mismatch, got %v, expected %v", got, want)
	}
}

func TestGetCTLogID(t *testing.T) {
	block, _ := pem.Decode([]byte(testdata.DemoPublicKey))
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected error loading public key: %v", err)
	}

	got, err := getCTLogID(pk)
	if err != nil {
		t.Fatalf("error getting logid: %v", err)
	}

	if want := demoLogID; got != want {
		t.Errorf("logID: \n%v want \n%v", got, want)
	}
}

// Creates a fake signer for use in interaction tests.
// It will always return fakeSig when asked to sign something.
func setupSigner(fakeSig []byte) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(testdata.DemoPublicKey))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return testdata.NewSignerWithFixedSig(key, fakeSig), nil
}
