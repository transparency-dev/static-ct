// Copyright 2025 The Tessera authors. All Rights Reserved.
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

// gen is a tool to generate test EC keys and test certificates for hammer.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

const (
	commonName   = "test.transparency.dev"
	organization = "TrustFabric Transparency.dev Test"
	country      = "GB"
)

var (
	outputPath = flag.String("output_path", "./internal/testdata/", "Output path for private keys and certificates")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	// Generate root.
	// Generate a new EC root CA private key.
	rootPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		klog.Fatalf("Failed to generate root CA private key: %v", err)
	}
	if err := saveECDSAPrivateKeyPEM(rootPrivKey, path.Join(*outputPath, "test_root_ca_private_key.pem")); err != nil {
		klog.Fatalf("Failed to save root CA private key: %v", err)
	}

	// Generate a new root CA certificate.
	rootCert, err := rootCACert(rootPrivKey)
	if err != nil {
		klog.Fatalf("Failed to generate root CA certificate: %v", err)
	}
	if err := saveCertificatePEM(rootCert, path.Join(*outputPath, "test_root_ca_cert.pem")); err != nil {
		klog.Fatalf("Failed to save root CA certificate: %v", err)
	}

	genLeaves(rootCert, rootPrivKey)
	genPreIssuerAndLeaves(rootCert, rootPrivKey)

}

// genPreIssuerAndLeaves generates a cert and a pre-cert.
func genLeaves(rootCert *x509.Certificate, rootPrivKey *ecdsa.PrivateKey) {
	// Generate leaf certs chaining to root.
	// Generate a new ECDSA leaf certificate signing private key.
	leafCertPrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		klog.Fatalf("Failed to generate leaf certificate signing private key: %v", err)
	}
	if err := saveECDSAPrivateKeyPEM(leafCertPrivateKey, path.Join(*outputPath, "test_leaf_signed_by_root_signing_private_key.pem")); err != nil {
		klog.Fatalf("Failed to save leaf certificate signing private key: %v", err)
	}

	chainGenerator := newChainGenerator(rootCert, rootPrivKey, leafCertPrivateKey.Public())
	leafCert, err := chainGenerator.certificate(100, false)
	if err != nil {
		klog.Fatalf("Failed to generate leaf certificate: %v", err)
	}
	if err := saveCertificatePEM(leafCert, path.Join(*outputPath, "test_leaf_cert_signed_by_root.pem")); err != nil {
		klog.Fatalf("Failed to save leaf cert: %v", err)
	}
	leafPreCert, err := chainGenerator.certificate(200, true)
	if err != nil {
		klog.Fatalf("Failed to generate leaf certificate: %v", err)
	}
	if err := saveCertificatePEM(leafPreCert, path.Join(*outputPath, "test_leaf_pre_cert_signed_by_root.pem")); err != nil {
		klog.Fatalf("Failed to save leaf cert: %v", err)
	}

}

// genPreIssuerAndLeaves generates a pre-issuer intermediate cert, a cert,
// a pre-cert.
func genPreIssuerAndLeaves(rootCert *x509.Certificate, rootPrivKey *ecdsa.PrivateKey) {
	// Generate a new ECDSA intermediate CA private key.
	preIntermediatePrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		klog.Fatalf("Failed to generate intermediate CA private key: %v", err)
	}
	if err := saveECDSAPrivateKeyPEM(preIntermediatePrivKey, path.Join(*outputPath, "test_pre_intermediate_ca_private_key.pem")); err != nil {
		klog.Fatalf("Failed to save intermediate CA private key: %v", err)
	}

	// Generate a new intermediate CA certificate with CT extension.
	preIntermediateCert, err := intermediateCACert(rootCert, rootPrivKey, preIntermediatePrivKey, true)
	if err != nil {
		klog.Fatalf("Failed to generate intermediate CA certificate: %v", err)
	}
	if err := saveCertificatePEM(preIntermediateCert, path.Join(*outputPath, "test_pre_intermediate_ca_cert.pem")); err != nil {
		klog.Fatalf("Failed to save intermediate CA certificate: %v", err)
	}

	// Generate a new ECDSA leaf certificate signing private key.
	leafCertPrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		klog.Fatalf("Failed to generate leaf certificate signing private key: %v", err)
	}
	if err := saveECDSAPrivateKeyPEM(leafCertPrivateKey, path.Join(*outputPath, "test_leaf_signed_by_pre_intermediate_signing_private_key.pem")); err != nil {
		klog.Fatalf("Failed to save leaf certificate signing private key: %v", err)
	}

	chainGenerator := newChainGenerator(preIntermediateCert, preIntermediatePrivKey, leafCertPrivateKey.Public())
	leafCert, err := chainGenerator.certificate(100, false)
	if err != nil {
		klog.Fatalf("Failed to generate leaf certificate: %v", err)
	}
	if err := saveCertificatePEM(leafCert, path.Join(*outputPath, "test_leaf_cert_signed_by_pre_intermediate.pem")); err != nil {
		klog.Fatalf("Failed to save leaf cert: %v", err)
	}
	leafPreCert, err := chainGenerator.certificate(200, true)
	if err != nil {
		klog.Fatalf("Failed to generate leaf certificate: %v", err)
	}
	if err := saveCertificatePEM(leafPreCert, path.Join(*outputPath, "test_leaf_pre_cert_signed_by_pre_intermediate.pem")); err != nil {
		klog.Fatalf("Failed to save leaf cert: %v", err)
	}
}

func rootCACert(privKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{fmt.Sprintf("%s Root Test CA", organization)},
			Country:      []string{country},
			CommonName:   fmt.Sprintf("%s Root Test CA", organization),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the self-signed certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create root certificate: %v", err)
	}

	// Parse the DER-encoded certificate.
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %v", err)
	}

	return cert, nil
}

func intermediateCACert(rootCACert *x509.Certificate, rootPrivKey, privKey *ecdsa.PrivateKey, preIntermediate bool) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{fmt.Sprintf("%s Intermediate Test CA", organization)},
			Country:      []string{country},
			CommonName:   fmt.Sprintf("%s Intermediate Test CA", organization),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	if preIntermediate {
		preIssuerExtension := pkix.Extension{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4},
		}
		template.ExtraExtensions = append(template.ExtraExtensions, preIssuerExtension)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCACert, privKey.Public(), rootPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate certificate: %v", err)
	}

	return cert, nil
}

const (
	organizationalUnit = "TrustFabric"
	locality           = "London"
	state              = "London"
)

type chainGenerator struct {
	intermediateCert  *x509.Certificate
	intermediateKey   any
	leafCertPublicKey any
}

// newChainGenerator creates the chainGenerator.
func newChainGenerator(intermediateCert *x509.Certificate, intermediateKey, leafCertPublicKey any) *chainGenerator {
	return &chainGenerator{
		intermediateCert:  intermediateCert,
		intermediateKey:   intermediateKey,
		leafCertPublicKey: leafCertPublicKey,
	}
}

// certificate generates a deterministic TLS certificate by using integer as the serial number.
func (g *chainGenerator) certificate(serialNumber int64, preCert bool) (*x509.Certificate, error) {
	notBefore := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Locality:           []string{locality},
			Province:           []string{state},
			Country:            []string{country},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}

	ctPoison := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
		Critical: true,
		Value:    []byte{0x05, 0x00}, // ASN.1 NULL
	}

	if preCert {
		template.ExtraExtensions = append(template.ExtraExtensions, ctPoison)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, g.intermediateCert, g.leafCertPublicKey, g.intermediateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf certificate: %v", err)
	}

	// Parse the DER-encoded certificate.
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %v", err)
	}

	return cert, nil
}

func saveECDSAPrivateKeyPEM(key *ecdsa.PrivateKey, filename string) error {
	// Marshal the private key to SEC1 ASN.1 DER.
	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal EC private key: %w", err)
	}

	// No encryption.
	block := &pem.Block{
		Type:  "EC TESTING KEY",
		Bytes: derBytes,
	}

	// Encode the PEM block to memory.
	pemData := pem.EncodeToMemory(block)

	// Write the PEM data to the file with restrictive permissions.
	if err := os.WriteFile(filename, pemData, 0600); err != nil {
		return fmt.Errorf("failed to write PEM file: %w", err)
	}

	return nil
}

func saveCertificatePEM(cert *x509.Certificate, filename string) error {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err := os.WriteFile(filename, pemData, 0644); err != nil {
		return fmt.Errorf("failed to write PEM file: %w", err)
	}
	// TODO(phboneff): automate cert printin in certificate.go
	fmt.Println("Don't forget to update certificate.go with the matching openssl text output.")
	return nil
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		ecdsaKey, err := x509.ParseECPrivateKey(keyBytes)
		if err == nil {
			return ecdsaKey, nil
		}
		return nil, fmt.Errorf("failed to decode PEM block and failed to parse as DER: %w", err)
	}

	// Fix block type for testing keys.
	block.Type = testingKey(block.Type)

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func loadCert(path string) (*x509.Certificate, error) {
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
	return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY")
}
