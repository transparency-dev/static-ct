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

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// ECDSAWithSHA256Signer implements crypto.Signer using Google Cloud Secret Manager.
// Only crypto.SHA256 and ECDSA are supported.
type ECDSAWithSHA256Signer struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
}

// Public returns the public key stored in the Signer object.
func (s *ECDSAWithSHA256Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the private key stored in Google Cloud Secret Manager.
func (s *ECDSAWithSHA256Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Verify hash function and digest bytes length.
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported hash func: %v", opts.HashFunc())
	}
	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("digest bytes length %d does not match hash function bytes length %d", len(digest), opts.HashFunc().Size())
	}

	privateKey, ok := s.privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the key stored in Secret Manager is not an ECDSA key")
	}

	return ecdsa.SignASN1(rand, privateKey, digest)
}

// NewSecretManagerSigner creates a new signer that uses the ECDSA P-256 key pair in
// Google Cloud Secret Manager for signing digests.
func NewSecretManagerSigner(ctx context.Context, publicKeySecretName, privateKeySecretName string) (*ECDSAWithSHA256Signer, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	defer client.Close()

	// Public Key
	publicKeyRaw, err := accessSecretVersion(ctx, client, publicKeySecretName)
	if err != nil {
		return nil, fmt.Errorf("failed to access public key secret (%s): %w", publicKeySecretName, err)
	}
	pemBlock, rest := pem.Decode([]byte(publicKeyRaw))
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("extra data after decoding PEM: %v", rest)
	}
	var publicKey crypto.PublicKey
	switch pemBlock.Type {
	case "PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", pemBlock.Type)
	}
	if err != nil {
		return nil, err
	}

	// Private Key
	privateKeyRaw, err := accessSecretVersion(ctx, client, privateKeySecretName)
	if err != nil {
		return nil, fmt.Errorf("failed to access private key secret (%s): %w", privateKeySecretName, err)
	}
	pemBlock, rest = pem.Decode([]byte(privateKeyRaw))
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("extra data after decoding PEM: %v", rest)
	}
	var privateKey crypto.PrivateKey
	switch pemBlock.Type {
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", pemBlock.Type)
	}
	if err != nil {
		return nil, err
	}

	return &ECDSAWithSHA256Signer{
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

func accessSecretVersion(ctx context.Context, client *secretmanager.Client, secretName string) ([]byte, error) {
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}
	if resp.Name != secretName {
		return nil, errors.New("request corrupted in-transit")
	}
	// Verify the data checksum.
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(resp.Payload.Data, crc32c))
	if checksum != *resp.Payload.DataCrc32C {
		return nil, errors.New("Data corruption detected.")
	}

	return resp.Payload.Data, nil
}