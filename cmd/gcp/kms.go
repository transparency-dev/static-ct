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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// Signer is a GCP KMS implementation of
// [crypto signer](https://pkg.go.dev/crypto#Signer).
type Signer struct {
	// ctx must be stored because Signer is used as an implementation of the
	// crypto.Signer interface, which does not allow for a context in the Sign
	// method. However, the KMS AsymmetricSign API requires a context.
	ctx       context.Context
	client    *kms.KeyManagementClient
	keyName   string
	publicKey crypto.PublicKey
}

// Public returns the public key stored in the Signer object.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest using the KMS signing key remotely on GCP.
// Only crypto.SHA256 is supported.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Verify hash function and digest bytes length.
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported hash func: %v", opts.HashFunc())
	}
	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("digest bytes length %d does not match hash function bytes length %d", len(digest), opts.HashFunc().Size())
	}

	// Build the signing request and call the remote signing.
	req := &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
	}
	resp, err := s.client.AsymmetricSign(s.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	// Perform integrity verification on result.
	if resp.Name != s.keyName {
		return nil, fmt.Errorf("request corrupted in-transit: %w", err)
	}

	return resp.GetSignature(), nil
}

// NewKMSSigner creates a new signer that uses GCP KMS to sign digests.
func NewKMSSigner(ctx context.Context, keyName string) (*Signer, error) {
	kmClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create KeyManagementClient: %w", err)
	}

	// Retrieve the public key from GCP KMS
	req := &kmspb.GetPublicKeyRequest{
		Name: keyName,
	}
	resp, err := kmClient.GetPublicKey(ctx, req)
	if err != nil {
		return nil, err
	}

	pemBlock, rest := pem.Decode([]byte(resp.Pem))
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
	case "RSA PUBLIC KEY":
		publicKey, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", pemBlock.Type)
	}
	if err != nil {
		return nil, err
	}

	return &Signer{
		ctx:       ctx,
		client:    kmClient,
		keyName:   keyName,
		publicKey: publicKey,
	}, nil
}
