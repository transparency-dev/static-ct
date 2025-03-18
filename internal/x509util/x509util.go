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

// Package x509util includes utility code for working with X.509
// certificates from the x509 package.
package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// CertificateFromPEM takes a certificate in PEM format and returns the
// corresponding x509.Certificate object.
func CertificateFromPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(pemBytes)
	if len(rest) != 0 {
		return nil, errors.New("trailing data found after PEM block")
	}
	if block == nil {
		return nil, errors.New("PEM block is nil")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block is not a CERTIFICATE")
	}
	return x509.ParseCertificate(block.Bytes)
}
