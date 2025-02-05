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

package sctfe

import (
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/google/trillian/crypto/keys/pem"
	"github.com/transparency-dev/static-ct/storage"
	"golang.org/x/mod/sumdb/note"
)

func TestNewCertValidationOpts(t *testing.T) {
	t100 := time.Unix(100, 0)
	t200 := time.Unix(200, 0)

	for _, tc := range []struct {
		desc    string
		wantErr string
		cvcfg   ChainValidationConfig
	}{
		{
			desc:    "empty-rootsPemFile",
			wantErr: "empty rootsPemFile",
		},
		{
			desc:    "missing-root-cert",
			wantErr: "failed to read trusted roots",
			cvcfg: ChainValidationConfig{
				RootsPEMFile: "./internal/testdata/bogus.cert",
			},
		},
		{
			desc:    "rejecting-all",
			wantErr: "configuration would reject all certificates",
			cvcfg: ChainValidationConfig{
				RootsPEMFile:    "./internal/testdata/fake-ca.cert",
				RejectExpired:   true,
				RejectUnexpired: true},
		},
		{
			desc:    "unknown-ext-key-usage-1",
			wantErr: "unknown extended key usage",
			cvcfg: ChainValidationConfig{
				RootsPEMFile: "./internal/testdata/fake-ca.cert",
				ExtKeyUsages: "wrong_usage"},
		},
		{
			desc:    "unknown-ext-key-usage-2",
			wantErr: "unknown extended key usage",
			cvcfg: ChainValidationConfig{
				RootsPEMFile: "./internal/testdata/fake-ca.cert",
				ExtKeyUsages: "ClientAuth,ServerAuth,TimeStomping",
			},
		},
		{
			desc:    "unknown-ext-key-usage-3",
			wantErr: "unknown extended key usage",
			cvcfg: ChainValidationConfig{
				RootsPEMFile: "./internal/testdata/fake-ca.cert",
				ExtKeyUsages: "Any ",
			},
		},
		{
			desc:    "unknown-reject-ext",
			wantErr: "failed to parse RejectExtensions",
			cvcfg: ChainValidationConfig{
				RootsPEMFile:     "./internal/testdata/fake-ca.cert",
				RejectExtensions: "1.2.3.4,one.banana.two.bananas",
			},
		},
		{
			desc:    "limit-before-start",
			wantErr: "before start",
			cvcfg: ChainValidationConfig{
				RootsPEMFile:  "./internal/testdata/fake-ca.cert",
				NotAfterStart: &t200,
				NotAfterLimit: &t100,
			},
		},
		{
			desc: "ok",
			cvcfg: ChainValidationConfig{
				RootsPEMFile: "./internal/testdata/fake-ca.cert",
			},
		},
		{
			desc: "ok-ext-key-usages",
			cvcfg: ChainValidationConfig{
				RootsPEMFile: "./internal/testdata/fake-ca.cert",
				ExtKeyUsages: "ServerAuth,ClientAuth,OCSPSigning",
			},
		},
		{
			desc: "ok-reject-ext",
			cvcfg: ChainValidationConfig{
				RootsPEMFile:     "./internal/testdata/fake-ca.cert",
				RejectExtensions: "1.2.3.4,5.6.7.8",
			},
		},
		{
			desc: "ok-start-timestamp",
			cvcfg: ChainValidationConfig{
				RootsPEMFile:  "./internal/testdata/fake-ca.cert",
				NotAfterStart: &t100,
			},
		},
		{
			desc: "ok-limit-timestamp",
			cvcfg: ChainValidationConfig{
				RootsPEMFile:  "./internal/testdata/fake-ca.cert",
				NotAfterStart: &t200,
			},
		},
		{
			desc: "ok-range-timestamp",
			cvcfg: ChainValidationConfig{
				RootsPEMFile:  "./internal/testdata/fake-ca.cert",
				NotAfterStart: &t100,
				NotAfterLimit: &t200,
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			vc, err := newCertValidationOpts(tc.cvcfg)
			if len(tc.wantErr) == 0 && err != nil {
				t.Errorf("ValidateLogConfig()=%v, want nil", err)
			}
			if len(tc.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("ValidateLogConfig()=%v, want err containing %q", err, tc.wantErr)
			}
			if err == nil && vc == nil {
				t.Error("err and ValidatedLogConfig are both nil")
			}
		})
	}
}

func TestNewLog(t *testing.T) {
	ctx := context.Background()
	signer, err := pem.ReadPrivateKeyFile("./internal/testdata/ct-http-server.privkey.pem", "dirk")
	if err != nil {
		t.Fatalf("Can't open key: %v", err)
	}

	for _, tc := range []struct {
		desc    string
		origin  string
		wantErr string
		cvcfg   ChainValidationConfig
		signer  crypto.Signer
	}{
		{
			desc:    "empty-origin",
			wantErr: "empty origin",
		},
		// TODO(phboneff): add a test for a signer of the wrong type
		{
			desc:   "ok",
			origin: "testlog",
			cvcfg: ChainValidationConfig{
				RootsPEMFile: "./internal/testdata/fake-ca.cert",
			},
			signer: signer,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			log, err := newLog(ctx, tc.origin, tc.signer, tc.cvcfg,
				func(_ context.Context, _ note.Signer) (*storage.CTStorage, error) {
					return &storage.CTStorage{}, nil
				})
			if len(tc.wantErr) == 0 && err != nil {
				t.Errorf("NewLog()=%v, want nil", err)
			}
			if len(tc.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("NewLog()=%v, want err containing %q", err, tc.wantErr)
			}
			if err == nil && log == nil {
				t.Error("err and log are both nil")
			}
		})
	}
}
