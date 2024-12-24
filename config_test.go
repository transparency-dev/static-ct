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
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/google/trillian/crypto/keys/pem"
)

func TestValidateLogConfig(t *testing.T) {
	signer, err := pem.ReadPrivateKeyFile("./testdata/ct-http-server.privkey.pem", "dirk")
	if err != nil {
		t.Fatalf("Can't open key: %v", err)
	}

	t100 := time.Unix(100, 0)
	t200 := time.Unix(200, 0)

	for _, tc := range []struct {
		desc             string
		origin           string
		projectID        string
		bucket           string
		spannerDB        string
		wantErr          string
		rootsPemFile     string
		rejectExpired    bool
		rejectUnexpired  bool
		extKeyUsages     string
		rejectExtensions string
		notAfterStart    *time.Time
		notAfterLimit    *time.Time
		signer           crypto.Signer
	}{
		{
			desc:      "empty-origin",
			wantErr:   "empty origin",
			projectID: "project",
			bucket:    "bucket",
			spannerDB: "spanner",
		},
		{
			desc:      "empty-rootsPemFile",
			wantErr:   "empty rootsPemFile",
			origin:    "testlog",
			projectID: "project",
			bucket:    "bucket",
			spannerDB: "spanner",
			signer:    signer,
		},
		{
			desc:         "missing-root-cert",
			wantErr:      "failed to read trusted roots",
			origin:       "testlog",
			projectID:    "project",
			bucket:       "bucket",
			spannerDB:    "spanner",
			rootsPemFile: "./testdata/bogus.cert",
			signer:       signer,
		},
		{
			desc:            "rejecting-all",
			wantErr:         "rejecting all certificates",
			origin:          "testlog",
			projectID:       "project",
			bucket:          "bucket",
			spannerDB:       "spanner",
			rootsPemFile:    "./testdata/fake-ca.cert",
			rejectExpired:   true,
			rejectUnexpired: true,
			signer:          signer,
		},
		{
			desc:         "unknown-ext-key-usage-1",
			wantErr:      "unknown extended key usage",
			origin:       "testlog",
			projectID:    "project",
			bucket:       "bucket",
			spannerDB:    "spanner",
			rootsPemFile: "./testdata/fake-ca.cert",
			extKeyUsages: "wrong_usage",
			signer:       signer,
		},
		{
			desc:         "unknown-ext-key-usage-2",
			wantErr:      "unknown extended key usage",
			origin:       "testlog",
			projectID:    "project",
			bucket:       "bucket",
			spannerDB:    "spanner",
			rootsPemFile: "./testdata/fake-ca.cert",
			extKeyUsages: "ClientAuth,ServerAuth,TimeStomping",
			signer:       signer,
		},
		{
			desc:         "unknown-ext-key-usage-3",
			wantErr:      "unknown extended key usage",
			origin:       "testlog",
			projectID:    "project",
			bucket:       "bucket",
			spannerDB:    "spanner",
			rootsPemFile: "./testdata/fake-ca.cert",
			extKeyUsages: "Any ",
			signer:       signer,
		},
		{
			desc:             "unknown-reject-ext",
			wantErr:          "failed to parse RejectExtensions",
			origin:           "testlog",
			projectID:        "project",
			bucket:           "bucket",
			spannerDB:        "spanner",
			rootsPemFile:     "./testdata/fake-ca.cert",
			rejectExtensions: "1.2.3.4,one.banana.two.bananas",
			signer:           signer,
		},
		{
			desc:          "limit-before-start",
			wantErr:       "limit before start",
			origin:        "testlog",
			projectID:     "project",
			bucket:        "bucket",
			spannerDB:     "spanner",
			rootsPemFile:  "./testdata/fake-ca.cert",
			notAfterStart: &t200,
			notAfterLimit: &t100,
			signer:        signer,
		},
		{
			desc:         "ok",
			origin:       "testlog",
			projectID:    "project",
			bucket:       "bucket",
			spannerDB:    "spanner",
			rootsPemFile: "./testdata/fake-ca.cert",
			signer:       signer,
		},
		{
			desc:         "ok-ext-key-usages",
			origin:       "testlog",
			projectID:    "project",
			bucket:       "bucket",
			spannerDB:    "spanner",
			rootsPemFile: "./testdata/fake-ca.cert",
			extKeyUsages: "ServerAuth,ClientAuth,OCSPSigning",
			signer:       signer,
		},
		{
			desc:             "ok-reject-ext",
			origin:           "testlog",
			projectID:        "project",
			bucket:           "bucket",
			spannerDB:        "spanner",
			rootsPemFile:     "./testdata/fake-ca.cert",
			rejectExtensions: "1.2.3.4,5.6.7.8",
			signer:           signer,
		},
		{
			desc:          "ok-start-timestamp",
			origin:        "testlog",
			projectID:     "project",
			bucket:        "bucket",
			spannerDB:     "spanner",
			rootsPemFile:  "./testdata/fake-ca.cert",
			notAfterStart: &t100,
			signer:        signer,
		},
		{
			desc:          "ok-limit-timestamp",
			origin:        "testlog",
			projectID:     "project",
			bucket:        "bucket",
			spannerDB:     "spanner",
			rootsPemFile:  "./testdata/fake-ca.cert",
			notAfterStart: &t200,
			signer:        signer,
		},
		{
			desc:          "ok-range-timestamp",
			origin:        "testlog",
			projectID:     "project",
			bucket:        "bucket",
			spannerDB:     "spanner",
			rootsPemFile:  "./testdata/fake-ca.cert",
			notAfterStart: &t100,
			notAfterLimit: &t200,
			signer:        signer,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			vc, err := ValidateLogConfig(tc.origin, tc.rootsPemFile, tc.rejectExpired, tc.rejectUnexpired, tc.extKeyUsages, tc.rejectExtensions, tc.notAfterStart, tc.notAfterLimit, signer)
			if len(tc.wantErr) == 0 && err != nil {
				t.Errorf("ValidateLogConfig()=%v, want nil", err)
			}
			if len(tc.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("ValidateLogConfig()=%v, want err containing %q", err, tc.wantErr)
			}
			if err == nil && vc == nil {
				t.Error("err and ValidatedLogConfig are both nil")
			}
			// TODO(pavelkalinnikov): Test that ValidatedLogConfig is correct.
		})
	}
}
