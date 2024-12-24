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
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/monitoring"
)

func TestSetUpInstance(t *testing.T) {
	ctx := context.Background()

	signer, err := pem.ReadPrivateKeyFile("./testdata/ct-http-server.privkey.pem", "dirk")
	if err != nil {
		t.Fatalf("Can't open key: %v", err)
	}

	var tests = []struct {
		desc             string
		origin           string
		rootsPemFile     string
		extKeyUsages     string
		rejectExtensions string
		signer           crypto.Signer
		wantErr          string
	}{
		{
			desc:         "valid",
			origin:       "log",
			rootsPemFile: "./testdata/fake-ca.cert",
			signer:       signer,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			vCfg, err := ValidateLogConfig(test.origin, test.rootsPemFile, false, false, test.extKeyUsages, test.rejectExtensions, nil, nil, signer)
			if err != nil {
				t.Fatalf("ValidateLogConfig(): %v", err)
			}
			opts := InstanceOptions{Validated: vCfg, Deadline: time.Second, MetricFactory: monitoring.InertMetricFactory{}, Storage: &CTStorage{}}

			if _, err := SetUpInstance(ctx, opts); err != nil {
				if test.wantErr == "" {
					t.Errorf("SetUpInstance()=_,%v; want _,nil", err)
				} else if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("SetUpInstance()=_,%v; want err containing %q", err, test.wantErr)
				}
				return
			}
			if test.wantErr != "" {
				t.Errorf("SetUpInstance()=_,nil; want err containing %q", test.wantErr)
			}
		})
	}
}

func equivalentTimes(a *time.Time, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil {
		// b can't be nil as it would have returned above.
		return false
	}
	return a.Equal(*b)
}

// This tests that the right values of LogInfo are passed through. We can probably delete these tests, or check
// that the whole loginfo is passed through.
func TestSetUpInstanceSetsValidationOpts(t *testing.T) {
	ctx := context.Background()

	start := time.Unix(10000, 0)
	limit := time.Unix(12000, 0)

	signer, err := pem.ReadPrivateKeyFile("./testdata/ct-http-server.privkey.pem", "dirk")
	if err != nil {
		t.Fatalf("Can't open key: %v", err)
	}

	var tests = []struct {
		desc          string
		origin        string
		rootsPemFile  string
		notAfterStart *time.Time
		notAfterLimit *time.Time
		signer        crypto.Signer
	}{
		{
			desc:         "no validation opts",
			origin:       "log",
			rootsPemFile: "./testdata/fake-ca.cert",
			signer:       signer,
		},
		{
			desc:          "notAfterStart only",
			origin:        "log",
			rootsPemFile:  "./testdata/fake-ca.cert",
			notAfterStart: &start,
		},
		{
			desc:          "notAfter range",
			origin:        "log",
			rootsPemFile:  "./testdata/fake-ca.cert",
			notAfterStart: &start,
			notAfterLimit: &limit,
			signer:        signer,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			vCfg, err := ValidateLogConfig(test.origin, test.rootsPemFile, false, false, "", "", test.notAfterStart, test.notAfterLimit, signer)
			if err != nil {
				t.Fatalf("ValidateLogConfig(): %v", err)
			}
			opts := InstanceOptions{Validated: vCfg, Deadline: time.Second, MetricFactory: monitoring.InertMetricFactory{}, Storage: &CTStorage{}}

			inst, err := SetUpInstance(ctx, opts)
			if err != nil {
				t.Fatalf("%v: SetUpInstance() = %v, want no error", test.desc, err)
			}
			addChainHandler, ok := inst.Handlers["/"+test.origin+ct.AddChainPath]
			if !ok {
				t.Fatal("Couldn't find AddChain handler")
			}
			gotOpts := addChainHandler.Info.validationOpts
			if got, want := gotOpts.notAfterStart, test.notAfterStart; !equivalentTimes(got, want) {
				t.Errorf("%v: handler notAfterStart %v, want %v", test.desc, got, want)
			}
			if got, want := gotOpts.notAfterLimit, test.notAfterLimit; !equivalentTimes(got, want) {
				t.Errorf("%v: handler notAfterLimit %v, want %v", test.desc, got, want)
			}
		})
	}
}

func TestErrorMasking(t *testing.T) {
	info := logInfo{}
	w := httptest.NewRecorder()
	prefix := "Internal Server Error"
	err := errors.New("well that's bad")
	info.SendHTTPError(w, 500, err)
	if got, want := w.Body.String(), fmt.Sprintf("%s\n%v\n", prefix, err); got != want {
		t.Errorf("SendHTTPError: got %s, want %s", got, want)
	}
	info.maskInternalErrors = true
	w = httptest.NewRecorder()
	info.SendHTTPError(w, 500, err)
	if got, want := w.Body.String(), prefix+"\n"; got != want {
		t.Errorf("SendHTTPError: got %s, want %s", got, want)
	}

}
