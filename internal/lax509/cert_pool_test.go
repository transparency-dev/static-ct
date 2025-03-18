// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lax509

import (
	"crypto/x509"
	"testing"
)

func TestCertPoolEqual(t *testing.T) {
	tc := &x509.Certificate{Raw: []byte{1, 2, 3}, RawSubject: []byte{2}}
	otherTC := &x509.Certificate{Raw: []byte{9, 8, 7}, RawSubject: []byte{8}}

	emptyPool := NewCertPool()
	nonSystemPopulated := NewCertPool()
	nonSystemPopulated.AddCert(tc)
	nonSystemPopulatedAlt := NewCertPool()
	nonSystemPopulatedAlt.AddCert(otherTC)
	tests := []struct {
		name  string
		a     *CertPool
		b     *CertPool
		equal bool
	}{
		{
			name:  "two empty pools",
			a:     emptyPool,
			b:     emptyPool,
			equal: true,
		},
		{
			name:  "one empty pool, one populated pool",
			a:     emptyPool,
			b:     nonSystemPopulated,
			equal: false,
		},
		{
			name:  "two populated pools",
			a:     nonSystemPopulated,
			b:     nonSystemPopulated,
			equal: true,
		},
		{
			name:  "two populated pools, different content",
			a:     nonSystemPopulated,
			b:     nonSystemPopulatedAlt,
			equal: false,
		},
		{
			name:  "two nil pools",
			a:     nil,
			b:     nil,
			equal: true,
		},
		{
			name:  "one nil pool, one empty pool",
			a:     nil,
			b:     emptyPool,
			equal: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			equal := tc.a.Equal(tc.b)
			if equal != tc.equal {
				t.Errorf("Unexpected Equal result: got %t, want %t", equal, tc.equal)
			}
		})
	}
}
