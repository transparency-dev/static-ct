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

package staticct

import (
	"encoding/base64"
	"fmt"
	"math"

	"github.com/transparency-dev/trillian-tessera/api/layout"
	"golang.org/x/crypto/cryptobyte"
)

///////////////////////////////////////////////////////////////////////////////
// The following structures represent those outlined in Static CT API.
///////////////////////////////////////////////////////////////////////////////

// EntryBundle represents a sequence of entries in the log.
// These entries correspond to a leaf tile in the hash tree.
type EntryBundle struct {
	// Entries stores the leaf entries of the log, in order.
	Entries [][]byte
}

// UnmarshalText implements encoding/TextUnmarshaler and reads EntryBundles
// which are encoded using the Static CT API spec.
func (t *EntryBundle) UnmarshalText(raw []byte) error {
	entries := make([][]byte, 0, layout.EntryBundleWidth)
	s := cryptobyte.String(raw)

	for len(s) > 0 {
		entry := []byte{}
		var timestamp uint64
		var entryType uint16
		var extensions, fingerprints cryptobyte.String
		if !s.ReadUint64(&timestamp) || !s.ReadUint16(&entryType) || timestamp > math.MaxInt64 {
			return fmt.Errorf("invalid data tile")
		}

		bb := []byte{}
		b := cryptobyte.NewBuilder(bb)
		b.AddUint64(timestamp)
		b.AddUint16(entryType)

		switch entryType {
		case 0: // x509_entry
			if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&entry)) ||
				!s.ReadUint16LengthPrefixed(&extensions) ||
				!s.ReadUint16LengthPrefixed(&fingerprints) {
				return fmt.Errorf("invalid data tile x509_entry")
			}
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(entry)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extensions)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(fingerprints)
			})

		case 1: // precert_entry
			IssuerKeyHash := [32]byte{}
			var defangedCrt, extensions cryptobyte.String
			if !s.CopyBytes(IssuerKeyHash[:]) ||
				!s.ReadUint24LengthPrefixed(&defangedCrt) ||
				!s.ReadUint16LengthPrefixed(&extensions) ||
				!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&entry)) ||
				!s.ReadUint16LengthPrefixed(&fingerprints) {
				return fmt.Errorf("invalid data tile precert_entry")
			}
			b.AddBytes(IssuerKeyHash[:])
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(defangedCrt)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extensions)
			})
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(entry)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(fingerprints)
			})
		default:
			return fmt.Errorf("invalid data tile: unknown type %d", entryType)
		}
		entries = append(entries, b.BytesOrPanic())
	}

	t.Entries = entries
	return nil
}

// parseCTExtensions parses CTEXtensions into an index.
// Code is inspired by https://github.com/FiloSottile/sunlight/blob/main/tile.go.
func ParseCTExtensions(ext string) (uint64, error) {
	extensionBytes, err := base64.StdEncoding.DecodeString(ext)
	if err != nil {
		return 0, fmt.Errorf("can't decode extensions: %v", err)
	}
	extensions := cryptobyte.String(extensionBytes)
	var extensionType uint8
	var extensionData cryptobyte.String
	var leafIdx int64
	if !extensions.ReadUint8(&extensionType) {
		return 0, fmt.Errorf("can't read extension type")
	}
	if extensionType != 0 {
		return 0, fmt.Errorf("wrong extension type %d, want 0", extensionType)
	}
	if !extensions.ReadUint16LengthPrefixed(&extensionData) {
		return 0, fmt.Errorf("can't read extension data")
	}
	if !readUint40(&extensionData, &leafIdx) {
		return 0, fmt.Errorf("can't read leaf index from extension")
	}
	if !extensionData.Empty() ||
		!extensions.Empty() {
		return 0, fmt.Errorf("invalid data tile extensions: %v", ext)
	}
	return uint64(leafIdx), nil
}

// readUint40 decodes a big-endian, 40-bit value into out and advances over it.
// It reports whether the read was successful.
// Code is copied from https://github.com/FiloSottile/sunlight/blob/main/extensions.go.
func readUint40(s *cryptobyte.String, out *int64) bool {
	var v []byte
	if !s.ReadBytes(&v, 5) {
		return false
	}
	*out = int64(v[0])<<32 | int64(v[1])<<24 | int64(v[2])<<16 | int64(v[3])<<8 | int64(v[4])
	return true
}
