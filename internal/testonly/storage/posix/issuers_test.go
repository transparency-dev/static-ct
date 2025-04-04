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

package posix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/transparency-dev/static-ct/storage"
)

func TestNewIssuerStorage(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid path",
			path:    tmpDir,
			wantErr: false,
		},
		{
			name:    "non-existent path",
			path:    filepath.Join(tmpDir, "nonexistent"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIssuerStorage(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIssuerStorage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKeyToObjName(t *testing.T) {
	tmpDir := t.TempDir()
	s := IssuersStorage(tmpDir)

	tests := []struct {
		name    string
		key     []byte
		want    string
		wantErr bool
	}{
		{
			name:    "valid key",
			key:     []byte("issuer1"),
			want:    filepath.Join(tmpDir, "issuer1"),
			wantErr: false,
		},
		{
			name:    "empty key",
			key:     []byte(""),
			wantErr: true,
		},
		{
			name:    "key with os.PathSeparator",
			key:     []byte(fmt.Sprintf("issuer%s1", string(os.PathSeparator))),
			want:    "",
			wantErr: true,
		},
		{
			name:    "key with multiple slashes",
			key:     []byte(fmt.Sprintf("issuer%s1%s2", string(os.PathSeparator), string(os.PathSeparator))),
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.keyToObjName(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("IssuersStorage.keyToObjName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IssuersStorage.keyToObjName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddIssuersIfNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := NewIssuerStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewIssuerStorage() failed: %v", err)
	}

	tests := []struct {
		name    string
		kv      []storage.KV
		want    map[string][]byte
		wantErr bool
	}{
		{
			name: "add single issuer",
			kv: []storage.KV{
				{K: []byte("issuer1"), V: []byte("issuer1 data")},
			},
			want: map[string][]byte{
				"issuer1": []byte("issuer1 data"),
			},
			wantErr: false,
		},
		{
			name: "add multiple issuers",
			kv: []storage.KV{
				{K: []byte("issuer2"), V: []byte("issuer2 data")},
				{K: []byte("issuer3"), V: []byte("issuer3 data")},
			},
			want: map[string][]byte{
				"issuer2": []byte("issuer2 data"),
				"issuer3": []byte("issuer3 data"),
			},
			wantErr: false,
		},
		{
			name: "add existing issuer",
			kv: []storage.KV{
				{K: []byte("issuer1"), V: []byte("issuer1 data")},
			},
			want: map[string][]byte{
				"issuer1": []byte("issuer1 data"),
			},
			wantErr: false,
		},
		{
			name: "add existing issuer with different data",
			kv: []storage.KV{
				{K: []byte("issuer1"), V: []byte("different data")},
			},
			want: map[string][]byte{
				"issuer1": []byte("issuer1 data"),
			},
			wantErr: true,
		},
		{
			name: "add new issuer and existing issuer",
			kv: []storage.KV{
				{K: []byte("issuer4"), V: []byte("issuer4 data")},
				{K: []byte("issuer1"), V: []byte("issuer1 data")},
			},
			want: map[string][]byte{
				"issuer1": []byte("issuer1 data"),
				"issuer4": []byte("issuer4 data"),
			},
			wantErr: false,
		},
		{
			name: "add issuer with invalid path",
			kv: []storage.KV{
				{K: []byte("dir1/dir2/issuer5"), V: []byte("issuer5 data")},
			},
			want:    map[string][]byte{},
			wantErr: true,
		},
		{
			name: "add issuer with empty path",
			kv: []storage.KV{
				{K: []byte(""), V: []byte("issuer5 data")},
			},
			want:    map[string][]byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.AddIssuersIfNotExist(context.Background(), tt.kv)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddIssuersIfNotExist() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for k, v := range tt.want {
				objName, err := s.keyToObjName([]byte(k))
				if err != nil {
					t.Errorf("Failed to convert key %q to object name: %v", k, err)
				}
				got, err := os.ReadFile(objName)
				if err != nil {
					t.Fatalf("Failed to read object %q: %v", objName, err)
				}
				if !reflect.DeepEqual(got, v) {
					t.Errorf("Object %q content mismatch: got %v, want %v", objName, got, v)
				}
			}
		})
	}
}
