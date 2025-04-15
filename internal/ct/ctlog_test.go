package ct

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/transparency-dev/static-ct/internal/x509util"
	"github.com/transparency-dev/static-ct/storage"
	"golang.org/x/mod/sumdb/note"
)

func TestNewLog(t *testing.T) {
	ctx := context.Background()
	ecdsaSigner, err := loadPEMPrivateKey("../testdata/test_ct_server_ecdsa_private_key.pem")
	if err != nil {
		t.Fatalf("Can't open key: %v", err)
	}
	rsaSigner, err := loadPEMPrivateKey("../testdata/test_ct_server_rsa_private_key.pem")
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	roots := x509util.NewPEMCertPool()
	if err := roots.AppendCertsFromPEMFile("../testdata/fake-ca.cert"); err != nil {
		t.Fatalf("Can't open roots: %v", err)
	}

	for _, tc := range []struct {
		desc    string
		origin  string
		wantErr string
		cv      chainValidator
		signer  crypto.Signer
	}{
		{
			desc:    "empty-origin",
			wantErr: "empty origin",
		},
		{
			desc:   "empty-signer",
			origin: "testlog",
			cv: chainValidator{
				trustedRoots: roots,
			},
			wantErr: "empty signer",
		},
		{
			desc:   "ok",
			origin: "testlog",
			cv: chainValidator{
				trustedRoots: roots,
			},
			signer: ecdsaSigner,
		},
		{
			desc:   "incorrect-signer-type",
			origin: "testlog",
			cv: chainValidator{
				trustedRoots: roots,
			},
			signer:  rsaSigner,
			wantErr: "unsupported key type",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			log, err := NewLog(ctx, tc.origin, tc.signer, tc.cv,
				func(_ context.Context, _ note.Signer) (*storage.CTStorage, error) {
					return &storage.CTStorage{}, nil
				}, &FixedTimeSource{})
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

func loadPEMPrivateKey(path string) (crypto.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM private key")
	}

	// Fix block type for testing keys.
	block.Type = strings.ReplaceAll(block.Type, "TESTING KEY", "PRIVATE KEY")

	var privateKey any
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return key, nil
	case ed25519.PrivateKey:
		return key, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}
