package scti

import (
	"context"
	"crypto"
	"strings"
	"testing"

	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/transparency-dev/static-ct/storage"
	"golang.org/x/mod/sumdb/note"
)

func TestNewLog(t *testing.T) {
	ctx := context.Background()
	signer, err := pem.ReadPrivateKeyFile("../testdata/ct-http-server.privkey.pem", "dirk")
	if err != nil {
		t.Fatalf("Can't open key: %v", err)
	}
	roots := x509util.NewPEMCertPool()
	if err := roots.AppendCertsFromPEMFile("../testdata/fake-ca.cert"); err != nil {
		t.Fatalf("Can't open roots: %v", err)
	}

	for _, tc := range []struct {
		desc    string
		origin  string
		wantErr string
		cvOpts  ChainValidationOpts
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
			cvOpts: ChainValidationOpts{
				trustedRoots: roots,
			},
			signer: signer,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			log, err := NewLog(ctx, tc.origin, tc.signer, tc.cvOpts,
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
