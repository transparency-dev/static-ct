package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

func hasSANExtension(c *x509.Certificate) bool {
	return oidInExtensions(oidExtensionSubjectAltName, c.Extensions)
}

// oidInExtensions reports whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}
