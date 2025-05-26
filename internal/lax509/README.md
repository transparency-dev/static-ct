# lax509

This is a minimalist fork of [`crypto/x509`](https://pkg.go.dev/crypto/x509).

> [!WARNING]
> This library is not safe to use for applications outside of this repository.

> [!WARNING]
> This fork will not be kept in synced with upstream. It will not be updated,
> unless required by a security vulnerability or a critical functionality issue.

## To be or not to be

As specified by [RFC6962 S3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1),
CT logs MUST validate submitted chains to ensure that they link up to roots
they accept. `crypto/x509` implements this, and also runs additional common
chain validation checks. However, these additional checks:

- Do not allow chains to contain precertificates or preissuers intermediates.
- Would block non compliant certificates signed by production roots from being
accepted, therefore preventing them from becoming transparency discoverable.

## The slings and arrows of outrageous fortune

The fork in this directory implements chain verification requirements from
[RFC6962 S3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1) and disables
some additional check, such as:

- **Handling of critical extensions**: CT precertificates are identified by a
critical extension defined in [RFC6962 S3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1),
 which the `crypto/x509` library does not process. A non-processed critical
 extension would fail certificate validation. This check is disabled to allow
 precertificate in the logs.
- **Cert expiry**: `notBefore` and `notAfter` certificate checks are handled at
submission time, based on the `notBeforeLimit` and `notAfterLimit` log
parameters. Therefore, not only we don't need to check them again at certificate
verification time, but we specifically want to accept all certificates within
the `[notBeforeLimit, notAfterLimit]` range, even if they have expired.
- **CA name restrictions**: an intermediate or root certificate can restrict the
domains it can issue certificates for. This check is disabled to make such
issuances discoverable.
- **Chain length**: this check is confused by chains including preissuer intermediates.
- **Extended Key Usage**: this would ensure that all the EKU of a child
certificate are also held by its parents. However, the EKU identifying preissuer
intermediate certs in [RFC6962S3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1)
does not need to be set in the issuing certificate, so this check would not pass
for chains using a preissuer intermediate. Also, see <https://github.com/golang/go/issues/24590>.
- **Policy graph validation**: chains that violate policy validation should be
discoverable through CT logs.

## To take arms against a sea of troubles

These additional checks can be disabled:

- Negative serial numbers are not allowed starting from go1.23. To allow
   them, set `x509negativeserial=1` in the GODBUG environment variable, either
   in your terminal at build time or with `//go:debug x509negativeserial=1` at
   the top of your main file.

## No more; and by a sleep to say we end

We've identified that the following root certificates and chains do not validate
with this library, while they would have validated with the [old CTFE library](https://github.com/google/certificate-transparency-go/tree/master/x509)
used by RFC6962 logs:

### Roots

- [Jerarquia Entitats de Certificacio Catalanes Root certificate](https://crt.sh/?sha256=88497F01602F3154246AE28C4D5AEF10F1D87EBB76626F4AE0B7F95BA7968799):
This certificate has a negative serial number, which is not allowed starting
from `go1.23`. At the time of writing, this certificate is trusted by the
Microsoft Root store, but not not seem to be used to issue certificates used for
server authentication.
- [Direccion General de Normatividad Mercantil Root certificate](https://crt.sh/?sha256=B41D516A5351D42DEEA191FA6EDF2A67DEE2F36DC969012C76669E616B900DDF):
affected by a known [crypto/x509 issue](https://github.com/golang/go/issues/69463).
This certificate expired on 2025-05-09.

### Chains

Chains that use `sha1WithRSAEncryption` as a signing algorithm do not validate. This
signing algorithm [has been rejected by `crypto/x509` since 2020](https://github.com/golang/go/issues/41682),
and by [Chromium since 2017](https://www.chromium.org/Home/chromium-security/education/tls/sha-1/).

Specifically, this means that chains issued by these roots do not validate:

- [Google's Merge Delay Monitor Root](https://crt.sh/?sha256=86D8219C7E2B6009E37EB14356268489B81379E076E8F372E3DDE8C162A34134):
this is the root used by Chrome to issue test certificate used to monitor CT
logs.
- [Cisco Root CA 2048](https://crt.sh?sha256=8327BC8C9D69947B3DE3C27511537267F59C21B9FA7B613FAFBCCD53B7024000)
such as [this chain](https://crt.sh/?id=284265742).
