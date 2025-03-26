# lax509

This is a minimalist fork of [`crypto/x509`](https://pkg.go.dev/crypto/x509). 

> [!WARNING]
> This library is not safe to use for applications outside of this repository.

> [!WARNING]
> This fork will not be kept in synced with upstream. It will not be updated, unless required by a security vulnerability or a critical functionality issue.

As specified by [RFC6962 S3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1), CT logs MUST validate sumbmitted chains to ensure that they link up to roots they accept. `crypto/x509` implements this, and also runs additional common chain validation checks. However, these additional checks:
 - Do not allow chains to contain precertificates or preissuers intermediates.
 - Would block non compliant certificates signed by production roots from being accepted, therefore preventing them from becoming transparency discoverable.

The fork in this directory implements chain verification requirements from [RFC6962 S3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1) and disables some additional check, such as:

  - **Handling of critical extensions**: CT precertificates are identified by a critical extension defined in [RFC6962 S3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1), which the `crypto/x509` library does not process. A non-processed critical extension would fail certificate validation. This check is disabled to allow precertificate in the logs.
  - **Cert expiry**: `notBefore` and `notAfter` certificate checks are handled at submission time, based on the `notBeforeLimit` and `notAfterLimit` log parameters. Therefore, not only we don't need to check them again at certificate verification time, but we specifically want to accept all certificates within the `[notBeforeLimit, notAfterLimit]` range, even if they have expired.
  - **CA name restrictions**: an intermediate or root certificate can restrict the domains it can issue certificates for. This check is disabled to make such issuances discoverable.
  - **Chain length**: this check is confused by chains including preissuer intermediates.
  - **Extended Key Usage**: this would ensure that all the EKU of a child certificate are also held by its parents. However, the EKU identifying preissuer intermediate certs in [RFC6962 S3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1) does not need to be set in the issuing certificate, so this check would not pass for chains using a preissuer intermediate. Also, see https://github.com/golang/go/issues/24590.
  - **Policy graph validation**: chains that violate policy validation should be discoverable through CT logs.

Disabling additional checks:

   - Negative serial numbers are not allowed starting from go1.23. To allow
   them, set `x509negativeserial=1` in the GODBUG environment variable, either
   in your terminal at build time or with `//go:debug x509negativeserial=1` at
   the top of your main file.
