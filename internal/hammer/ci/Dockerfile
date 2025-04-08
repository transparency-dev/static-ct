FROM tesseract-hammer:latest AS base

# Build release image
FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5

# Copy the hammer test intermediate CA certificate, intermediate CA key and certificate signing private key into the container
COPY ./internal/hammer/testdata/test_intermediate_ca_cert.pem ./internal/hammer/testdata/test_intermediate_ca_private_key.pem ./internal/hammer/testdata/test_leaf_cert_signing_private_key.pem /bin/

# Copy the hammer binary
COPY --from=base /bin/hammer /bin/

ENTRYPOINT ["/bin/hammer"]
