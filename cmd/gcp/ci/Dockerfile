FROM sctfe-gcp:latest AS base

# Build release image
FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5

# Copy the hammer test root CA certificate into the container
COPY ./internal/hammer/testdata/test_root_ca_cert.pem /bin/

# Copy the sctfe-gcp binary
COPY --from=base /bin/sctfe-gcp /bin/

ENTRYPOINT ["/bin/sctfe-gcp"]
