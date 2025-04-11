FROM sctfe-aws:latest AS base

# Build release image
FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

# Copy the hammer test root CA certificate into the container
COPY ./internal/hammer/testdata/test_root_ca_cert.pem /bin/

# Copy the sctfe-aws binary
COPY --from=base /bin/sctfe-aws /bin/

ENTRYPOINT ["/bin/sctfe-aws"]
