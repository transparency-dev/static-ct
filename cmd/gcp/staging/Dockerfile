FROM sctfe-gcp:latest AS base

# Build release image
FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

# Copy roots into the container
# TODO(phbnf): use a better name without test, right now this is what works with main.tf
COPY ./deployment/live/gcp/static-ct-staging/logs/arche2025h1/roots.pem /bin/test_root_ca_cert.pem

# Copy the sctfe-gcp binary
COPY --from=base /bin/sctfe-gcp /bin/

ENTRYPOINT ["/bin/sctfe-gcp"]
