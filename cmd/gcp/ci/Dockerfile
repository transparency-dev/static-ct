FROM sctfe-gcp:latest AS base

# Copy the fake CA certificate into the container
COPY ./testdata/fake-ca.cert /bin/

# Copy the sctfe-gcp binary
COPY --from=base /bin/sctfe-gcp /bin/

ENTRYPOINT ["/bin/sctfe-gcp"]
