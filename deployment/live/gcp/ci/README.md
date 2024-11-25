# GCP SCTFE CI Environment

## Overview

This config uses the [gcp/conformance](/deployment/modules/gcp/conformance) module to
define a CI environment to run the SCTFE, backed by Trillian Tessera.

At a high level, this environment consists of:
- One Spanner instance with two databases:
  - one for Tessera
  - one for deduplication
- A GCS Bucket
- Secret Manager
- Cloud Run

### Manual Deployment

First authenticate via `gcloud` as a principle with sufficient ACLs for
the project:

```sh
gcloud auth application-default login
```

Set the required environment variables:

```sh
export GOOGLE_PROJECT={VALUE}
export GOOGLE_REGION={VALUE} # e.g: us-central1
unset TESSERA_BASE_NAME
```

Build and push the Docker image to Artifact Registry repository:

```sh
gcloud auth configure-docker ${GOOGLE_REGION}-docker.pkg.dev
docker build -f ./cmd/gcp/Dockerfile -t sctfe-gcp:latest .
docker build -f ./cmd/gcp/ci/Dockerfile -t conformance-gcp:latest .
docker tag conformance-gcp:latest ${GOOGLE_REGION}-docker.pkg.dev/${GOOGLE_PROJECT}/docker-ci/conformance-gcp:latest
docker push ${GOOGLE_REGION}-docker.pkg.dev/${GOOGLE_PROJECT}/docker-ci/conformance-gcp
```

Terraforming the project can be done by:
  1. `cd` to the relevant directory (deployment/live/gcp/ci/) for the environment to deploy/change.
  2. Run `terragrunt apply`.
