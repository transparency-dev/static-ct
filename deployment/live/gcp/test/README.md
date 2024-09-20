# GCP SCTFE Configs

## Prerequisites
You'll need to have a VM running in the same GCP project that you can SSH to,
with go installed.

## Overview

This config uses the [gcp/storage](/deployment/modules/gcp/conformance) module to
define a test environment to run the SCTFE, backed by Trillian Tessera.

At a high level, this environment consists of:
- Spanner DB
- GCS Bucket
- VM to run the code

## Manual deployment 

This 

First authenticate via `gcloud` as a principle with sufficient ACLs for
the project:
```bash
gcloud auth application-default login
```

Set the required environment variables:
```bash
export GOOGLE_PROJECT={VALUE}
export GOOGLE_REGION={VALUE} # e.g: us-central1
export TESSERA_BASE_NAME={VALUE} # e.g: staticct
```

Terraforming the project can be done by:
 1. `cd` to the relevant directory for the environment to deploy/change (e.g. `ci`)
 2. Run `terragrunt apply`

## Run the SCTFE

Run the following command:
```bash
go run ./cmd/gcp/ --project_id=${GOOGLE_PROJECT} --bucket=${GOOGLE_PROJECT}-${TESSERA_BASE_NAME}-bucket --spanner_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-db --spanner_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-dedup-db --private_key=./testdata/ct-http-server.privkey.pem  --password=dirk --roots_pem_file=./testdata/fake-ca.cert --origin=${TESSERA_BASE_NAME}
```
