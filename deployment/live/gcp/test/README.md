# GCP SCTFE Configs

## Prerequisites
You'll need to have a VM running in the same GCP project that you can SSH to,
with Go installed, and you favourite terminal multiplexer.

## Overview

This config uses the [gcp/storage](/deployment/modules/gcp/conformance) module to
define a test environment to run the SCTFE, backed by Trillian Tessera.

At a high level, this environment consists of:
- One Spanner instance with two databases:
  - one for Tessera
  - one for deduplication
- A GCS Bucket

## Manual deployment 

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
### With fake chains

On the VM, run the following command to bring up the SCTFE:
```bash
go run ./cmd/gcp/ --project_id=${GOOGLE_PROJECT} --bucket=${GOOGLE_PROJECT}-${TESSERA_BASE_NAME}-bucket --spanner_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-db --spanner_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-dedup-db --private_key=./testdata/ct-http-server.privkey.pem  --password=dirk --roots_pem_file=./testdata/fake-ca.cert --origin=${TESSERA_BASE_NAME}
```

In a different terminal you can either mint and submit certificates manually, or use the hammer tool to do this.

#### Generate chains manually
First, save the SCTFE repo's path:

```bash
export SCTFE_REPO=$(pwd)
```

Clone the [certificate-transparenct-go](https://github.com/google/certificate-transparency-go) repo.
Then, generate a chain manually. The password for the private key is `gently`:

```bash
mkdir -p /tmp/httpschain
openssl genrsa -out /tmp/httpschain/cert.key 2048
openssl req -new -key /tmp/httpschain/cert.key -out /tmp/httpschain/cert.csr -config=${SCTFE_REPO}/testdata/fake-ca.cfg
openssl x509 -req -days 3650 -in /tmp/httpschain/cert.csr -CAkey ${SCTFE_REPO}/testdata/fake-ca.privkey.pem -CA  ${SCTFE_REPO}/testdata/fake-ca.cert -outform pem -out /tmp/httpschain/chain.pem -provider legacy -provider default
cat ${SCTFE_REPO}/testdata/fake-ca.cert >> /tmp/httpschain/chain.pem
```

Finally, submit the chain to the SCTFE:

```bash
go run ./client/ctclient upload --cert_chain=/tmp/httpschain/chain.pem --skip_https_verify --log_uri=http://localhost:6962/${TESSERA_BASE_NAME}
```

#### Automatically generate chains
Save the SCTFE repo's path:

```bash
export SCTFE_REPO=$(pwd)
```

Clone the [certificate-transparenct-go](https://github.com/google/certificate-transparency-go) repo, and from there run:

```bash
go run ./trillian/integration/ct_hammer/ --ct_http_servers=localhost:6962/${TESSERA_BASE_NAME} --max_retry=2m --invalid_chance=0 --get_sth=0 --get_sth_consistency=0 --get_proof_by_hash=0 --get_entries=0 --get_roots=0 --get_entry_and_proof=0 --max_parallel_chains=4 --skip_https_verify=true --operations=10000 --rate_limit=150 --log_config=${SCTFE_REPO}/testdata/hammer.cfg --testdata_dir=./trillian/testdata/
```

