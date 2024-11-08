# GCP SCTFE Configs

## Prerequisites
You'll need to have a VM running in the same GCP project that you can SSH to,
with [Go](https://go.dev/doc/install) and 
[terragrunt](https://terragrunt.gruntwork.io/docs/getting-started/install/) 
installed, and your favourite terminal multiplexer.

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
go run ./cmd/gcp/ \
  --project_id=${GOOGLE_PROJECT} \
  --bucket=${GOOGLE_PROJECT}-${TESSERA_BASE_NAME}-bucket \
  --spanner_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-db \
  --spanner_dedup_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-dedup-db \
  --private_key=./testdata/ct-http-server.privkey.pem \
  --password=dirk \
  --roots_pem_file=./testdata/fake-ca.cert \
  --origin=${TESSERA_BASE_NAME}
```

In a different terminal you can either mint and submit certificates manually, or
use the [ct_hammer
tool](https://github.com/google/certificate-transparency-go/blob/master/trillian/integration/ct_hammer/main.go)
to do this.

#### Generate chains manually

Generate a chain manually. The password for the private key is `gently`:

```bash
mkdir -p /tmp/httpschain
openssl genrsa -out /tmp/httpschain/cert.key 2048
openssl req -new -key /tmp/httpschain/cert.key -out /tmp/httpschain/cert.csr -config=testdata/fake-ca.cfg
openssl x509 -req -days 3650 -in /tmp/httpschain/cert.csr -CAkey testdata/fake-ca.privkey.pem -CA testdata/fake-ca.cert -outform pem -out /tmp/httpschain/chain.pem -provider legacy -provider default
cat testdata/fake-ca.cert >> /tmp/httpschain/chain.pem
```

Finally, submit the chain to the SCTFE:

```bash
go run github.com/google/certificate-transparency-go/client/ctclient@master upload --cert_chain=/tmp/httpschain/chain.pem --skip_https_verify --log_uri=http://localhost:6962/${TESSERA_BASE_NAME}
```

#### Automatically generate chains

Save the SCTFE repo's path:

```bash
export SCTFE_REPO=$(pwd)
```

Clone the [certificate-transparency-go](https://github.com/google/certificate-transparency-go) repo, and from there run:

```bash
go run ./trillian/integration/ct_hammer/ \
  --ct_http_servers=localhost:6962/${TESSERA_BASE_NAME} \
  --max_retry=2m \
  --invalid_chance=0 \
  --get_sth=0 \
  --get_sth_consistency=0 \
  --get_proof_by_hash=0 \
  --get_entries=0 \
  --get_roots=0 \
  --get_entry_and_proof=0 \
  --max_parallel_chains=4 \
  --skip_https_verify=true \
  --operations=10000 \
  --rate_limit=150 \
  --log_config=${SCTFE_REPO}/testdata/hammer.cfg \
  --testdata_dir=./trillian/testdata/
```

### With real HTTPS certificates

We'll run a SCTFE and copy certificates from an existing RFC6962 log to it.
It uses the [ct_hammer tool from certificate-transparency-go](https://github.com/google/certificate-transparency-go/tree/aceb1d4481907b00c087020a3930c7bd691a0110/trillian/integration/ct_hammer).

First, set a few environment variables:

```bash
export SCTFE_REPO=$(pwd)
export SRC_LOG_URI=https://ct.googleapis.com/logs/xenon2022
```

Then, get fetch the roots the source logs accepts, and edit configs accordingly.
To do so, clone the [certificate-transparency-go](https://github.com/google/certificate-transparency-go) repo, and from there run:

```bash
export CTGO_REPO=$(pwd)
mkdir -p /tmp/hammercfg
cp ${SCTFE_REPO}/testdata/hammer.cfg /tmp/hammercfg
go run ./client/ctclient get-roots --log_uri=${SRC_LOG_URI} --text=false > /tmp/hammercfg/roots.pem
sed -i 's-""-"/tmp/hammercfg/roots.pem"-g' /tmp/hammercfg/hammer.cfg
```


Run the SCTFE with the same roots:

```bash
cd ${SCTFE_REPO}
go run ./cmd/gcp/ \
  --project_id=${GOOGLE_PROJECT} \
  --bucket=${GOOGLE_PROJECT}-${TESSERA_BASE_NAME}-bucket \
  --spanner_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-db \
  --private_key=./testdata/ct-http-server.privkey.pem \
  --password=dirk \
  --roots_pem_file=/tmp/hammercfg/roots.pem \
  --origin=${TESSERA_BASE_NAME} \
  --spanner_dedup_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-dedup-db \
  -v=3
```

Run `ct_hammer` in a different terminal:

```bash
cd ${CTGO_REPO}
go run ./trillian/integration/ct_hammer/ \
  --ct_http_servers=localhost:6962/${TESSERA_BASE_NAME} \
  --max_retry=2m \
  --invalid_chance=0 \
  --get_sth=0 \
  --get_sth_consistency=0 \
  --get_proof_by_hash=0 \
  --get_entries=0 \
  --get_roots=0 \
  --get_entry_and_proof=0 \
  --max_parallel_chains=4 \
  --skip_https_verify=true \
  --operations=10000 \
  --rate_limit=150 \
  --log_config=/tmp/hammercfg/hammer.cfg \
  --src_log_uri=${SRC_LOG_URI}
```
