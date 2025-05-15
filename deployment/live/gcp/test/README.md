# GCP TesseraCT Test Environment

## Prerequisites
You'll need to have a VM running in the same GCP project that you can SSH to,
with [Go](https://go.dev/doc/install) and 
[terragrunt](https://terragrunt.gruntwork.io/docs/getting-started/install/) 
installed, and your favourite terminal multiplexer.

## Overview

This config uses the [gcp/test](/deployment/modules/gcp/test) module to
define a test environment to run TesseraCT, backed by Trillian Tessera.

At a high level, this environment consists of:
- One Spanner instance with two databases:
  - one for Tessera
  - one for antispam
- A GCS Bucket
- Secret Manager

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
export TESSERA_BASE_NAME={VALUE} # e.g: test-static-ct
```

Terraforming the project can be done by:
  1. `cd` to the relevant directory for the environment to deploy/change (e.g. `ci`)
  2. Run `terragrunt apply`

Store the Secret Manager resource ID of signer key pair into the environment variables:

```sh
export TESSERACT_SIGNER_ECDSA_P256_PUBLIC_KEY_ID=$(terragrunt output -raw ecdsa_p256_public_key_id)
export TESSERACT_SIGNER_ECDSA_P256_PRIVATE_KEY_ID=$(terragrunt output -raw ecdsa_p256_private_key_id)
```

## Run TesseraCT

### With fake chains

On the VM, run the following command to bring up TesseraCT:

```bash
go run ./cmd/gcp/ \
  --bucket=${GOOGLE_PROJECT}-${TESSERA_BASE_NAME}-bucket \
  --spanner_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-db \
  --spanner_antispam_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-antispam-db \
  --roots_pem_file=./internal/testdata/fake-ca.cert \
  --origin=${TESSERA_BASE_NAME} \
  --signer_public_key_secret_name=${TESSERACT_SIGNER_ECDSA_P256_PUBLIC_KEY_ID} \
  --signer_private_key_secret_name=${TESSERACT_SIGNER_ECDSA_P256_PRIVATE_KEY_ID}
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
openssl req -new -key /tmp/httpschain/cert.key -out /tmp/httpschain/cert.csr -config=internal/testdata/fake-ca.cfg
openssl x509 -req -days 3650 -in /tmp/httpschain/cert.csr -CAkey internal/testdata/fake-ca.privkey.pem -CA internal/testdata/fake-ca.cert -outform pem -out /tmp/httpschain/chain.pem -provider legacy -provider default
cat internal/testdata/fake-ca.cert >> /tmp/httpschain/chain.pem
```

Finally, submit the chain to TesseraCT:

```bash
go run github.com/google/certificate-transparency-go/client/ctclient@master upload --cert_chain=/tmp/httpschain/chain.pem --skip_https_verify --log_uri=http://localhost:6962/${TESSERA_BASE_NAME}
```

#### Automatically generate chains

Save TesseraCT repo's path:

```bash
export TESSERACT_REPO=$(pwd)
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
  --log_config=${TESSERACT_REPO}/internal/testdata/hammer.cfg \
  --testdata_dir=./trillian/testdata/
```

### With real HTTPS certificates

We'll run a TESSERACT and copy certificates from an existing RFC6962 log to it.
It uses the [ct_hammer tool from certificate-transparency-go](https://github.com/google/certificate-transparency-go/tree/aceb1d4481907b00c087020a3930c7bd691a0110/trillian/integration/ct_hammer).

First, set a few environment variables:

```bash
export TESSERACT_REPO=$(pwd)
export SRC_LOG_URI=https://ct.googleapis.com/logs/xenon2022
```

Then, get fetch the roots the source logs accepts, and edit configs accordingly.
To do so, clone the [certificate-transparency-go](https://github.com/google/certificate-transparency-go) repo, and from there run:

```bash
export CTGO_REPO=$(pwd)
mkdir -p /tmp/hammercfg
cp ${TESSERACT_REPO}/internal/testdata/hammer.cfg /tmp/hammercfg
go run ./client/ctclient get-roots --log_uri=${SRC_LOG_URI} --text=false > /tmp/hammercfg/roots.pem
sed -i 's-""-"/tmp/hammercfg/roots.pem"-g' /tmp/hammercfg/hammer.cfg
```

Run TesseraCT with the same roots:

```bash
cd ${TESSERACT_REPO}
go run ./cmd/gcp/ \
  --bucket=${GOOGLE_PROJECT}-${TESSERA_BASE_NAME}-bucket \
  --spanner_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-db \
  --roots_pem_file=/tmp/hammercfg/roots.pem \
  --origin=${TESSERA_BASE_NAME} \
  --spanner_antispam_db_path=projects/${GOOGLE_PROJECT}/instances/${TESSERA_BASE_NAME}/databases/${TESSERA_BASE_NAME}-antispam-db \
  --signer_public_key_secret_name=${TESSERACT_SIGNER_ECDSA_P256_PUBLIC_KEY_ID} \
  --signer_private_key_secret_name=${TESSERACT_SIGNER_ECDSA_P256_PRIVATE_KEY_ID} \
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
