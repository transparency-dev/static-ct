terraform {
  backend "gcs" {}

  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = "6.12.0"
    }
  }
}

# Artifact Registry

module "artifactregistry" {
  source = "../artifactregistry"

  location   = var.location
  docker_env = var.docker_env
}

# Cloud Build

locals {
  cloudbuild_service_account   = "cloudbuild-${var.env}-sa@${var.project_id}.iam.gserviceaccount.com"
  artifact_repo                = "${var.location}-docker.pkg.dev/${var.project_id}/${module.artifactregistry.docker.name}"
  conformance_gcp_docker_image = "${local.artifact_repo}/conformance-gcp"
}

resource "google_project_service" "cloudbuild_api" {
  service            = "cloudbuild.googleapis.com"
  disable_on_destroy = false
}

## Service usage API is required on the project to enable APIs.
## https://cloud.google.com/apis/docs/getting-started#enabling_apis
## serviceusage.googleapis.com acts as a central point for managing the API 
## lifecycle within your project. By ensuring the required APIs are enabled 
## and accessible, it allows Cloud Build to function seamlessly and interact 
## with other Google Cloud services as needed.
## 
## The Cloud Build service account also needs roles/serviceusage.serviceUsageViewer.
resource "google_project_service" "serviceusage_api" {
  service            = "serviceusage.googleapis.com"
  disable_on_destroy = false
}

resource "google_cloudbuild_trigger" "build_trigger" {
  name            = "build-docker-${var.docker_env}"
  service_account = "projects/${var.project_id}/serviceAccounts/${local.cloudbuild_service_account}"
  location        = var.location

  github {
    owner = var.github_owner
    name  = "static-ct"
    push {
      branch = "^main$"
    }
  }

  build {
    ## Destroy any pre-existing deployment/live/gcp/ci environment.
    ## This might happen if a previous cloud build failed for some reason.
    step {
      id     = "preclean_env"
      name   = "alpine/terragrunt"
      script = <<EOT
        terragrunt --terragrunt-non-interactive --terragrunt-no-color destroy -auto-approve -no-color 2>&1
      EOT
      dir    = "deployment/live/gcp/ci"
      env = [
        "GOOGLE_PROJECT=${var.project_id}",
        "TF_IN_AUTOMATION=1",
        "TF_INPUT=false",
        "TF_VAR_project_id=${var.project_id}"
      ]
    }

    ## Build the SCTFE GCP Docker image.
    ## This will be used by the building the conformance Docker image which includes 
    ## the test data.
    step {
      id   = "docker_build_sctfe_gcp"
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "sctfe-gcp:$SHORT_SHA",
        "-t", "sctfe-gcp:latest",
        "-f", "./cmd/gcp/Dockerfile",
        "."
      ]
    }

    ## Build the SCTFE GCP Conformance Docker container image.
    step {
      id   = "docker_build_conformance_gcp"
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "${local.conformance_gcp_docker_image}:$SHORT_SHA",
        "-t", "${local.conformance_gcp_docker_image}:latest",
        "-f", "./cmd/gcp/ci/Dockerfile",
        "."
      ]
      wait_for = ["docker_build_sctfe_gcp"]
    }

    ## Push the conformance Docker container image to Artifact Registry.
    step {
      id   = "docker_push_conformance_gcp"
      name = "gcr.io/cloud-builders/docker"
      args = [
        "push",
        "--all-tags",
        local.conformance_gcp_docker_image
      ]
      wait_for = ["docker_build_conformance_gcp"]
    }

    ## Apply the deployment/live/gcp/ci terragrunt config.
    ## This will bring up the conformance infrastructure, including a service
    ## running the conformance server docker image built above.
    step {
      id     = "terraform_apply_conformance_ci"
      name   = "alpine/terragrunt"
      script = <<EOT
        terragrunt --terragrunt-non-interactive --terragrunt-no-color apply -auto-approve -no-color 2>&1
        terragrunt --terragrunt-no-color output --raw conformance_url -no-color > /workspace/conformance_url
      EOT
      dir    = "deployment/live/gcp/ci"
      env = [
        "GOOGLE_PROJECT=${var.project_id}",
        "TF_IN_AUTOMATION=1",
        "TF_INPUT=false",
        "TF_VAR_project_id=${var.project_id}"
      ]
      wait_for = ["preclean_env", "docker_push_conformance_gcp"]
    }

    ## Since the conformance infrastructure is not publicly accessible, we need to use 
    ## bearer tokens for the test to access them.
    ## This step creates those, and stores them for later use.
    step {
      id       = "bearer_token"
      name     = "gcr.io/cloud-builders/gcloud"
      script   = <<EOT
        curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/${local.cloudbuild_service_account}/identity?audience=$(cat /workspace/conformance_url)" > /workspace/cb_identity
      EOT
      wait_for = ["terraform_apply_conformance_ci"]
    }

    ## Test against the conformance server.
    ## TODO: Replace this with CT Hammer when it is ready.
    step {
      id       = "curl_test"
      name     = "gcr.io/cloud-builders/gcloud"
      script   = <<EOT
        apt update && apt install jq -y
        mkdir -p /tmp/httpschain
        openssl genrsa -out /tmp/httpschain/cert.key 2048
        openssl req -new -key /tmp/httpschain/cert.key -out /tmp/httpschain/cert.csr -config=testdata/fake-ca.cfg
        openssl x509 -req -days 3650 -in /tmp/httpschain/cert.csr -CAkey testdata/fake-ca.privkey.pem -CA testdata/fake-ca.cert -passin pass:"gently" -outform pem -out /tmp/httpschain/chain.pem -provider legacy -provider default
        cat testdata/fake-ca.cert >> /tmp/httpschain/chain.pem
        cat /tmp/httpschain/chain.pem | jq --raw-input --slurp --compact-output 'split("\n-----END CERTIFICATE-----\n") | map(select(length > 0) | sub("^-----BEGIN CERTIFICATE-----\n"; "") | sub("\n-----END CERTIFICATE-----$"; "")) | { "chain": . }' > /tmp/httpschain/chain.json
        curl -s -o >(cat > /tmp/add_chain_response_body) -w "%{http_code}" -X POST --data @/tmp/httpschain/chain.json -H "Content-Type: application/json" -H "Authorization: Bearer $(cat /workspace/cb_identity)" $(cat /workspace/conformance_url)/ci-${var.project_id}/ct/v1/add-chain > /tmp/add_chain_response_code

        cat /tmp/add_chain_response_code
        if ! grep -q 200 /tmp/add_chain_response_code; then
          echo "Error: File does not contain 200 status OK" >&2
          exit 1
        fi

        cat /tmp/add_chain_response_body
      EOT
      wait_for = ["bearer_token"]
    }

    ## Destroy the deployment/live/gcp/ci terragrunt config.
    ## This will tear down the conformance infrastructure we brought up
    ## above.
    step {
      id     = "terraform_destroy_conformance_ci"
      name   = "alpine/terragrunt"
      script = <<EOT
        terragrunt --terragrunt-non-interactive --terragrunt-no-color destroy -auto-approve -no-color 2>&1
      EOT
      dir    = "deployment/live/gcp/ci"
      env = [
        "GOOGLE_PROJECT=${var.project_id}",
        "TF_IN_AUTOMATION=1",
        "TF_INPUT=false",
        "TF_VAR_project_id=${var.project_id}"
      ]
      wait_for = ["curl_test"]
    }

    options {
      logging      = "CLOUD_LOGGING_ONLY"
      machine_type = "E2_HIGHCPU_8"
    }
  }

  depends_on = [
    module.artifactregistry
  ]
}
