terraform {
  backend "gcs" {}

  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = "6.12.0"
    }
  }
}

# Cloud Build

locals {
  cloudbuild_service_account   = "cloudbuild-${var.env}-sa@${var.project_id}.iam.gserviceaccount.com"
  scheduler_service_account    = "scheduler-${var.env}-sa@${var.project_id}.iam.gserviceaccount.com"
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

resource "google_cloudbuild_trigger" "preloader_trigger" {
  name            = "preloader-${var.env}"
  service_account = "projects/${var.project_id}/serviceAccounts/${local.cloudbuild_service_account}"
  location        = var.location

  # TODO(phboneff): use a better mechanism to trigger releases that re-uses Docker containters, or based on branches rather.
  # This is a temporary mechanism to speed up development.
  github {
    owner = var.github_owner
    name  = "static-ct"
    push {
      tag = "^staging-deploy-(.+)$"
    }
  }

  build {
    ## Since TesseraCT's infrastructure is not publicly accessible, we need to use 
    ## bearer tokens for the test to access them.
    ## This step creates those, and stores them for later use.
    step {
      id       = "bearer_token"
      name     = "gcr.io/cloud-builders/gcloud"
      script   = <<EOT
        gcloud auth print-access-token --lifetime=4200 > /workspace/cb_access
        curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/${local.cloudbuild_service_account}/identity?audience=${var.submission_url}" > /workspace/cb_identity
      EOT
    }

    ## TODO(phboneff): move to its own container / cloudrun / batch job.
    ## Preload entries.
    ## Leave enough time for the preloader to run, until the token expires.
    timeout = "4200s" // 60 minutes
    step {
      id       = "ct_preloader"
      name     = "golang"
      script   = <<EOT
	      START_INDEX=$(curl -H "Authorization: Bearer $(cat /workspace/cb_access)" https://storage.googleapis.com/${var.monitoring_url}/checkpoint | head -2 | tail -1)
	      echo "Will start preloader at index $START_INDEX"
        go run github.com/google/certificate-transparency-go/preload/preloader@master \
          --target_log_uri=${var.submission_url}/ \
	        --target_bearer_token="$(cat /workspace/cb_identity)" \
          --source_log_uri=https://ct.googleapis.com/logs/us1/argon2025h1 \
	        --start_index=$START_INDEX \
          --num_workers=20 \
          --parallel_fetch=20 \
          --parallel_submit=20
      EOT
      wait_for = ["bearer_token"]
      timeout = "3600s" // 60 minutes, duration of token validity.
    }

    options {
      logging      = "CLOUD_LOGGING_ONLY"
      machine_type = "E2_HIGHCPU_8"
    }
  }
}

resource "google_cloud_scheduler_job" "deploy_cron" {
  paused = false
  project = var.project_id
  region  = var.location
  name    = "deploy-cron"

  schedule  = "50 * * * *"
  time_zone = "America/Los_Angeles"

  attempt_deadline = "120s"

  // TODO(phboneff): use a batch job instead maybe
  http_target {
    http_method = "POST"
    uri         = "https://cloudbuild.googleapis.com/v1/projects/${var.project_id}/locations/${var.location}/triggers/${google_cloudbuild_trigger.preloader_trigger.trigger_id}:run"
    body        = base64encode(jsonencode({
      source = {
        branchName = "preloader"
      }
    }))
    headers = {
      "Content-Type" = "application/json"
    }

    oauth_token {
      service_account_email = local.scheduler_service_account
    }
  }
}
