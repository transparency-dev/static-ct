terraform {
  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = "6.1.0"
    }
  }
}

# Cloud Run

resource "google_project_service" "cloudrun_api" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_service_account" "cloudrun_service_account" {
  account_id   = "cloudrun-${var.env}-sa"
  display_name = "Service Account for Cloud Run (${var.env})"
}

resource "google_project_iam_member" "run_service_agent" {
  project = var.project_id
  role    = "roles/run.serviceAgent"
  member  = "serviceAccount:${google_service_account.cloudrun_service_account.email}"
}

resource "google_project_iam_member" "monitoring_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.cloudrun_service_account.email}"
}

resource "google_storage_bucket_iam_member" "member" {
  bucket = var.bucket
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.cloudrun_service_account.email}"
}

resource "google_project_iam_member" "iam_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.cloudrun_service_account.email}"
}

resource "google_spanner_database_iam_member" "iam_log_spanner_database_user" {
  instance = var.log_spanner_instance
  database = var.log_spanner_db
  role     = "roles/spanner.databaseUser"
  member   = "serviceAccount:${google_service_account.cloudrun_service_account.email}"
}

resource "google_spanner_database_iam_member" "iam_dedup_spanner_database_user" {
  instance = var.log_spanner_instance
  database = var.dedup_spanner_db
  role     = "roles/spanner.databaseUser"
  member   = "serviceAccount:${google_service_account.cloudrun_service_account.email}"
}

locals {
  spanner_log_db_path   = "projects/${var.project_id}/instances/${var.log_spanner_instance}/databases/${var.log_spanner_db}"
  spanner_dedup_db_path = "projects/${var.project_id}/instances/${var.log_spanner_instance}/databases/${var.dedup_spanner_db}"
}

resource "google_cloud_run_v2_service" "default" {
  name         = var.base_name
  location     = var.location
  launch_stage = "GA"

  template {
    service_account                  = google_service_account.cloudrun_service_account.account_id
    max_instance_request_concurrency = 700
    timeout                          = "5s"

    scaling {
      max_instance_count = 3
    }

    containers {
      image = var.server_docker_image
      name  = "conformance"
      args = [
        "--logtostderr",
        "--v=1",
        "--http_endpoint=:6962",
        "--project_id=${var.project_id}",
        "--bucket=${var.bucket}",
        "--spanner_db_path=${local.spanner_log_db_path}",
        "--spanner_dedup_db_path=${local.spanner_dedup_db_path}",
        "--roots_pem_file=/bin/fake-ca.cert",
        "--origin=${var.base_name}",
        "--signer_public_key_secret_name=${var.signer_public_key_secret_name}",
        "--signer_private_key_secret_name=${var.signer_private_key_secret_name}",
      ]
      ports {
        container_port = 6962
      }

      resources {
        limits = {
          cpu    = "2000m"
          memory = "1Gi"
        }
      }

      startup_probe {
        initial_delay_seconds = 1
        timeout_seconds       = 1
        period_seconds        = 10
        failure_threshold     = 6
        tcp_socket {
          port = 6962
        }
      }
    }
  }

  deletion_protection = false

  client = "terraform"

  depends_on = [
    google_project_service.cloudrun_api,
  ]
}
