terraform {
  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = "6.12.0"
    }
  }
}

# Cloud Run

locals {
  cloudrun_service_account_id = var.env == "" ? "cloudrun-sa" : "cloudrun-${var.env}-sa"
  spanner_log_db_path         = "projects/${var.project_id}/instances/${var.log_spanner_instance}/databases/${var.log_spanner_db}"
  spanner_dedup_db_path       = "projects/${var.project_id}/instances/${var.log_spanner_instance}/databases/${var.dedup_spanner_db}"
}

resource "google_project_service" "cloudrun_api" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_cloud_run_v2_service" "default" {
  name         = var.base_name
  location     = var.location
  launch_stage = "GA"

  template {
    service_account                  = "${local.cloudrun_service_account_id}@${var.project_id}.iam.gserviceaccount.com"
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
        "--bucket=${var.bucket}",
        "--spanner_db_path=${local.spanner_log_db_path}",
        "--spanner_dedup_db_path=${local.spanner_dedup_db_path}",
        "--roots_pem_file=/bin/test_root_ca_cert.pem",
        "--origin=${var.base_name}${var.origin_suffix}",
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
    containers {
      image      = "us-docker.pkg.dev/cloud-ops-agents-artifacts/cloud-run-gmp-sidecar/cloud-run-gmp-sidecar:1.2.0"
      name       = "collector"
      depends_on = ["conformance"]
    }
  }

  deletion_protection = false

  client = "terraform"

  depends_on = [
    google_project_service.cloudrun_api,
  ]
}
