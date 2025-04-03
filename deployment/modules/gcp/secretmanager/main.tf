terraform {
  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = "6.28.0"
    }
  }
}

# Secret Manager

resource "google_project_service" "secretmanager_googleapis_com" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_secret_manager_secret" "sctfe_ecdsa_p256_public_key" {
  secret_id = "${var.base_name}-ecdsa-p256-public-key"

  labels = {
    label = "sctfe-public-key"
  }

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager_googleapis_com]
}

resource "google_secret_manager_secret_version" "sctfe_ecdsa_p256_public_key" {
  secret = google_secret_manager_secret.sctfe_ecdsa_p256_public_key.id

  secret_data = var.tls_private_key_ecdsa_p256_public_key_pem
}

resource "google_secret_manager_secret" "sctfe_ecdsa_p256_private_key" {
  secret_id = "${var.base_name}-ecdsa-p256-private-key"

  labels = {
    label = "sctfe-private-key"
  }

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager_googleapis_com]
}

resource "google_secret_manager_secret_version" "sctfe_ecdsa_p256_private_key" {
  secret                 = google_secret_manager_secret.sctfe_ecdsa_p256_private_key.id
  secret_data_wo_version = 1
  secret_data_wo         = var.tls_private_key_ecdsa_p256_private_key_pem
}
