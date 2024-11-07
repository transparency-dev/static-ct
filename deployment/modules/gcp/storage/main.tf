terraform {
  backend "gcs" {}

  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = "6.1.0"
    }
  }
}

# TODO(phboneff): import tessera terraform directly
# Services
resource "google_project_service" "serviceusage_googleapis_com" {
  service            = "serviceusage.googleapis.com"
  disable_on_destroy = false
}
resource "google_project_service" "storage_api_googleapis_com" {
  service            = "storage-api.googleapis.com"
  disable_on_destroy = false
}
resource "google_project_service" "storage_component_googleapis_com" {
  service            = "storage-component.googleapis.com"
  disable_on_destroy = false
}
resource "google_project_service" "storage_googleapis_com" {
  service            = "storage.googleapis.com"
  disable_on_destroy = false
}

## Resources

# Buckets

resource "google_storage_bucket" "log_bucket" {
  name                        = "${var.project_id}-${var.base_name}-bucket"
  location                    = var.location
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
}

# Spanner

resource "google_spanner_instance" "log_spanner" {
  name             = var.base_name
  config           = "regional-${var.location}"
  display_name     = var.base_name
  processing_units = 100
}

resource "google_spanner_database" "log_db" {
  instance = google_spanner_instance.log_spanner.name
  name     = "${var.base_name}-db"
  ddl = [
    "CREATE TABLE SeqCoord (id INT64 NOT NULL, next INT64 NOT NULL,) PRIMARY KEY (id)",
    "CREATE TABLE Seq (id INT64 NOT NULL, seq INT64 NOT NULL, v BYTES(MAX),) PRIMARY KEY (id, seq)",
    "CREATE TABLE IntCoord (id INT64 NOT NULL, seq INT64 NOT NULL,) PRIMARY KEY (id)",
  ]
}

resource "google_spanner_database" "dedup_db" {
  instance = google_spanner_instance.log_spanner.name
  name     = "${var.base_name}-dedup-db"
  ddl = [
    "CREATE TABLE IDSeq (id INT64 NOT NULL, h BYTES(MAX) NOT NULL, idx INT64 NOT NULL,) PRIMARY KEY (id, h)",
  ]
}

# Secret Manager

# ECDSA key with P256 elliptic curve
resource "tls_private_key" "sctfe-ecdsa-p256" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "google_secret_manager_secret" "sctfe-ecdsa-p256-public-key" {
  secret_id = "sctfe-ecdsa-p256-public-key"

  labels = {
    label = "sctfe-public-key"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "sctfe-ecdsa-p256-public-key" {
  secret = google_secret_manager_secret.sctfe-ecdsa-p256-public-key.id

  secret_data = tls_private_key.sctfe-ecdsa-p256.public_key_pem
}

resource "google_secret_manager_secret" "sctfe-ecdsa-p256-private-key" {
  secret_id = "sctfe-ecdsa-p256-private-key"

  labels = {
    label = "sctfe-private-key"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "sctfe-ecdsa-p256-private-key" {
  secret = google_secret_manager_secret.sctfe-ecdsa-p256-private-key.id

  secret_data = tls_private_key.sctfe-ecdsa-p256.private_key_pem
}
