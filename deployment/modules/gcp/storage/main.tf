terraform {
  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = "6.12.0"
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

  force_destroy = var.ephemeral
}

# Spanner

resource "google_spanner_instance" "log_spanner" {
  name                         = var.base_name
  config                       = "regional-${var.location}"
  display_name                 = var.base_name
  processing_units             = var.spanner_pu
  default_backup_schedule_type = "NONE"

  force_destroy = var.ephemeral
}

resource "google_spanner_database" "log_db" {
  instance = google_spanner_instance.log_spanner.name
  name     = "${var.base_name}-db"
  ddl = [
    "CREATE TABLE IF NOT EXISTS Tessera (id INT64 NOT NULL, compatibilityVersion INT64 NOT NULL) PRIMARY KEY (id)",
    "CREATE TABLE IF NOT EXISTS SeqCoord (id INT64 NOT NULL, next INT64 NOT NULL,) PRIMARY KEY (id)",
    "CREATE TABLE IF NOT EXISTS Seq (id INT64 NOT NULL, seq INT64 NOT NULL, v BYTES(MAX),) PRIMARY KEY (id, seq)",
    "CREATE TABLE IF NOT EXISTS IntCoord (id INT64 NOT NULL, seq INT64 NOT NULL, rootHash BYTES(32)) PRIMARY KEY (id)",
  ]

  deletion_protection = !var.ephemeral
}

resource "google_spanner_database" "dedup_db" {
  instance = google_spanner_instance.log_spanner.name
  name     = "${var.base_name}-dedup-db"
  ddl = [
    "CREATE TABLE IDSeq (id INT64 NOT NULL, h BYTES(MAX) NOT NULL, idx INT64 NOT NULL, timestamp INT64 NOT NULL,) PRIMARY KEY (id, h)",
  ]

  deletion_protection = !var.ephemeral
}
