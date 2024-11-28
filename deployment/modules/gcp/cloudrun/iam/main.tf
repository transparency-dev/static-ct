resource "google_service_account" "cloudrun_service_account" {
  account_id   = var.cloudrun_service_account_id
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
