variable "project_id" {
  description = "GCP project ID where the log is hosted"
  type        = string
}

variable "env" {
  description = "Unique identifier for the env, e.g. dev or ci or prod"
  type        = string
}

variable "cloudrun_service_account_id" {
  description = "The Clour Run service account ID to be created"
  type        = string
}

variable "bucket" {
  description = "Log GCS bucket"
  type        = string
}

variable "log_spanner_instance" {
  description = "Log Spanner instance"
  type        = string
}

variable "log_spanner_db" {
  description = "Log Spanner database"
  type        = string
}

variable "dedup_spanner_db" {
  description = "Dedup Spanner database"
  type        = string
}
