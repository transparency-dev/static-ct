output "log_bucket" {
  description = "Log GCS bucket"
  value       = google_storage_bucket.log_bucket
}

output "log_spanner_db" {
  description = "Log Spanner database"
  value       = google_spanner_database.log_db
}

output "log_spanner_instance" {
  description = "Log Spanner instance"
  value       = google_spanner_instance.log_spanner
}

output "dedup_spanner_db" {
  description = "Dedup Spanner database"
  value       = google_spanner_database.dedup_db
}

output "kms_key" {
  description = "KMS asymmetric sign key (P256_SHA256)"
  value       = google_kms_crypto_key.sctfe-asymmetric-sign-key-p256-sha256
}
