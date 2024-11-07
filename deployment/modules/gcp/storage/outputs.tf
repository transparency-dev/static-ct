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

output "ecdsa_p256_public_key_id" {
  description = "Signer public key (P256_SHA256)"
  value       = google_secret_manager_secret_version.sctfe-ecdsa-p256-public-key.id
}

output "ecdsa_p256_private_key_id" {
  description = "Signer private key (P256_SHA256)"
  value       = google_secret_manager_secret_version.sctfe-ecdsa-p256-private-key.id
}
