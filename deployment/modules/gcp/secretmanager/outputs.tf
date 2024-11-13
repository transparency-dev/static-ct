output "ecdsa_p256_public_key_id" {
  description = "Signer public key (P256_SHA256)"
  value       = google_secret_manager_secret_version.sctfe_ecdsa_p256_public_key.id
}

output "ecdsa_p256_private_key_id" {
  description = "Signer private key (P256_SHA256)"
  value       = google_secret_manager_secret_version.sctfe_ecdsa_p256_private_key.id
}
