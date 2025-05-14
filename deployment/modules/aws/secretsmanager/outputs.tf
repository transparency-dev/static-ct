output "ecdsa_p256_public_key_id" {
  description = "Signer public key (P256_SHA256)"
  value       = aws_secretsmanager_secret.tesseract_ecdsa_p256_public_key.name
}

output "ecdsa_p256_public_key_data" {
  description = "Signer public key (P256_SHA256) data from secret manager"
  value       = aws_secretsmanager_secret_version.tesseract_ecdsa_p256_public_key.secret_string
  sensitive   = true
}

output "ecdsa_p256_private_key_id" {
  description = "Signer private key (P256_SHA256)"
  value       = aws_secretsmanager_secret.tesseract_ecdsa_p256_private_key.name
}
