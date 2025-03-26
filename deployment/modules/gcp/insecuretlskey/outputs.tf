output "tls_private_key_ecdsa_p256_public_key_pem" {
  value     = tls_private_key.ecdsa_p256.public_key_pem
  sensitive = true
}

output "tls_private_key_ecdsa_p256_private_key_pem" {
  value     = tls_private_key.ecdsa_p256.private_key_pem
  sensitive = true
}
