variable "base_name" {
  description = "Base name to use when naming resources"
  type        = string
}

variable "tls_private_key_ecdsa_p256_public_key_pem" {
  description = "Public ECDSA key with P256 elliptic curve in PEM format."
  type        = string
  sensitive   = true
}

variable "tls_private_key_ecdsa_p256_private_key_pem" {
  description = "Private ECDSA key with P256 elliptic curve in PEM format."
  type        = string
  sensitive   = true
}
