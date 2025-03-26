terraform {
  backend "gcs" {}
}

module "storage" {
  source = "../../storage"

  project_id = var.project_id
  base_name  = var.base_name
  location   = var.location
  ephemeral  = false
}

module "secretmanager" {
  source = "../../secretmanager"

  base_name                                  = var.base_name
  tls_private_key_ecdsa_p256_public_key_pem  = module.insecuretlskey.tls_private_key_ecdsa_p256_public_key_pem
  tls_private_key_ecdsa_p256_private_key_pem = module.insecuretlskey.tls_private_key_ecdsa_p256_private_key_pem
}

# [WARNING]
# This module will hardcode unencrypted private keys in the Terraform state file.
# DO NOT use this for production logs.
module "insecuretlskey" {
  source = "../../insecuretlskey"
}
