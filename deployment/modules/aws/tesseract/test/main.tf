terraform {
  backend "s3" {}
}

module "storage" {
  source = "../../storage"

  prefix_name = var.prefix_name
  base_name   = var.base_name
  region      = var.region
  ephemeral   = var.ephemeral
}

module "secretsmanager" {
  source = "../../secretsmanager"

  base_name                                  = var.base_name
  region                                     = var.region
  tls_private_key_ecdsa_p256_public_key_pem  = module.insecuretlskey.tls_private_key_ecdsa_p256_public_key_pem
  tls_private_key_ecdsa_p256_private_key_pem = module.insecuretlskey.tls_private_key_ecdsa_p256_private_key_pem
}

# [WARNING]
# This module will hardcode unencrypted private keys in the Terraform state file.
# DO NOT use this for production logs.
module "insecuretlskey" {
  source = "../../insecuretlskey"
}
