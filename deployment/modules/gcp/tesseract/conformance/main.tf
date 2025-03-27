terraform {
  backend "gcs" {}
}

module "storage" {
  source = "../../storage"

  project_id = var.project_id
  base_name  = var.base_name
  location   = var.location
  ephemeral  = true
}

# [WARNING]
# Using secret manager does NOT guarantee the security of the signing keys. 
# There are significant security risks if the secrets are mismanaged.
module "secretmanager" {
  source = "../../secretmanager"

  base_name = var.base_name
}

module "cloudrun" {
  source = "../../cloudrun"

  env                            = var.env
  project_id                     = var.project_id
  base_name                      = var.base_name
  origin_suffix                  = var.origin_suffix
  location                       = var.location
  server_docker_image            = var.server_docker_image
  bucket                         = module.storage.log_bucket.id
  log_spanner_instance           = module.storage.log_spanner_instance.name
  log_spanner_db                 = module.storage.log_spanner_db.name
  dedup_spanner_db               = module.storage.dedup_spanner_db.name
  signer_public_key_secret_name  = module.secretmanager.ecdsa_p256_public_key_id
  signer_private_key_secret_name = module.secretmanager.ecdsa_p256_private_key_id

  depends_on = [
    module.secretmanager,
    module.storage
  ]
}
