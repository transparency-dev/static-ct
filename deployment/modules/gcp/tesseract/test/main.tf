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

# [WARNING]
# Using secret manager does NOT guarantee the security of the signing keys. 
# There are significant security risks if the secrets are mismanaged.
module "secretmanager" {
  source = "../../secretmanager"

  base_name = var.base_name
}
