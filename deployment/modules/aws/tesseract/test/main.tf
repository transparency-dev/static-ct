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

# [WARNING]
# Using secrets manager does NOT guarantee the security of the signing keys. 
# There are significant security risks if the secrets are mismanaged.
module "secretsmanager" {
  source = "../../secretsmanager"

  base_name = var.base_name
  region    = var.region
}
