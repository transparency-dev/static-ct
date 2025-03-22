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
