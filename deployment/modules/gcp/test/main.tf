terraform {
  backend "gcs" {}
}

module "storage" {
  source = "../storage"

  project_id = var.project_id
  base_name  = var.base_name
  location   = var.location
}

module "secretmanager" {
  source = "../secretmanager"

  base_name = var.base_name
}
