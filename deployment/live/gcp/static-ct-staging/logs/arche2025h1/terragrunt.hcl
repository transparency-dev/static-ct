terraform {
  source = "${get_repo_root()}/deployment/modules/gcp//tesseract/conformance"
}

locals {
  env                 = include.root.locals.env
  docker_env          = local.env
  base_name           = include.root.locals.base_name
  origin_suffix       = include.root.locals.origin_suffix
  server_docker_image = "us-central1-docker.pkg.dev/${include.root.locals.project_id}/docker-${local.env}/conformance-gcp:latest"
}

include "root" {
  path   = find_in_parent_folders()
  expose = true
}

inputs = merge(
  local,
  include.root.locals,
)
