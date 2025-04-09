terraform {
  source = "${get_repo_root()}/deployment/modules/gcp//tesseract/cloudrun"
}

locals {
  env                 = include.root.locals.env
  docker_env          = local.env
  base_name           = include.root.locals.base_name
  origin_suffix       = include.root.locals.origin_suffix
  server_docker_image = "${include.root.locals.location}-docker.pkg.dev/${include.root.locals.project_id}/docker-${local.env}/tesseract-gcp:${include.root.locals.docker_container_tag}"
  spanner_pu          = 500
}

include "root" {
  path   = find_in_parent_folders()
  expose = true
}

inputs = merge(
  local,
  include.root.locals,
)
