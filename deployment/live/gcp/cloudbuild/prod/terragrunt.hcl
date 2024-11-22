terraform {
  source = "${get_repo_root()}/deployment/modules/gcp//cloudbuild"
}

locals {
  docker_env = "ci"
  server_docker_image = "${include.root.locals.location}-docker.pkg.dev/${include.root.locals.project_id}/docker-${local.docker_env}/conformance-gcp:latest"
}

include "root" {
  path   = find_in_parent_folders()
  expose = true
}

inputs = merge(
  local,
  include.root.locals,
)
