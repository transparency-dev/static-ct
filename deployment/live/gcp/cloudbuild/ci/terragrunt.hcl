terraform {
  source = "${get_repo_root()}/deployment/modules/gcp//cloudbuild"
}

locals {
  server_docker_image = "${include.root.locals.location}-docker.pkg.dev/${include.root.locals.project_id}/docker-${include.root.locals.env}/conformance-gcp:latest"
}

include "root" {
  path   = find_in_parent_folders()
  expose = true
}

inputs = merge(
  local,
  include.root.locals,
)
