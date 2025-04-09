terraform {
  source = "${get_repo_root()}/deployment/modules/gcp//cloudbuild/preloaded"
}

locals {
  env            = get_env("GOOGLE_ENV", "staging")
  docker_env     = get_env("GOOGLE_ENV", "staging")
  project_id     = get_env("GOOGLE_PROJECT", "static-ct-staging")
  location       = get_env("GOOGLE_REGION", "us-central1")
  github_owner   = get_env("GITHUB_OWNER", "transparency-dev")
}

include "root" {
  path   = find_in_parent_folders()
  expose = true
}

inputs = merge(
  local,
  include.root.locals,
)
