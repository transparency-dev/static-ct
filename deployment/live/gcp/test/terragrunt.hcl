terraform {
  source = "${get_repo_root()}/deployment/modules/gcp//test"
}

locals {
  env        = "test"
  base_name  = get_env("TESSERA_BASE_NAME", "${local.env}-static-ct")
}

include "root" {
  path   = find_in_parent_folders()
  expose = true
}

inputs = merge(
  local,
  include.root.locals,
)
