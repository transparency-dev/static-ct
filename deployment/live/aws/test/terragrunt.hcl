terraform {
  source = "${get_repo_root()}/deployment/modules/aws//tesseract/test"
}

locals {
  env       = "test"
  base_name = get_env("TESSERA_BASE_NAME", "${local.env}-static-ct")
  ephemeral = true
}

include "root" {
  path   = find_in_parent_folders("root.hcl")
  expose = true
}

inputs = merge(
  local,
  include.root.locals,
)
