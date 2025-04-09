terraform {
  source = "${get_repo_root()}/deployment/modules/aws//tesseract/conformance"
}

include "root" {
  path   = find_in_parent_folders()
  expose = true
}

inputs = include.root.locals
