terraform {
  source = "${get_repo_root()}/deployment/modules/gcp//conformance"
}

locals {
  project_id = get_env("GOOGLE_PROJECT", "phboneff-dev")
  location   = get_env("GOOGLE_REGION", "us-central1")
  base_name  = get_env("TESSERA_BASE_NAME", "tessera-staticct")
}

inputs = local

remote_state {
  backend = "gcs"

  config = {
    project  = local.project_id
    location = local.location
    bucket   = "${local.project_id}-${local.base_name}-terraform-state"
    prefix   = "terraform.tfstate"

    gcs_bucket_labels = {
      name = "terraform_state_conformance"
    }
  }
}
