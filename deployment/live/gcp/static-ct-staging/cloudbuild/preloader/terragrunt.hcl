terraform {
  source = "${get_repo_root()}/deployment/modules/gcp//cloudbuild/preloader"
}

locals {
  env            = get_env("GOOGLE_ENV", "staging")
  docker_env     = get_env("GOOGLE_ENV", "staging")
  project_id     = get_env("GOOGLE_PROJECT", "static-ct-staging")
  location       = get_env("GOOGLE_REGION", "us-central1")
  github_owner   = get_env("GITHUB_OWNER", "transparency-dev")
  source_log_uri = get_env("SOURCE_LOG_URI", "https://ct.googleapis.com/logs/us1/argon2025h1")
  submission_url = get_env("SUBMISSION_URL", "https://arche2025h1-64t3hlisgq-uc.a.run.app/arche2025h1.ct.transparency.dev")
  monitoring_url = get_env("MONITORING_URL", " https://storage.googleapis.com/static-ct-staging-arche2025h1-bucket")
}

inputs = local

remote_state {
  backend = "gcs"

  config = {
    project  = local.project_id
    location = local.location
    bucket   = "${local.project_id}-cloudbuild-preloader-terraform-state"
    prefix   = "terraform.tfstate"

    gcs_bucket_labels = {
      name = "terraform_state"
      env  = "${local.env}"
    }
  }
}
