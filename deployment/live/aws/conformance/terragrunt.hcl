locals {
  env                        = path_relative_to_include()
  account_id                 = "${get_aws_account_id()}"
  region                     = get_env("AWS_REGION", "us-east-1")
  base_name                  = get_env("TESSERA_BASE_NAME", "conformance")
  origin_suffix              = get_env("TESSERA_ORIGIN_SUFFIX", "")
  prefix_name                = get_env("TESSERA_PREFIX_NAME", "static-ct-${local.env}")
  ecr_registry               = get_env("ECR_REGISTRY", "${local.account_id}.dkr.ecr.${local.region}.amazonaws.com")
  ecr_repository_conformance = get_env("ECR_REPOSITORY_CONFORMANCE", "static-ct-${local.env}/conformance:latest")
  ecr_repository_hammer      = get_env("ECR_REPOSITORY_HAMMER", "static-ct-${local.env}/hammer:latest")
  ecs_execution_role         = get_env("ECS_EXECUTION_ROLE")
  ecs_conformance_task_role  = get_env("ECS_CONFORMANCE_TASK_ROLE")
  ephemeral                  = true
}

remote_state {
  backend = "s3"

  config = {
    region = local.region
    bucket = "${local.prefix_name}-${local.base_name}-terraform-state"
    key    = "terraform.tfstate"
    s3_bucket_tags = {
      name = "terraform_state_storage"
    }
    use_lockfile = true
  }
}
