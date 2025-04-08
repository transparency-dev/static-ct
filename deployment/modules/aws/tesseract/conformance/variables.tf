variable "prefix_name" {
  description = "Common prefix to use when naming resources, ensures unicity of the s3 bucket name."
  type        = string
}

variable "base_name" {
  description = "Base name to use when naming resources"
  type        = string
}

variable "region" {
  description = "Region in which to create resources"
  type        = string
}

variable "ephemeral" {
  description = "Set to true if this is a throwaway/temporary log instance. Will set attributes on created resources to allow them to be disabled/deleted more easily."
  type        = bool
}

variable "ecr_registry" {
  description = "Container registry address, with the conformance and hammer repositories."
  type        = string
}

variable "ecr_repository_conformance" {
  description = "Container repository for the conformance binary, with the tag."
  type        = string
}

variable "ecr_repository_hammer" {
  description = "Container repository for the hammer binary, with the tag."
  type        = string
}

variable "ecs_execution_role" {
  description = "Role used to run the ECS task."
  type        = string
}

variable "ecs_conformance_task_role" {
  description = "Role assumed by conformance containers when they run."
  type        = string
}
