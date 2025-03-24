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
