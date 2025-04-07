variable "project_id" {
  description = "GCP project ID where the log is hosted"
  type        = string
}

variable "base_name" {
  description = "Base name to use when naming resources"
  type        = string
}

variable "origin_suffix" {
  description = "Origin suffix, appended to base_name"
  type        = string
}

variable "location" {
  description = "Location in which to create resources"
  type        = string
}

variable "env" {
  description = "Unique identifier for the env, e.g. dev or ci or prod"
  type        = string
}

variable "docker_env" {
  description = "Unique identifier for the Docker env, e.g. dev or ci or prod"
  type        = string
}

variable "server_docker_image" {
  description = "The full image URL (path & tag) for the Docker image to deploy in Cloud Run"
  type        = string
}

variable "spanner_pu" {
  description = "Amount of Spanner processing units"
  type = number
  default = 100
}

variable "ephemeral" {
  description = "Set to true if this is a throwaway/temporary log instance. Will set attributes on created resources to allow them to be disabled/deleted more easily."
  default     = false
  type        = bool
}
