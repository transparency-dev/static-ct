terraform {
  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = "6.12.0"
    }
  }
}

# Artifact Registry

resource "google_project_service" "artifact_registry_api" {
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "docker" {
  repository_id = "docker-${var.docker_env}"
  location      = var.location
  description   = "Static CT docker images"
  format        = "DOCKER"
  depends_on = [
    google_project_service.artifact_registry_api,
  ]
}
