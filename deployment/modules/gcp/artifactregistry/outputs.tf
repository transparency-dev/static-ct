output "docker" {
  description = "The artifact registry repository for Docker container images"
  value       = google_artifact_registry_repository.docker
}
