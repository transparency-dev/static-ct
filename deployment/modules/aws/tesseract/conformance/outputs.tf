output "s3_bucket_name" {
  value = module.storage.s3_bucket_name
}

output "rds_aurora_cluster_endpoint" {
  value     = module.storage.rds_aurora_cluster_endpoint
  sensitive = true
}

output "rds_aurora_cluster_master_username" {
  value = module.storage.rds_aurora_cluster_master_username
}

output "rds_aurora_cluster_database_name" {
  value = module.storage.rds_aurora_cluster_database_name
}

output "rds_aurora_cluster_master_user_secret" {
  value     = module.storage.rds_aurora_cluster_master_user_secret
  sensitive = true
}

output "ecdsa_p256_public_key_id" {
  description = "Signer public key (P256_SHA256)"
  value       = module.secretsmanager.ecdsa_p256_public_key_id
}

output "ecdsa_p256_private_key_id" {
  description = "Signer private key (P256_SHA256)"
  value       = module.secretsmanager.ecdsa_p256_private_key_id
}

output "ecs_cluster" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.ecs_cluster.id
}

output "vpc_subnets" {
  description = "VPC subnets list"
  value       = data.aws_subnets.subnets.ids
}
