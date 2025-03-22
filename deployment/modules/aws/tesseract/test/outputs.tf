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
