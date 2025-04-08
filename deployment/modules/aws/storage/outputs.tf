output "s3_bucket_name" {
  value = aws_s3_bucket.log_bucket.id
}

output "s3_bucket_arn" {
  value = aws_s3_bucket.log_bucket.arn
}

output "s3_bucket_regional_domain_name" {
  value = aws_s3_bucket.log_bucket.bucket_regional_domain_name
}

output "rds_aurora_cluster_endpoint" {
  value     = aws_rds_cluster.log_rds_cluster.endpoint
  sensitive = true
}

output "rds_aurora_cluster_master_username" {
  value = aws_rds_cluster.log_rds_cluster.master_username
}

output "rds_aurora_cluster_database_name" {
  value = aws_rds_cluster.log_rds_cluster.database_name
}

output "rds_aurora_cluster_master_user_secret" {
  value     = aws_rds_cluster.log_rds_cluster.master_user_secret
  sensitive = true
}

output "rds_aurora_cluster_master_user_secret_unsafe" {
  description = "Retrieved RDS Aurora DB Password (UNSAFE - AVOID IN PRODUCTION)"
  value       = jsondecode(data.aws_secretsmanager_secret_version.db_credentials.secret_string)["password"]
  sensitive   = true # Mark as sensitive, but it can still be exposed
}
