output "s3_bucket_name" {
  value = aws_s3_bucket.log_bucket.id
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
