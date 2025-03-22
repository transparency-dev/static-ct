terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.92.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "${var.prefix_name}-${var.base_name}-bucket"

  force_destroy = var.ephemeral
}

resource "aws_rds_cluster" "log_rds_cluster" {
  cluster_identifier          = "${var.base_name}-cluster"
  engine                      = "aurora-mysql"
  engine_version              = "8.0.mysql_aurora.3.05.2"
  database_name               = "tesseract"
  manage_master_user_password = true
  master_username             = "tesseract"
  skip_final_snapshot         = true
  apply_immediately           = true
}

resource "aws_rds_cluster_instance" "cluster_instances" {
  count              = 1
  cluster_identifier = aws_rds_cluster.log_rds_cluster.id
  instance_class     = "db.r5.large"
  engine             = aws_rds_cluster.log_rds_cluster.engine
  engine_version     = aws_rds_cluster.log_rds_cluster.engine_version
  identifier         = "${var.base_name}-${count.index + 1}"

  force_destroy = var.ephemeral
}
