# AWS live configs

TODO: Add terraform configuration files.

## Temporary Dev Env Setup

### Create the MySQL database and user

```sh
mysql -h tesseract.cluster-xxxx12345678.us-east-1.rds.amazonaws.com -u admin -p
```

```sql
CREATE DATABASE tesseract;
CREATE USER 'tesseract'@'%' IDENTIFIED BY 'tesseract';
GRANT ALL PRIVILEGES ON tesseract.* TO 'tesseract'@'%';
FLUSH PRIVILEGES;
```

### Create the S3 bucket

### Start the TesseraCT server

```sh
export AWS_REGION=us-east-1
export AWS_PROFILE=AdministratorAccess-<REDACTED>
```

```sh
go run ./cmd/aws \
  --http_endpoint=localhost:6962 \
  --roots_pem_file=./internal/testdata/fake-ca.cert \
  --origin=test-static-ct \
  --bucket=test-static-ct \
  --db_name=tesseract \
  --db_host=tesseract.cluster-xxxx12345678.us-east-1.rds.amazonaws.com \
  --db_port=3306 \
  --db_user=tesseract \
  --db_password=tesseract \
  --dedup_path=test-static-ct
```
