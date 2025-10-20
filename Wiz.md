### Wiz posture review for demo.tf (terraform/aws/demo.tf)

Below is a prioritized list of security issues Wiz will flag in `terraform/aws/demo.tf`, plus concrete remediation guidance and safer Terraform examples. Apply changes iteratively and test in a non‑prod workspace first.

---

## 0) Critical quick wins (do these first)
- **Revoke any exposed credentials immediately**: hardcoded AWS keys and secrets in Terraform outputs and Lambda envs must be removed, rotated in IAM/Secrets Manager, and purged from git history where possible.
- **Close public network access**: lock down `0.0.0.0/0` ingress; remove public S3 ACLs/policies; set S3 Block Public Access.
- **Turn on logging and encryption**: enable CloudTrail (multi‑region, validation), S3 encryption, RDS storage encryption, SNS KMS.

---

## 1) S3 bucket publicly exposed
Problem
- `acl = "public-read"`
- Bucket policy allows `Principal = "*"` and `Action = "s3:*"` on bucket objects.
- Missing S3 Block Public Access and server‑side encryption.

Fix
```hcl
resource "aws_s3_bucket" "public_bucket" {
  bucket = "vulnerable-public-bucket"

  # Remove public ACLs
  acl = "private"

  # Server-side encryption by default
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# OPTIONAL: HTTPS-only access via bucket policy
data "aws_iam_policy_document" "s3_https_only" {
  statement {
    sid     = "HttpsOnly"
    actions = ["s3:*"]
    effect  = "Deny"
    principals { type = "*" identifiers = ["*"] }
    resources = [
      aws_s3_bucket.public_bucket.arn,
      "${aws_s3_bucket.public_bucket.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "policy" {
  bucket = aws_s3_bucket.public_bucket.id
  policy = data.aws_iam_policy_document.s3_https_only.json
}
```

Also enable access logging to a separate, locked bucket.

---

## 2) Hardcoded credentials and secret outputs
Problem
- Terraform outputs contain `exposed_access_key` and `exposed_secret_key`.
- Lambda `environment` embeds a secret key.

Fix
- Remove these outputs and environment literals.
- Store secrets in AWS Secrets Manager or SSM Parameter Store and reference at deploy time.
- Rotate any leaked keys in IAM immediately.

Example (Secrets Manager reference at deploy time via environment variable):
```hcl
resource "aws_secretsmanager_secret" "app_secret" {
  name = "app/secret-key"
}

resource "aws_secretsmanager_secret_version" "app_secret_v" {
  secret_id     = aws_secretsmanager_secret.app_secret.id
  secret_string = var.secret_key_value  # never commit the value
}

resource "aws_lambda_function" "secure_lambda" {
  # ...
  runtime = "nodejs18.x"
  environment {
    variables = {
      SECRET_KEY_ARN = aws_secretsmanager_secret.app_secret.arn
    }
  }
}
```

---

## 3) Security group allows 0.0.0.0/0 on all TCP ports
Problem
- Ingress from `0.0.0.0/0` range, ports 0‑65535.

Fix
- Restrict to necessary ports and trusted CIDRs/VPC peers. Prefer ALB/NLB + SG referencing.
```hcl
resource "aws_security_group" "app_sg" {
  name        = "app-sg"
  description = "Minimal inbound"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.office_cidr] # e.g., "203.0.113.0/24"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

---

## 4) RDS: outdated engine, public, unencrypted, weak creds
Problem
- `engine = "mysql"`, `engine_version = "5.7"` (EOL), `publicly_accessible = true`, `storage_encrypted = false`, weak static `username/password`, `skip_final_snapshot = true`.

Fix
```hcl
resource "aws_db_instance" "secure_rds" {
  identifier            = "secure-db"
  engine                = "mysql"
  engine_version        = "8.0"
  instance_class        = "db.t3.medium"
  allocated_storage     = 20
  storage_encrypted     = true
  kms_key_id            = var.kms_key_id
  publicly_accessible   = false
  backup_retention_period = 7
  deletion_protection   = true
  skip_final_snapshot   = false

  username              = var.rds_username
  password              = var.rds_password  # supply via TF var/secret, not VCS
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  # place into private subnets via subnet group
}
```

Also place RDS in private subnets and use Secrets Manager rotation.

---

## 5) EC2 instance: outdated AMI, enables SSH password auth
Problem
- Hardcoded AMI; `user_data` sets root password and enables password authentication.

Fix
- Use latest patched AMIs (SSM Parameter), disable password auth, require key‑based or SSM Session Manager, enforce IMDSv2 and EBS encryption.
```hcl
data "aws_ssm_parameter" "ami_linux2" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "secure_ec2" {
  ami           = jsondecode(data.aws_ssm_parameter.ami_linux2.value).image_id
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "required"  # IMDSv2
  }

  user_data = <<-EOF
              #!/bin/bash
              sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
              systemctl restart sshd
              EOF
}
```

Prefer disabling SSH entirely and using SSM.

---

## 6) CloudTrail disabled
Problem
- `enable_logging = false`, `include_global_service_events = false`, `enable_log_file_validation = false`.

Fix
```hcl
resource "aws_cloudtrail" "org_trail" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.public_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
}
```

Send to a dedicated, locked logging bucket with MFA delete/object lock.

---

## 7) SNS topic unencrypted
Problem
- No KMS key specified.

Fix
```hcl
resource "aws_kms_key" "sns_kms" {
  description = "KMS for SNS"
}

resource "aws_sns_topic" "secure_topic" {
  name              = "secure-topic"
  kms_master_key_id = aws_kms_key.sns_kms.arn
}
```

---

## 8) Lambda runtime outdated and secrets in env
Problem
- `runtime = "nodejs12.x"` (EOL), plaintext secrets in `environment`.

Fix
- Upgrade to a supported runtime (e.g., `nodejs18.x`), remove plaintext secrets, optionally enable environment encryption with KMS and use IAM to retrieve secrets at runtime.
```hcl
resource "aws_lambda_function" "secure_lambda" {
  # ...
  runtime = "nodejs18.x"
  kms_key_arn = aws_kms_key.lambda_env.arn
}

resource "aws_kms_key" "lambda_env" {
  description = "KMS for Lambda env"
}
```

Ensure IAM role has least privilege; consider code signing and DLQ/CloudWatch alarms.

---

## 9) IAM user and access key in IaC
Problem
- Dedicated IAM user with long‑term access key; credentials should not be provisioned or exposed this way.

Fix
- Prefer IAM roles (federated/OIDC) and short‑lived credentials; avoid creating users and access keys via Terraform unless absolutely necessary.

---

## Variables and policy hardening checklist
- Define `kms_key_id`, `office_cidr`, `rds_username`, `rds_password` as variables and load values from your secret store.
- Replace wildcard principals with least‑privilege role ARNs.
- Tag resources for ownership and lifecycle.

---

## Validation steps
1. Run terraform fmt/validate/plan in a scratch environment.
2. Enable pre‑commit scanning (gitleaks, tfsec, Checkov) and repo secret scanning.
3. Re‑scan with Wiz to confirm: no public S3, SGs restricted, RDS encrypted/private, CloudTrail enabled, SNS/Lambda KMS, no plaintext secrets, up‑to‑date runtimes and AMIs.


