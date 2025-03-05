provider "aws" {
  region = "us-east-2"
}

# Publicly exposed S3 bucket
resource "aws_s3_bucket" "public_bucket" {
  bucket = "vulnerable-public-bucket"
  acl    = "public-read"  
  website {
    index_document = "index.html"
  }
}

resource "aws_s3_bucket_policy" "public_policy" {
  bucket = aws_s3_bucket.public_bucket.id
  policy = <<POLICY
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::vulnerable-public-bucket/*"
      }
    ]
  }
  POLICY
}

# Insecure IAM User with Admin Access
resource "aws_iam_user" "insecure_admin" {
  name = "insecure-admin"
}

resource "aws_iam_policy" "admin_policy" {
  name        = "full-admin-policy"
  description = "Overly permissive policy"
  policy      = <<EOP
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }
  EOP
}

resource "aws_iam_user_policy_attachment" "attach_admin_policy" {
  user       = aws_iam_user.insecure_admin.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

# Security Group with Open Access
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allows unrestricted inbound access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Unencrypted and Publicly Accessible RDS Database
resource "aws_db_instance" "vulnerable_rds" {
  allocated_storage   = 20
  engine             = "mysql"
  engine_version     = "5.7" 
  instance_class     = "db.t2.micro"
  publicly_accessible = true  
  username          = "root"
  password          = "weakpassword123" 
  skip_final_snapshot = true
}

# 🔥 Unencrypted EC2 Instance with Root Access and Outdated AMI
resource "aws_instance" "vulnerable_ec2" {
  ami                    = "ami-0c55b159cbfafe1f0" 
  instance_type          = "t2.micro"
  key_name               = "exposed-ssh-key"
  security_groups        = [aws_security_group.insecure_sg.name]
  user_data              = <<EOF
#!/bin/bash
echo "root:toor" | chpasswd 
EOF
  metadata_options {
    http_tokens = "optional" 
  }
}

# IAM Access Key for User (Exposed Credentials)
resource "aws_iam_access_key" "exposed_key" {
  user = aws_iam_user.insecure_admin.name
}

output "exposed_access_key" {
  value     = aws_iam_access_key.exposed_key.id
  sensitive = false 
}

output "exposed_secret_key" {
  value     = aws_iam_access_key.exposed_key.secret
  sensitive = false 
}

# Exposed SSH Key
resource "aws_key_pair" "exposed_ssh_key" {
  key_name   = "exposed-ssh-key"
  public_key = file("public-ssh-key.pub") 
}

# CloudTrail Disabled (No Logging)
resource "aws_cloudtrail" "disabled_trail" {
  name                          = "insecure-trail"
  s3_bucket_name                = aws_s3_bucket.public_bucket.id
  enable_logging                = false 
}
