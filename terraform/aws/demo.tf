provider "aws" {
  region = "us-east-1"
}

# Publicly exposed S3 bucket
resource "aws_s3_bucket" "public_bucket" {
  bucket = "vulnerable-public-bucket"
  acl    = "public-read"   
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
        "Action": "s3:*",
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


resource "aws_iam_access_key" "exposed_key" {
  user = aws_iam_user.insecure_admin.name
}

# Hardcoded credentials (DO NOT USE IN PRODUCTION)
output "exposed_access_key" {
  value = "AKIAIOSFODNN7EXAMPLE"
}

output "exposed_secret_key" {
  value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Security Group with Open Access
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allows unrestricted inbound access"

  ingress {
    from_port   = 0
    to_port     = 65535
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
  identifier           = "vulnerable-db"
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "5.7" 
  instance_class       = "db.t2.micro"
  name                 = "mydb2"
  username             = "admin"
  password             = "Password123!" # Weak password
  parameter_group_name = "default.mysql5.7"
  publicly_accessible  = true
  skip_final_snapshot  = true
  storage_encrypted    = false
}

# Vulnerable EC2 Instance
resource "aws_instance" "vulnerable_ec2" {
  ami                    = "ami-0c55b159cbfafe1f0" # Outdated AMI
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]
  
  user_data = <<-EOF
              #!/bin/bash
              echo "root:Password123!" | chpasswd
              sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
              service sshd restart
              EOF

  tags = {
    Name = "VulnerableInstanceTest"
  }
}

# Exposed SSH Key (DO NOT USE IN PRODUCTION)
resource "aws_key_pair" "exposed_ssh_key" {
  key_name   = "exposed-ssh-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxEeNAr4Ue3/jNwlI5xpZWn7Oe8Iu4eil1qTbXG7XKZB5VoGbXlNx7MQVv9QMfW4oVJ6WDuLsO1yJDY+3fTwfUWdvk3banner@example.com"
}

# Disabled CloudTrail
resource "aws_cloudtrail" "disabled_trail" {
  name                          = "disabled-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.public_bucket.id
  include_global_service_events = false
  enable_logging                = false
  enable_log_file_validation    = false
}

# Unencrypted SNS Topic
resource "aws_sns_topic" "unencrypted_topic" {
  name = "unencrypted-topic"
}

# Lambda function with vulnerable dependencies
resource "aws_lambda_function" "vulnerable_lambda" {
  filename      = "lambda_function.zip"
  function_name = "vulnerable_lambda"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs12.x" # Outdated runtime

  environment {
    variables = {
      SECRET_KEY = "sk_test_51ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "vulnerable_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}
