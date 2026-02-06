#Include provider block
provider "aws" {
  profile = "default"
  region  = "us-east-1"
}


#Create an IAM Policy - Read only Access 
resource "aws_iam_policy" "demo-s3-policy-read" {
  name        = "S3-Bucket-Access-Policy"
  description = "Provides permission to access S3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:Get*",
          "s3:List*",
        ]
        Effect   = "Allow"
        Resource = aws_s3_bucket.my_s3_bucket.arn
      },
    ]
  })
}

#Create an IAM Policy - No delete permissions
resource "aws_iam_policy" "demo-s3-policy-nodelete" {
  name        = "S3-Bucket-NoDelete-Policy"
  description = "Denies delete permission in s3 objects"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Effect   = "Deny"
        Resource = aws_s3_bucket.my_s3_bucket.arn
      },
    ]
  })
}


#Creating s3 bucket for testing
resource "aws_s3_bucket" "my_s3_bucket" {
  bucket = "my-tf-test-bucket-oluwanifemi"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}


#Create an IAM Role
resource "aws_iam_role" "demo-role" {
  name = "ec2_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "RoleForEC2"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

#Attach policy to role
resource "aws_iam_policy_attachment" "demo-attach-policies-read-access" {
  name       = "demo-attachment-read-access"
  roles      = [aws_iam_role.demo-role.name]
  policy_arn = aws_iam_policy.demo-s3-policy-read.arn
}

resource "aws_iam_policy_attachment" "demo-attach-policies-nodelete" {
  name       = "demo-attachment-nodelete"
  roles      = [aws_iam_role.demo-role.name]
  policy_arn = aws_iam_policy.demo-s3-policy-nodelete.arn
}

#Create instance profile 
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "demo_profile"
  role = aws_iam_role.demo-role.name
}

#Create EC2 instance and Attach Instance Profile
resource "aws_instance" "example" {
  ami                  = "ami-0532be01f26a3de55"
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name
  key_name             = "aws_ec2_key"
  associate_public_ip_address = true

  vpc_security_group_ids = [
    aws_security_group.allow_ssh.id
  ]


  tags = {
    Name = "my_ec2instance"
  }
}

#Include Security Group for instance
resource "aws_security_group" "allow_ssh" {
  name        = "ec2_sg"
  description = "Allow SSH inbound traffic"

  tags = {
    Name = "allow_ssh"
  }
}

resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv4         = "197.211.59.199/32"
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_key_pair" "deployer" {
  key_name   = "aws_ec2_key"
  public_key = file("C:/Users/DELL E7470/.ssh/aws_ec2_key.pub")
}
