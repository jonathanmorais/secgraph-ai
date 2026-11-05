#############################################
# GraphSec Lab — ambiente AWS proposital-
# mente inseguro para popular o grafo.
# NUNCA USE EM PRODUÇÃO.
#############################################

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  suffix = random_id.suffix.hex
  name   = "${var.name_prefix}-${local.suffix}"
}

#############################################
# VPC pública + IGW (caminho internet → VPC)
#############################################
resource "aws_vpc" "lab" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "${local.name}-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${local.name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.42.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.region}a"
  tags                    = { Name = "${local.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

#############################################
# SG escancarado: SSH (22) ao mundo
#############################################
resource "aws_security_group" "wide_open" {
  name        = "${local.name}-wide-open"
  description = "Intentionally wide-open SG for GraphSec demo"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from the entire internet (BAD)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP open"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = var.scenario_k8s ? [1] : []
    content {
      description = "k3s API (kubeconfig externo) - LAB"
      from_port   = 6443
      to_port     = 6443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#############################################
# EC2 pública com instance profile permissivo
#############################################
data "aws_ami" "al2023" {
  count       = var.create_ec2 ? 1 : 0
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_iam_role" "ec2_role" {
  count = var.create_ec2 ? 1 : 0
  name  = "${local.name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Policy excessivamente permissiva: s3:* em qualquer bucket
resource "aws_iam_role_policy" "ec2_s3_wide" {
  count = var.create_ec2 ? 1 : 0
  name  = "${local.name}-s3-wide"
  role  = aws_iam_role.ec2_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  count = var.create_ec2 ? 1 : 0
  name  = "${local.name}-ec2-profile"
  role  = aws_iam_role.ec2_role[0].name
}

resource "aws_instance" "public_ec2" {
  count                       = var.create_ec2 ? 1 : 0
  ami                         = data.aws_ami.al2023[0].id
  instance_type               = var.scenario_k8s ? "t3.small" : "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.wide_open.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2[0].name
  user_data                   = local.k8s_user_data != "" ? local.k8s_user_data : null
  tags                        = { Name = "${local.name}-public-ec2" }
}

#############################################
# S3 bucket público, sem criptografia padrão
# e com dados "sensíveis" de mentira.
#############################################
resource "aws_s3_bucket" "clientes" {
  bucket        = "${local.name}-clientes-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "clientes" {
  bucket                  = aws_s3_bucket.clientes.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "clientes" {
  bucket = aws_s3_bucket.clientes.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_policy" "clientes_public" {
  bucket     = aws_s3_bucket.clientes.id
  depends_on = [aws_s3_bucket_public_access_block.clientes]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.clientes.arn}/*"
    }]
  })
}

resource "aws_s3_object" "fake_data" {
  bucket  = aws_s3_bucket.clientes.id
  key     = "dados-clientes.csv"
  content = "cpf,nome,saldo\n000.000.000-00,FAKE DATA,0.00\n"
}

#############################################
# Bucket "seguro" de comparação
#############################################
resource "aws_s3_bucket" "logs" {
  bucket        = "${local.name}-logs-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

#############################################
# IAM user sem MFA + access key
#############################################
resource "aws_iam_user" "no_mfa" {
  name = "${local.name}-dev-sem-mfa"
}

resource "aws_iam_user_policy" "dev_admin" {
  name = "overly-broad"
  user = aws_iam_user.no_mfa.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "ec2:Describe*", "rds:Describe*"]
      Resource = "*"
    }]
  })
}

#############################################
# IAM role cross-service com trust amplo
#############################################
resource "aws_iam_role" "wildcard_trust" {
  name = "${local.name}-wildcard-trust"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "wildcard_readonly" {
  role       = aws_iam_role.wildcard_trust.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

#############################################
# Lambda com role
#############################################
resource "aws_iam_role" "lambda_role" {
  name = "${local.name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/.lambda.zip"
  source {
    content  = "def handler(event, context):\n    return {'ok': True}\n"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "demo" {
  function_name    = "${local.name}-demo"
  filename         = data.archive_file.lambda_zip.output_path
  handler          = "index.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_role.arn
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
}

#############################################
# RDS público não criptografado (opcional)
#############################################
resource "aws_subnet" "public_b" {
  count                   = var.create_rds ? 1 : 0
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.42.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = true
}

resource "aws_db_subnet_group" "lab" {
  count      = var.create_rds ? 1 : 0
  name       = "${local.name}-rds"
  subnet_ids = [aws_subnet.public.id, aws_subnet.public_b[0].id]
}

resource "aws_db_instance" "prod_db" {
  count                  = var.create_rds ? 1 : 0
  identifier             = "${local.name}-prod-db"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "postgres"
  password               = "ChangeMe123!"
  publicly_accessible    = true
  storage_encrypted      = false
  skip_final_snapshot    = true
  deletion_protection    = false
  db_subnet_group_name   = aws_db_subnet_group.lab[0].name
  vpc_security_group_ids = [aws_security_group.wide_open.id]
}
