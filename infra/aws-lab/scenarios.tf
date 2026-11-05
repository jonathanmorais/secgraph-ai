#############################################
# Cenários de attack path adicionais.
# Cada um cria um caminho distinto que o
# GraphSec deve conseguir traçar no grafo.
#############################################

#############################################
# CENÁRIO 1 — Data exfil (internet → dados)
# EC2 pública → role → ALLOWS → bucket PII específico.
# Diferente do bucket "clientes" (público): aqui o
# bucket é PRIVADO, mas alcançável via role da EC2.
#############################################
resource "aws_s3_bucket" "pii" {
  count         = var.scenario_data_exfil ? 1 : 0
  bucket        = "${local.name}-dados-pii-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "pii" {
  count                   = var.scenario_data_exfil ? 1 : 0
  bucket                  = aws_s3_bucket.pii[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "pii_data" {
  count   = var.scenario_data_exfil ? 1 : 0
  bucket  = aws_s3_bucket.pii[0].id
  key     = "pii/dados-sensiveis.csv"
  content = "cpf,nome,cartao\n000.000.000-00,FAKE,0000-0000-0000-0000\n"
}

# Concede à role da EC2 pública acesso ao bucket PII ESPECÍFICO
# (Resource = ARN do bucket → gera aresta ALLOWS → S3Bucket no grafo)
resource "aws_iam_role_policy" "ec2_pii_read" {
  count = var.scenario_data_exfil && var.create_ec2 ? 1 : 0
  name  = "pii-read"
  role  = aws_iam_role.ec2_role[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [aws_s3_bucket.pii[0].arn, "${aws_s3_bucket.pii[0].arn}/*"]
    }]
  })
}

#############################################
# CENÁRIO 2 — Privilege escalation
# user sem MFA → assume role break-glass admin.
# Dois sinais: trust (CAN_ASSUME) + policy inline
# com sts:AssumeRole (ALLOWS → IAMRole).
#############################################
resource "aws_iam_user" "contractor" {
  count = var.scenario_privesc ? 1 : 0
  name  = "${local.name}-contractor"
}

resource "aws_iam_access_key" "contractor" {
  count = var.scenario_privesc ? 1 : 0
  user  = aws_iam_user.contractor[0].name
}

resource "aws_iam_role" "break_glass_admin" {
  count = var.scenario_privesc ? 1 : 0
  name  = "${local.name}-break-glass-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.contractor[0].arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin" {
  count      = var.scenario_privesc ? 1 : 0
  role       = aws_iam_role.break_glass_admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Policy inline do user permitindo assumir a role admin explicitamente
resource "aws_iam_user_policy" "contractor_assume" {
  count = var.scenario_privesc ? 1 : 0
  name  = "allow-assume-admin"
  user  = aws_iam_user.contractor[0].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.break_glass_admin[0].arn
    }]
  })
}

#############################################
# CENÁRIO 3 — Lambda exfil (identidade → dados)
# Lambda → role → ALLOWS → bucket financeiro específico.
#############################################
resource "aws_s3_bucket" "financeiro" {
  count         = var.scenario_lambda_exfil ? 1 : 0
  bucket        = "${local.name}-financeiro-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_object" "fin_data" {
  count   = var.scenario_lambda_exfil ? 1 : 0
  bucket  = aws_s3_bucket.financeiro[0].id
  key     = "relatorios/balanco.csv"
  content = "conta,valor\n1001,999999.99\n"
}

resource "aws_iam_role" "lambda_exfil_role" {
  count = var.scenario_lambda_exfil ? 1 : 0
  name  = "${local.name}-lambda-exfil-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_fin_read" {
  count = var.scenario_lambda_exfil ? 1 : 0
  name  = "financeiro-read"
  role  = aws_iam_role.lambda_exfil_role[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [aws_s3_bucket.financeiro[0].arn, "${aws_s3_bucket.financeiro[0].arn}/*"]
    }]
  })
}

resource "aws_lambda_function" "exfil" {
  count            = var.scenario_lambda_exfil ? 1 : 0
  function_name    = "${local.name}-exporta-financeiro"
  filename         = data.archive_file.lambda_zip.output_path
  handler          = "index.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_exfil_role[0].arn
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
}
