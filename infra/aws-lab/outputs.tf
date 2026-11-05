output "summary" {
  value = {
    region            = var.region
    account_id        = data.aws_caller_identity.current.account_id
    vpc_id            = aws_vpc.lab.id
    igw_id            = aws_internet_gateway.lab.id
    public_ec2_ip     = try(aws_instance.public_ec2[0].public_ip, null)
    public_bucket     = aws_s3_bucket.clientes.bucket
    public_bucket_url = "https://${aws_s3_bucket.clientes.bucket}.s3.${var.region}.amazonaws.com/dados-clientes.csv"
    iam_user_no_mfa   = aws_iam_user.no_mfa.name
    lambda_fn         = aws_lambda_function.demo.function_name
    rds_endpoint      = try(aws_db_instance.prod_db[0].endpoint, null)
  }
}

output "anti_patterns" {
  description = "O que o GraphSec deve detectar"
  value = [
    "S3 bucket público (${aws_s3_bucket.clientes.bucket}) com dados sensíveis simulados",
    "SG com SSH 0.0.0.0/0 → EC2 pública (${try(aws_instance.public_ec2[0].id, "desabilitada")})",
    "EC2 role com policy s3:* Resource:* (privilege escalation path)",
    "IAM user sem MFA (${aws_iam_user.no_mfa.name}) com access policy ampla",
    "IAM role com trust para root da conta + ReadOnlyAccess",
    var.create_rds ? "RDS publicly_accessible + storage_encrypted=false" : "RDS: desabilitado (-var create_rds=true pra habilitar)",
  ]
}

output "k8s" {
  description = "Acesso ao k3s na EC2 (para o connector K8s do GraphSec)"
  value = var.scenario_k8s && var.create_ec2 ? {
    node_public_ip = aws_instance.public_ec2[0].public_ip
    api            = "https://${aws_instance.public_ec2[0].public_ip}:6443"
    sa_role        = aws_iam_role.k8s_backend_sa_role[0].arn
    como_obter_kubeconfig = "aguarde ~3min o user-data; scp ec2-user@${aws_instance.public_ec2[0].public_ip}:/home/ec2-user/kubeconfig.yaml ./kubeconfig.yaml (ou pegue via SSM)"
  } : null
}

output "attack_paths" {
  description = "Caminhos de ataque plantados (para testar no chat / grafo)"
  value = {
    data_exfil = var.scenario_data_exfil ? (
      "internet → EC2 pública → role → ALLOWS → ${aws_s3_bucket.pii[0].bucket} (PII privado)"
    ) : "desabilitado",
    privesc = var.scenario_privesc ? (
      "${aws_iam_user.contractor[0].name} (sem MFA) → CAN_ASSUME → ${aws_iam_role.break_glass_admin[0].name} (AdministratorAccess)"
    ) : "desabilitado",
    lambda_exfil = var.scenario_lambda_exfil ? (
      "${aws_lambda_function.exfil[0].function_name} → role → ALLOWS → ${aws_s3_bucket.financeiro[0].bucket}"
    ) : "desabilitado",
    public_rds = var.create_rds ? "internet → VPC → RDS publicamente acessível e não criptografado" : "desabilitado (-var create_rds=true)",
  }
}
