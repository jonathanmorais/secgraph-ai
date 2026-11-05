#############################################
# CENÁRIO K8s — k3s na EC2 pública + workloads
# vulneráveis com IRSA (pod -> SA -> IAM role).
# Reusa a EC2 pública já criada (var.create_ec2).
#############################################

variable "scenario_k8s" {
  description = "Instala k3s na EC2 pública e deploya workloads de demo (pod->SA->role)"
  type        = bool
  default     = true
}

# Role que a service account 'backend-sa' vai 'assumir' (IRSA modelado).
# Dá acesso de leitura ao bucket PII -> fecha o path workload -> dados.
resource "aws_iam_role" "k8s_backend_sa_role" {
  count = var.scenario_k8s ? 1 : 0
  name  = "${local.name}-k8s-backend-sa"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "k8s_backend_sa_policy" {
  count = var.scenario_k8s && var.scenario_data_exfil ? 1 : 0
  name  = "pii-read"
  role  = aws_iam_role.k8s_backend_sa_role[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [aws_s3_bucket.pii[0].arn, "${aws_s3_bucket.pii[0].arn}/*"]
    }]
  })
}

locals {
  k8s_manifest = var.scenario_k8s ? replace(
    file("${path.module}/k8s-manifests/workloads.yaml"),
    "ROLE_ARN_PLACEHOLDER",
    aws_iam_role.k8s_backend_sa_role[0].arn
  ) : ""

  k8s_script = join("\n", [
    "#!/bin/bash",
    "set -euxo pipefail",
    "PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)",
    "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC=\"--tls-san $PUBLIC_IP --write-kubeconfig-mode 644\" sh -",
    "until kubectl get nodes >/dev/null 2>&1; do sleep 3; done",
    "echo '${base64encode(local.k8s_manifest)}' | base64 -d >/tmp/workloads.yaml",
    "kubectl apply -f /tmp/workloads.yaml",
    "sed \"s/127.0.0.1/$PUBLIC_IP/\" /etc/rancher/k3s/k3s.yaml >/root/kubeconfig.yaml",
    "cp /root/kubeconfig.yaml /home/ec2-user/kubeconfig.yaml 2>/dev/null || true",
  ])

  k8s_user_data = var.scenario_k8s ? local.k8s_script : ""
}
