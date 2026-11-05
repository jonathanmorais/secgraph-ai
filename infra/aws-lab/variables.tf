variable "region" {
  description = "AWS region (us-east-1 = mais barato e com free tier)"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefixo dos recursos para facilitar identificação/destroy"
  type        = string
  default     = "graphsec-lab"
}

variable "create_rds" {
  description = "Cria RDS publicamente acessível (adiciona ~15min ao apply/destroy e custa ~USD 0.017/h)"
  type        = bool
  default     = false
}

variable "create_ec2" {
  description = "Cria EC2 t3.micro com SG aberto na 22 (free tier elegível)"
  type        = bool
  default     = true
}

variable "scenario_data_exfil" {
  description = "Path internet→dados: EC2 pública → role → ALLOWS → bucket PII específico"
  type        = bool
  default     = true
}

variable "scenario_privesc" {
  description = "Path privilege escalation: user sem MFA → assume role break-glass admin"
  type        = bool
  default     = true
}

variable "scenario_lambda_exfil" {
  description = "Path identidade→dados: Lambda → role → ALLOWS → bucket financeiro"
  type        = bool
  default     = true
}
