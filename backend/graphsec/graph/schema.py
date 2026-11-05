"""Schema definition for the security graph (source of truth)."""
from typing import Final

NODE_LABELS: Final[dict[str, list[str]]] = {
    "AWSAccount": ["account_id", "alias", "org_id"],
    "IAMUser": ["arn", "user_name", "create_date", "has_mfa", "last_used"],
    "IAMRole": ["arn", "role_name", "trust_policy", "is_service_role"],
    "IAMPolicy": ["arn", "policy_name", "is_aws_managed"],
    "EC2Instance": ["instance_id", "public_ip", "private_ip", "state", "sg_ids"],
    "SecurityGroup": [
        "group_id", "vpc_id", "name",
        "inbound_ports", "inbound_cidrs", "inbound_protocols",
        "inbound_world_ports", "exposes_world",
        "exposes_ssh_world", "exposes_http_world", "exposes_rdp_world",
        "outbound_ports", "outbound_cidrs",
    ],
    "S3Bucket": ["bucket_name", "is_public", "encryption", "region"],
    "RDSInstance": ["db_id", "engine", "publicly_accessible", "encrypted"],
    "LambdaFunction": ["function_name", "runtime", "role_arn", "vpc_config"],
    "VPC": ["vpc_id", "cidr_block", "region"],
    "Subnet": ["subnet_id", "cidr", "is_public", "az"],
    "InternetGateway": ["igw_id", "vpc_id"],
    "Finding": ["severity", "source", "title", "resource_arn"],
    "ServicePrincipal": ["service"],
    # Kubernetes / workloads
    "Pod": ["name", "namespace", "node_name", "status"],
    "Container": ["name", "namespace", "pod", "image_ref"],
    "ContainerImage": ["image_ref", "repo", "tag", "digest", "cve_count", "critical_count", "high_count", "worst_severity"],
    "CVE": ["cve_id", "severity", "package", "installed_version", "fixed_version", "title"],
    "ServiceAccount": ["name", "namespace", "role_arn"],
}

# severidades CVE ordenadas (para priorização)
CVE_SEVERITY_ORDER: Final[dict[str, int]] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0,
}

RELATIONSHIPS: Final[list[tuple[str, str, str, str]]] = [
    ("HAS_USER", "AWSAccount", "IAMUser", "conta possui user"),
    ("HAS_ROLE", "AWSAccount", "IAMRole", "conta possui role"),
    ("CAN_ASSUME", "IAMUser|IAMRole|EC2Instance|LambdaFunction|ServicePrincipal", "IAMRole", "pode assumir role (trust/instance profile)"),
    ("HAS_POLICY", "IAMUser|IAMRole", "IAMPolicy", "politica anexada"),
    ("ALLOWS", "IAMPolicy", "S3Bucket|RDSInstance|EC2Instance|LambdaFunction", "permissao sobre recurso"),
    ("MEMBER_OF", "EC2Instance", "SecurityGroup", "instancia no SG"),
    ("IN_VPC", "EC2Instance|RDSInstance|LambdaFunction|Subnet", "VPC", "recurso na VPC"),
    ("IN_SUBNET", "EC2Instance|RDSInstance|LambdaFunction", "Subnet", "recurso na subnet"),
    ("EXPOSES", "SecurityGroup", "EC2Instance", "SG com porta aberta a internet"),
    ("ROUTES_TO", "InternetGateway", "VPC", "IGW conectado a VPC"),
    ("STORES_DATA", "S3Bucket|RDSInstance", "Finding", "recurso com dados sensiveis"),
    ("HAS_FINDING", "*", "Finding", "achado de seguranca"),
    ("PUBLIC_ACCESS", "InternetGateway", "EC2Instance|S3Bucket|RDSInstance", "caminho de acesso publico"),
    # Kubernetes / workloads
    ("HOSTS", "EC2Instance", "Pod", "no k8s (EC2) hospeda o pod"),
    ("RUNS", "Pod", "Container", "pod executa o container"),
    ("USES_IMAGE", "Container", "ContainerImage", "container usa a imagem"),
    ("HAS_CVE", "ContainerImage", "CVE", "imagem tem vulnerabilidade CVE"),
    ("USES_SA", "Pod", "ServiceAccount", "pod usa a service account"),
    ("CAN_ASSUME", "ServiceAccount", "IAMRole", "SA assume role via IRSA (annotation)"),
]


def schema_as_text() -> str:
    """Renderiza o schema em texto para injetar no prompt do LLM."""
    lines = ["# NODES"]
    for label, props in NODE_LABELS.items():
        lines.append(f"({label}): {', '.join(props)}")
    lines.append("")
    lines.append("# RELATIONSHIPS")
    for rel, src, dst, desc in RELATIONSHIPS:
        lines.append(f"({src})-[:{rel}]->({dst})  # {desc}")
    return "\n".join(lines)


CONSTRAINTS: Final[list[str]] = [
    # uid é o merge key universal (igual ao Node.id do modelo)
    *[
        f"CREATE CONSTRAINT {label.lower()}_uid IF NOT EXISTS FOR (n:{label}) REQUIRE n.uid IS UNIQUE"
        for label in NODE_LABELS
    ],
    "CREATE CONSTRAINT aws_account_id IF NOT EXISTS FOR (n:AWSAccount) REQUIRE n.account_id IS UNIQUE",
    "CREATE CONSTRAINT iam_user_arn IF NOT EXISTS FOR (n:IAMUser) REQUIRE n.arn IS UNIQUE",
    "CREATE CONSTRAINT iam_role_arn IF NOT EXISTS FOR (n:IAMRole) REQUIRE n.arn IS UNIQUE",
    "CREATE CONSTRAINT iam_policy_arn IF NOT EXISTS FOR (n:IAMPolicy) REQUIRE n.arn IS UNIQUE",
    "CREATE CONSTRAINT ec2_instance_id IF NOT EXISTS FOR (n:EC2Instance) REQUIRE n.instance_id IS UNIQUE",
    "CREATE CONSTRAINT sg_group_id IF NOT EXISTS FOR (n:SecurityGroup) REQUIRE n.group_id IS UNIQUE",
    "CREATE CONSTRAINT s3_bucket_name IF NOT EXISTS FOR (n:S3Bucket) REQUIRE n.bucket_name IS UNIQUE",
    "CREATE CONSTRAINT rds_db_id IF NOT EXISTS FOR (n:RDSInstance) REQUIRE n.db_id IS UNIQUE",
    "CREATE CONSTRAINT lambda_fn IF NOT EXISTS FOR (n:LambdaFunction) REQUIRE n.function_name IS UNIQUE",
    "CREATE CONSTRAINT vpc_id IF NOT EXISTS FOR (n:VPC) REQUIRE n.vpc_id IS UNIQUE",
]


def apply_constraints() -> None:
    from graphsec.graph.client import run_write
    for stmt in CONSTRAINTS:
        run_write(stmt)
