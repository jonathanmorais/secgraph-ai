# Schema do Grafo

Fonte canônica: [backend/graphsec/graph/schema.py](../backend/graphsec/graph/schema.py).

## Nós

| Label | Propriedades chave |
|-------|-------------------|
| AWSAccount | account_id, alias, org_id |
| IAMUser | arn, user_name, create_date, has_mfa, last_used |
| IAMRole | arn, role_name, trust_policy, is_service_role |
| IAMPolicy | arn, policy_name, is_aws_managed |
| EC2Instance | instance_id, public_ip, private_ip, state, sg_ids |
| SecurityGroup | group_id, vpc_id, inbound_rules, outbound_rules |
| S3Bucket | bucket_name, is_public, encryption, region |
| RDSInstance | db_id, engine, publicly_accessible, encrypted |
| LambdaFunction | function_name, runtime, role_arn, vpc_config |
| VPC | vpc_id, cidr_block, region |
| Subnet | subnet_id, cidr, is_public, az |
| InternetGateway | igw_id, vpc_id |
| Finding | severity, source, title, resource_arn |

## Relações

Ver `RELATIONSHIPS` em `schema.py`. Principais: `HAS_USER`, `HAS_ROLE`,
`CAN_ASSUME`, `HAS_POLICY`, `ALLOWS`, `MEMBER_OF`, `IN_VPC`, `IN_SUBNET`,
`EXPOSES`, `ROUTES_TO`, `STORES_DATA`, `HAS_FINDING`, `PUBLIC_ACCESS`.
