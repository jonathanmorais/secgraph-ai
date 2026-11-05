# Few-shot examples (text → Cypher)

Fonte canônica: `backend/graphsec/chat/prompts.py` (`FEW_SHOTS`).

```yaml
- pergunta: "quais buckets S3 estão públicos?"
  cypher: |
    MATCH (b:S3Bucket {is_public: true})
    RETURN b.bucket_name, b.region

- pergunta: "quais usuários IAM não têm MFA ativado?"
  cypher: |
    MATCH (u:IAMUser {has_mfa: false})
    RETURN u.user_name, u.arn, u.last_used

- pergunta: "mostre os caminhos de ataque até o bucket de dados de clientes"
  cypher: |
    MATCH path = shortestPath((entry)-[*1..6]->(b:S3Bucket))
    WHERE (entry:InternetGateway OR (entry:IAMUser AND entry.has_mfa = false))
      AND b.bucket_name CONTAINS 'cliente'
    RETURN path

- pergunta: "quais roles podem acessar o RDS de produção?"
  cypher: |
    MATCH (r:IAMRole)-[:HAS_POLICY]->(p:IAMPolicy)-[:ALLOWS]->(db:RDSInstance)
    WHERE db.db_id CONTAINS 'prod'
    RETURN r.role_name, p.policy_name, db.db_id

- pergunta: "quais instâncias EC2 estão expostas à internet com porta 22?"
  cypher: |
    MATCH (ec2:EC2Instance)-[:MEMBER_OF]->(sg:SecurityGroup)
    WHERE ec2.public_ip IS NOT NULL
      AND ANY(rule IN sg.inbound_rules
              WHERE rule.port = 22 AND rule.cidr = '0.0.0.0/0')
    RETURN ec2.instance_id, ec2.public_ip, sg.group_id

- pergunta: "qual o risco mais crítico agora?"
  cypher: |
    MATCH (r)-[:HAS_FINDING]->(f:Finding)
    WHERE f.severity = 'CRITICAL'
    RETURN labels(r)[0] AS tipo, r.arn AS recurso, f.title, f.source
    ORDER BY f.severity DESC
    LIMIT 10
```

Para adicionar mais exemplos edite o array `FEW_SHOTS` em `prompts.py` e replique aqui.
