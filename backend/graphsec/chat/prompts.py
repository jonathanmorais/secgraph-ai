"""Prompts and few-shot examples for text-to-Cypher."""
from graphsec.graph.schema import schema_as_text


FEW_SHOTS: list[dict[str, str]] = [
    {
        "q": "quais buckets S3 estao publicos?",
        "c": "MATCH (b:S3Bucket {is_public: true}) RETURN b.bucket_name, b.region",
    },
    {
        "q": "quais usuarios IAM nao tem MFA ativado?",
        "c": "MATCH (u:IAMUser {has_mfa: false}) RETURN u.user_name, u.arn, u.last_used",
    },
    {
        "q": "mostre os caminhos de ataque ate o bucket de dados de clientes",
        "c": (
            "MATCH path = shortestPath((entry)-[*1..6]->(b:S3Bucket)) "
            "WHERE (entry:InternetGateway OR (entry:IAMUser AND entry.has_mfa = false)) "
            "AND toLower(b.bucket_name) CONTAINS 'cliente' RETURN path"
        ),
    },
    {
        "q": "existe caminho da internet ate dados de PII?",
        "c": (
            "MATCH path = shortestPath((igw:InternetGateway)-[*1..6]->(b:S3Bucket)) "
            "WHERE toLower(b.bucket_name) CONTAINS 'pii' "
            "RETURN path, b.bucket_name, b.is_public"
        ),
    },
    {
        "q": "qual lambda tem acesso ao bucket financeiro?",
        "c": (
            "MATCH (l:LambdaFunction)-[:CAN_ASSUME]->(r:IAMRole)"
            "-[:HAS_POLICY]->(p:IAMPolicy)-[:ALLOWS]->(b:S3Bucket) "
            "WHERE toLower(b.bucket_name) CONTAINS 'financ' "
            "RETURN l.function_name, r.role_name, p.policy_name, b.bucket_name"
        ),
    },
    {
        "q": "qual usuario sem MFA pode escalar para admin?",
        "c": (
            "MATCH (u:IAMUser {has_mfa: false})-[:CAN_ASSUME|HAS_POLICY|ALLOWS*1..4]"
            "->(r:IAMRole)-[:HAS_POLICY]->(p:IAMPolicy) "
            "WHERE toLower(p.policy_name) CONTAINS 'admin' "
            "RETURN DISTINCT u.user_name, r.role_name, p.policy_name"
        ),
    },
    {
        "q": "quais roles podem acessar o RDS de producao?",
        "c": (
            "MATCH (r:IAMRole)-[:HAS_POLICY]->(p:IAMPolicy)-[:ALLOWS]->(db:RDSInstance) "
            "WHERE db.db_id CONTAINS 'prod' RETURN r.role_name, p.policy_name, db.db_id"
        ),
    },
    {
        "q": "quais instancias EC2 estao expostas a internet com porta 22?",
        "c": (
            "MATCH (ec2:EC2Instance)-[:MEMBER_OF]->(sg:SecurityGroup) "
            "WHERE ec2.public_ip IS NOT NULL AND sg.exposes_ssh_world = true "
            "RETURN ec2.instance_id, ec2.public_ip, sg.group_id"
        ),
    },
    {
        "q": "qual o risco mais critico agora?",
        "c": (
            "MATCH (r)-[:HAS_FINDING]->(f:Finding) WHERE f.severity = 'CRITICAL' "
            "RETURN labels(r)[0] AS tipo, r.arn AS recurso, f.title, f.source "
            "ORDER BY f.severity DESC LIMIT 10"
        ),
    },
]


def system_prompt() -> str:
    examples = "\n".join(
        f"PERGUNTA: {ex['q']}\n```cypher\n{ex['c']}\n```"
        for ex in FEW_SHOTS
    )
    return f"""Voce e um assistente de seguranca cloud. Voce traduz perguntas em linguagem
natural para queries Cypher contra um grafo Neo4j de seguranca.

SCHEMA DO GRAFO:
{schema_as_text()}

REGRAS:
- Gere APENAS queries READ-ONLY (MATCH/RETURN). Nunca CREATE/DELETE/SET/MERGE/REMOVE/DROP/LOAD.
- Use os labels e propriedades EXATAMENTE como definidos no schema.
- Dados sensiveis sao identificados pelo NOME do recurso, nao por nos Finding.
  Ex.: bucket de PII contem 'pii' no bucket_name; clientes -> 'cliente';
  financeiro -> 'financ'; producao -> 'prod'. Use toLower(...) CONTAINS.
- Para "caminho da internet ate X", comece em (:InternetGateway) e use
  shortestPath((igw)-[*1..6]->(alvo)). As arestas de ataque sao direcionadas
  (PUBLIC_ACCESS, CAN_ASSUME, HAS_POLICY, ALLOWS), entao use ->.
- Nos Finding/STORES_DATA podem nao estar populados; nao dependa deles para
  identificar dados sensiveis.
- Se a pergunta nao pode ser respondida pelo grafo, diga isso em uma linha comecando com `ERRO:`.
- Responda em portugues.

FORMATO DE SAIDA:
```cypher
<sua query aqui>
```

Depois da query, explique brevemente o que ela busca em uma linha.

EXEMPLOS:
{examples}
"""


FORMATTER_PROMPT = """Voce recebeu o resultado bruto de uma query Cypher executada contra o grafo
de seguranca. Reescreva como uma resposta curta e util em portugues para o usuario.

PERGUNTA ORIGINAL: {question}
QUERY EXECUTADA: {cypher}
RESULTADO (JSON): {rows}

Resposta (direta, sem enrolar, max 5 linhas):"""
