# GraphSec — Security Graph Open-Core

## O que é este projeto

Plataforma open-core de security graph para o mercado brasileiro. Ingere ambientes cloud (AWS, Azure, GCP), constrói um grafo de contexto unificado (ativos, identidades, permissões, exposições), revela attack paths e prioriza remediação. Inclui chat LLM para consulta em linguagem natural ao grafo.

## Arquitetura

```
┌─────────────────────────────────────────────────────┐
│                    Frontend (React)                  │
│  ┌──────────────┐  ┌───────────┐  ┌──────────────┐  │
│  │ Graph Viewer  │  │ Chat LLM  │  │  Dashboards  │  │
│  │ (Cytoscape.js)│  │           │  │              │  │
│  └──────────────┘  └───────────┘  └──────────────┘  │
└──────────────────────┬──────────────────────────────┘
                       │ REST + WebSocket
┌──────────────────────┴──────────────────────────────┐
│                 Backend (FastAPI)                     │
│  ┌────────────┐  ┌────────────┐  ┌───────────────┐  │
│  │ Graph API   │  │ Chat API   │  │ Auth (JWT)    │  │
│  │ /query      │  │ /chat      │  │               │  │
│  │ /paths      │  │ text→cypher│  │               │  │
│  └────────────┘  └────────────┘  └───────────────┘  │
│  ┌────────────┐  ┌────────────┐  ┌───────────────┐  │
│  │ Connectors  │  │ Scheduler  │  │ Report Gen    │  │
│  │ AWS/Azure   │  │ (Celery)   │  │ PDF/CSV       │  │
│  └────────────┘  └────────────┘  └───────────────┘  │
└──────────────────────┬──────────────────────────────┘
                       │ Bolt protocol
              ┌────────┴────────┐
              │   Neo4j (grafo)  │
              └─────────────────┘
```

### Stack

- **Grafo**: Neo4j Community Edition (Cypher). Protótipos rápidos com NetworkX.
- **Backend**: Python 3.12+, FastAPI, Pydantic, Celery + Redis (scheduler de ingestão).
- **Ingestão**: connectors via boto3 (AWS), azure-sdk (Azure). Cada connector é um módulo em `graphsec/connectors/`.
- **Chat LLM**: Claude API (Anthropic SDK). Text-to-Cypher com schema injection + few-shot examples.
- **Frontend**: React + TypeScript, Cytoscape.js (grafo), Tailwind CSS.
- **Deploy**: Docker Compose (Neo4j + backend + frontend + Redis). Self-hosted first.

### Diretórios

```
graphsec/
├── CLAUDE.md                  # este arquivo
├── docker-compose.yml
├── backend/
│   ├── graphsec/
│   │   ├── __init__.py
│   │   ├── main.py            # FastAPI app
│   │   ├── config.py          # settings via pydantic-settings
│   │   ├── models/            # Pydantic models (nodes, edges, queries)
│   │   ├── connectors/        # um módulo por cloud provider
│   │   │   ├── base.py        # BaseConnector ABC
│   │   │   ├── aws/
│   │   │   │   ├── iam.py
│   │   │   │   ├── ec2.py
│   │   │   │   ├── s3.py
│   │   │   │   ├── rds.py
│   │   │   │   └── lambda_.py
│   │   │   └── azure/         # fase 2
│   │   ├── graph/
│   │   │   ├── client.py      # Neo4j driver wrapper
│   │   │   ├── schema.py      # definição do schema (nós, relações)
│   │   │   ├── queries.py     # Cypher queries reutilizáveis
│   │   │   └── paths.py       # attack path analysis (shortest path, all paths)
│   │   ├── chat/
│   │   │   ├── engine.py      # text-to-cypher pipeline
│   │   │   ├── prompts.py     # system prompt + few-shot examples
│   │   │   ├── validator.py   # validação sintática de Cypher gerado
│   │   │   └── formatter.py   # formata resultado do grafo → resposta legível
│   │   ├── reports/
│   │   │   └── compliance.py  # geração de relatórios BACEN/LGPD
│   │   ├── api/
│   │   │   ├── graph.py       # rotas /api/graph/*
│   │   │   ├── chat.py        # rotas /api/chat/*
│   │   │   ├── connectors.py  # rotas /api/connectors/*
│   │   │   └── reports.py     # rotas /api/reports/*
│   │   └── scheduler/
│   │       └── tasks.py       # tarefas Celery (sync periódico)
│   ├── tests/
│   ├── pyproject.toml
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── GraphViewer.tsx    # Cytoscape.js wrapper
│   │   │   ├── AttackPath.tsx     # visualização de path destacado
│   │   │   ├── Chat.tsx           # interface de chat
│   │   │   ├── NodeDetail.tsx     # painel lateral com detalhes do nó
│   │   │   └── Dashboard.tsx      # métricas de risco
│   │   ├── hooks/
│   │   │   ├── useGraph.ts
│   │   │   └── useChat.ts
│   │   ├── api/
│   │   │   └── client.ts
│   │   └── App.tsx
│   ├── package.json
│   └── Dockerfile
└── docs/
    ├── architecture.md
    ├── schema.md              # schema do grafo documentado
    └── few-shot-examples.md   # exemplos text→cypher
```

## Schema do Grafo

### Nós (Labels)

| Label | Propriedades chave | Fonte |
|-------|-------------------|-------|
| `AWSAccount` | account_id, alias, org_id | AWS Organizations |
| `IAMUser` | arn, user_name, create_date, has_mfa, last_used | IAM |
| `IAMRole` | arn, role_name, trust_policy, is_service_role | IAM |
| `IAMPolicy` | arn, policy_name, is_aws_managed | IAM |
| `EC2Instance` | instance_id, public_ip, private_ip, state, sg_ids | EC2 |
| `SecurityGroup` | group_id, vpc_id, inbound_rules, outbound_rules | EC2 |
| `S3Bucket` | bucket_name, is_public, encryption, region | S3 |
| `RDSInstance` | db_id, engine, publicly_accessible, encrypted | RDS |
| `LambdaFunction` | function_name, runtime, role_arn, vpc_config | Lambda |
| `VPC` | vpc_id, cidr_block, region | VPC |
| `Subnet` | subnet_id, cidr, is_public, az | VPC |
| `InternetGateway` | igw_id, vpc_id | VPC |
| `Finding` | severity, source, title, resource_arn | SecurityHub/custom |

### Relações (Relationships)

| Relação | De → Para | Significado |
|---------|-----------|-------------|
| `HAS_USER` | AWSAccount → IAMUser | conta possui user |
| `HAS_ROLE` | AWSAccount → IAMRole | conta possui role |
| `CAN_ASSUME` | IAMUser/IAMRole → IAMRole | pode assumir role (trust policy) |
| `HAS_POLICY` | IAMUser/IAMRole → IAMPolicy | política anexada |
| `ALLOWS` | IAMPolicy → S3Bucket/RDS/EC2/Lambda | permissão sobre recurso |
| `MEMBER_OF` | EC2Instance → SecurityGroup | instância no SG |
| `IN_VPC` | EC2/RDS/Lambda/Subnet → VPC | recurso na VPC |
| `IN_SUBNET` | EC2/RDS/Lambda → Subnet | recurso na subnet |
| `EXPOSES` | SecurityGroup → EC2Instance | SG com porta aberta à internet |
| `ROUTES_TO` | InternetGateway → VPC | IGW conectado à VPC |
| `STORES_DATA` | S3Bucket/RDS → Finding | recurso com dados sensíveis |
| `HAS_FINDING` | qualquer recurso → Finding | achado de segurança |
| `PUBLIC_ACCESS` | InternetGateway → EC2/S3/RDS | caminho de acesso público |

### Attack Paths

Um attack path é uma sequência de relações no grafo que conecta um ponto de entrada (internet, identity comprometida) a um alvo de alto valor (bucket com dados PII, RDS com dados financeiros). Exemplo:

```
InternetGateway → (ROUTES_TO) → VPC → (IN_VPC) ← EC2[public_ip]
  → (MEMBER_OF) → SecurityGroup[porta 22 aberta]
  → EC2 → (role via instance profile) → IAMRole
  → (HAS_POLICY) → IAMPolicy → (ALLOWS) → S3Bucket[dados_clientes]
```

Query Cypher para encontrar attack paths:
```cypher
MATCH path = (igw:InternetGateway)-[:ROUTES_TO]->(vpc:VPC)
  <-[:IN_VPC]-(ec2:EC2Instance {state: 'running'})
  -[:MEMBER_OF]->(sg:SecurityGroup)
  -[:CAN_ASSUME|HAS_POLICY*1..3]->(target)
WHERE ec2.public_ip IS NOT NULL
  AND ANY(rule IN sg.inbound_rules WHERE rule.cidr = '0.0.0.0/0')
  AND target:S3Bucket OR target:RDSInstance
RETURN path, length(path) as hops
ORDER BY hops ASC
```

## Chat LLM — Text-to-Cypher

### System prompt (template)

```
Você é um assistente de segurança cloud. Você traduz perguntas em linguagem
natural para queries Cypher contra um grafo Neo4j de segurança.

SCHEMA DO GRAFO:
{schema_yaml}

REGRAS:
- Gere APENAS queries READ-ONLY (MATCH/RETURN). Nunca CREATE/DELETE/SET/MERGE.
- Use os labels e propriedades EXATAMENTE como definidos no schema.
- Se a pergunta não pode ser respondida pelo grafo, diga isso.
- Responda em português.

FORMATO DE SAÍDA:
```cypher
<sua query aqui>
```

Depois da query, explique brevemente o que ela busca.
```

### Few-shot examples (manter em `docs/few-shot-examples.md`)

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
    MATCH path = shortestPath(
      (entry)-[*1..6]->(b:S3Bucket)
    )
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

### Pipeline do chat

1. Usuário envia pergunta via `/api/chat/`
2. `chat/engine.py` monta prompt: system prompt (com schema) + few-shot examples + pergunta
3. Chama Claude API (`anthropic.Anthropic().messages.create()`)
4. `chat/validator.py` valida a query Cypher retornada:
   - Parse sintático (regex ou py2neo parser)
   - Rejeita qualquer query com CREATE/DELETE/SET/MERGE/REMOVE/DROP
   - Valida que labels e propriedades existem no schema
5. Executa query no Neo4j (read-only transaction)
6. `chat/formatter.py` passa resultado + pergunta original ao LLM para formatação
7. Retorna resposta formatada + query usada (transparência) + nós relevantes (para highlight no grafo)

## Convenções de código

- Python: ruff para lint/format, mypy strict, pytest para testes.
- Tipagem: tudo tipado com Pydantic models, sem `Any` sem justificativa.
- Connectors: cada connector implementa `BaseConnector` com métodos `sync()` e `get_nodes()` / `get_edges()`.
- Commits: conventional commits em português (`feat:`, `fix:`, `docs:`, `refactor:`).
- Branches: `main` (estável), `dev` (integração), `feat/<nome>` (features).
- Testes: cada connector deve ter testes com mocks (moto para AWS).
- Segurança: nunca logar credenciais, nunca hardcodar secrets, usar variáveis de ambiente via config.py.
- Chat LLM: toda query gerada DEVE passar pelo validator antes de executar. Sem exceção.

### Regras mandatórias do system prompt (text-to-Cypher)

Estas regras são **obrigatórias** em `chat/prompts.py` e protegidas pelo teste
`tests/test_prompts.py` (falha o CI se alguma for removida). Não as remova sem
atualizar o teste conscientemente — elas são o que faz os attack paths resolverem:

1. **Somente leitura** — nunca `CREATE/DELETE/SET/MERGE/REMOVE/DROP/LOAD`.
2. **Dados sensíveis são identificados pelo NOME do recurso**, não por nós `Finding`
   (ex.: `toLower(bucket_name) CONTAINS 'pii'`, `'cliente'`, `'financ'`, `'prod'`).
3. **"Caminho da internet até X"** começa em `(:InternetGateway)` e usa
   `shortestPath((igw)-[*1..6]->(alvo))` com arestas **direcionadas**
   (`PUBLIC_ACCESS`, `CAN_ASSUME`, `HAS_POLICY`, `ALLOWS`).
4. **Não depender de `Finding`/`STORES_DATA`** — podem não estar populados.
5. **Erro explícito** — se não dá pra responder pelo grafo, retornar linha
   iniciada por `ERRO:`.

Além disso, os few-shots de attack path (PII, Lambda→bucket, user→admin) devem
permanecer em `FEW_SHOTS` e ser read-only (também coberto pelo teste).

## Variáveis de ambiente

```env
# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=

# AWS (connector)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=sa-east-1

# LLM (chat)
ANTHROPIC_API_KEY=

# Redis (scheduler)
REDIS_URL=redis://localhost:6379/0

# App
APP_SECRET_KEY=
APP_ENV=development
```

## Roadmap MVP (90 dias)

### Semanas 1–4: Fundação
- [ ] Setup projeto: monorepo, Docker Compose, CI básico
- [ ] Neo4j rodando com schema inicial
- [ ] Connector AWS IAM (users, roles, policies, trust relationships)
- [ ] Connector AWS EC2 (instances, security groups, VPCs)
- [ ] Connector AWS S3 (buckets, policies, ACLs)
- [ ] Attack path query básica (internet → recurso sensível)
- [ ] API REST mínima (FastAPI)

### Semanas 5–8: Visualização + Chat
- [ ] Frontend: Graph Viewer com Cytoscape.js
- [ ] Highlight de attack paths no grafo
- [ ] Chat LLM: text-to-Cypher funcional
- [ ] Painel de detalhes de nó (click no grafo)
- [ ] PoC com 2–3 ambientes AWS reais
- [ ] Connector AWS RDS e Lambda

### Semanas 9–12: Enterprise-ready
- [ ] Connector Azure (IAM + VMs + Storage)
- [ ] Relatório de compliance BACEN 4893 (PDF)
- [ ] Auth (JWT + RBAC básico)
- [ ] Deploy self-hosted via Docker Compose documentado
- [ ] Scheduler de sync periódico (Celery)
- [ ] Docs de onboarding para PoC

## Comandos úteis

```bash
# subir tudo
docker compose up -d

# rodar backend local
cd backend && uvicorn graphsec.main:app --reload

# rodar testes
cd backend && pytest -v

# lint
cd backend && ruff check . && mypy .

# sync AWS (manual)
cd backend && python -m graphsec.connectors.aws.sync

# frontend
cd frontend && npm run dev
```