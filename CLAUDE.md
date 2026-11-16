# GraphSec — Security Graph Open-Core

## O que é este projeto

Plataforma open-core de security graph para o mercado brasileiro. Ingere ambientes cloud (AWS, Azure, GCP), constrói um grafo de contexto unificado (ativos, identidades, permissões, exposições), revela attack paths e prioriza remediação. Inclui chat LLM para consulta em linguagem natural ao grafo.

## Arquitetura

```
┌─────────────────────────────────────────────────────┐
│                    Frontend (React)                  │
│  ┌──────────────┐  ┌───────────┐  ┌──────────────┐  │ac
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

## Ontologia

O schema acima é a materialização AWS-específica. A **ontologia** é o modelo semântico que está por trás dele: define o que as entidades *significam*, como se especializam e — o mais importante — **o que se pode inferir** a partir dos fatos coletados. É a camada que separa um banco de grafo de um motor de raciocínio de ataque, e é onde está a defensabilidade do produto (um concorrente de checklist não copia a camada de inferência).

### Princípio: três estratos

1. **Core abstrato (provider-agnostic)** — meta-classes e relações que o motor de attack path, scoring e remediação usam. **Não mudam** quando entra Azure/GCP/on-prem.
2. **Especialização por provider** — tipos concretos (`AWSIAMRole isa Identity`, `S3Bucket isa DataStore`) que os connectors populam. Toda a parte que muda por cloud vive aqui.
3. **Axiomas de inferência** — regras que derivam *acesso efetivo* a partir de *configuração declarada*. É o que o atacante realmente enxerga.

> **Decisão de arquitetura**: as queries de attack path operam sobre o core abstrato e sobre arestas *derivadas* (ver axiomas), nunca sobre os labels AWS crus. Isso é o que torna o motor multi-cloud por construção — o Cartography (base do Subimage) não fez isso e paga o preço de um schema paralelo por provider. É brecha nossa.

### Meta-classes (upper ontology)

Todo nó que um connector descobre cai em uma destas 7 categorias raiz:

| Meta-classe | O que é | Especializações (exemplos) |
|-------------|---------|----------------------------|
| **Identity** | Qualquer principal que age | HumanIdentity; NonHumanIdentity → ServiceAccount, AccessKey, OIDCRole, PAT, AIAgent |
| **Resource** | Asset gerenciável | ComputeNode (EC2, Lambda), DataStore (S3, RDS), Function, Queue, Secret |
| **Permission** | Capacidade concedida | Policy, Grant, Role, SCP, ACL |
| **NetworkBoundary** | Fronteira de rede | VPC, Subnet, SecurityGroup, Firewall, VLAN |
| **DataAsset** | O dado em si (não o container) | PIIRecord, FinancialData, Secret, Credential |
| **Finding** | Observação de risco | Misconfig, CVE, ExposedCredential, DriftEvent |
| **Activity** | Evento temporal | AuthEvent, APICall, AgentInteraction |
| **Control** | Mitigação / countermeasure | MFA, SCP, Encryption, NetworkPolicy, ApprovalGate |
| **Goal / Loss** | Objetivo do atacante / valor em risco | AttackerGoal (exfiltração, parada de processo); Loss (multa LGPD, downtime, dano físico) |

**Decisão guiada pelos dados de 2026**: `Identity` é cidadão de primeira classe e `NonHumanIdentity` é uma subárvore rica — não um atributo de outra coisa. 83% dos breaches são identidade e NHI supera humano 45:1, então access key, service account e OIDC role precisam ser *tipos* (com granularidade própria de risco), não flags.

**`Control` e `Goal`/`Loss` (survey arXiv 2510.16610 → ROSE/COVER/UFO)**: trabalhos robustos de ontologia de segurança aterram o vocabulário numa ontologia de risco estabelecida — Threat / Vulnerability / Control / Loss / Asset(Value). Consequências práticas:
- **`Control`** fecha o loop da remediação: remediar deixa de ser só "remover aresta" e passa a ser "adicionar `Control` que neutraliza o path". Modela cobertura ("este MFA cobre N identidades") e alimenta o verification loop (Paper 3).
- **`Goal`/`Loss`** dá narrativa de negócio ao terminus: o path não termina em "chegou no S3", termina em `Loss` ("R$ X de multa LGPD" / "parada de linha"). Essencial pro board/CISO.
- **Aterramento COVER/UFO é alinhamento de vocabulário, não reescrita** — dá rigor e interoperabilidade sem mexer no motor.

### Hierarquia (relação `isa`)

Os labels AWS atuais são folhas desta árvore. Query em meta-classe deve alcançar todas as folhas:

```
Identity
├── HumanIdentity ........... IAMUser
└── NonHumanIdentity
    ├── ServiceAccount ...... IAMRole (is_service_role=true)
    ├── AccessKey ........... (nó novo — chave de longa duração)
    ├── OIDCRole ............ IAMRole com trust federado (GitHub/Okta)
    ├── PAT ................. (nó novo — token externo)
    └── AIAgent ............. (nó novo — identidade de agente)

Resource
├── ComputeNode ............ EC2Instance, LambdaFunction
├── DataStore .............. S3Bucket, RDSInstance
└── Secret ................. (KMS, Secrets Manager — expansão)
```

Implementação em Neo4j: label múltiplo por nó (`:IAMRole:NonHumanIdentity:Identity`) ou propriedade `meta_class`. Label múltiplo é preferível — permite `MATCH (i:Identity)` pegar toda a subárvore sem `WHERE`.

### Relações com semântica formal

Além do nome e direção, cada relação carrega propriedades que habilitam raciocínio:

| Relação | De → Para | Propriedade formal | Por que importa |
|---------|-----------|--------------------|-----------------|
| `CAN_ASSUME` | Identity → Identity | **transitiva** | Cadeia de escalação (fechamento transitivo) |
| `HAS_POLICY` | Identity → Permission | componível com ALLOWS | Base do acesso efetivo |
| `ALLOWS` | Permission → Resource | não-transitiva | Permissão concreta sobre asset |
| `TRUSTS` | Resource → ExternalPrincipal | **condicional** | Trust federado OIDC (vetor do UNC6426) — hoje ninguém modela |
| `EXPOSES` | NetworkBoundary → Resource | condicional (rota + regra) | Exposição à internet |
| `STORES` | DataStore → DataAsset | — | Dá peso ao *terminus* do path (S3 vs S3-com-PII) |
| `HAS_FINDING` | Resource/Identity → Finding | — | Anexa risco observado |
| `MITIGATES` | Control → Finding / ATTACK_EDGE | — | Controle que neutraliza um risco ou corta uma aresta de ataque |
| `RESULTS_IN` | DataAsset/PhysicalProcess → Loss | — | Liga o crown jewel ao impacto de negócio (narrativa pro board) |

As folhas AWS (`MEMBER_OF`, `IN_VPC`, `ROUTES_TO`, `PUBLIC_ACCESS`) são **estruturais** — descrevem topologia, não são remediáveis nem compõem acesso. A ontologia distingue relações *estruturais* de relações de *acesso/confiança*; só as segundas entram no vertex cover / min-cut.

### Axiomas de inferência (o coração)

Regras que materializam arestas derivadas pós-sync. O grafo cru tem o que o connector viu; a ontologia deriva o que isso *implica*. As engines (vertex cover, blast radius, remediation) rodam sobre estas, **não** sobre as cruas.

```cypher
-- CAN_ACCESS: identidade com policy que permite recurso
MATCH (i:Identity)-[:HAS_POLICY]->(:Permission)-[:ALLOWS]->(r:Resource)
MERGE (i)-[:CAN_ACCESS {derived: true, rule: 'policy-allows'}]->(r)
```

```cypher
-- CAN_ESCALATE_TO: fechamento transitivo de CAN_ASSUME
MATCH (i:Identity)-[:CAN_ASSUME*1..5]->(target:Identity)
MERGE (i)-[:CAN_ESCALATE_TO {derived: true}]->(target)
```

```cypher
-- IS_INTERNET_REACHABLE: inferida de topologia (não é flag manual)
MATCH (igw:InternetGateway)-[:ROUTES_TO]->(vpc:VPC)<-[:IN_VPC]-(c:ComputeNode)
WHERE c.public_ip IS NOT NULL
  AND EXISTS {
    MATCH (c)-[:MEMBER_OF]->(sg:SecurityGroup)
    WHERE ANY(rule IN sg.inbound_rules WHERE rule.cidr = '0.0.0.0/0')
  }
MERGE (c)-[:IS_INTERNET_REACHABLE {derived: true}]->(c)
```

```cypher
-- ATTACK_EDGE: composição de exposição + acesso + confiança
-- (esta é a aresta sobre a qual o motor de attack path realmente opera)
MATCH (a)-[:IS_INTERNET_REACHABLE|CAN_ESCALATE_TO|CAN_ACCESS]->(b)
MERGE (a)-[:ATTACK_EDGE {derived: true}]->(b)
```

Princípio: **o atacante raciocina em acesso efetivo, não em configuração declarada**. A camada de inferência é o tradutor. Rodar como job pós-sync (`graph/inference.py`), re-materializando a cada connector sync — e invalidando junto com o cache de blast radius.

### Dimensão temporal e proveniência

Herdada do Paper 3 (ver Research Notes). Cada nó/aresta carrega `observed_at`, `valid_from/to`, `source`, `confidence`, `verification_status`. Consequências ontológicas:
- O grafo é uma **crença** sobre a infra, não a infra — modelar isso evita falsa-confiança.
- Arestas derivadas herdam o menor `confidence` da cadeia que as gerou → alimenta o fator Q(P) do scoring.
- Uma credencial vazada ontem e rotacionada hoje é um path que *existiu* (`valid_to` fechado) — relevante para IR e forense.

### Alinhamento a padrões (não reinventar)

Meta-classes são nossas; folhas e atributos de `Finding`/`Activity` falam o dialeto de:

| Padrão | Onde aplica |
|--------|-------------|
| **OCSF** (Open Cybersecurity Schema Framework) | Normalização de Finding e Activity → qualquer SIEM consome |
| **MITRE ATT&CK** (+ fase de kill-chain) | Anotar `ATTACK_EDGE` com técnica (T1078, T1550) **e fase** (recon→…→impact) → arco narrativo do path |
| **STIX 2.1 / UCO-CASE** | Threat intel e interoperabilidade de grafo |
| **CVE/CWE/CAPEC/CPE + CVSS** | Camada de vulnerabilidade/asset — CPE identifica `SoftwareComponent` (crucial pro SBOM/supply chain) |
| **NIS 2 / taxonomia JRC** | Moldura regulatória (paralelo europeu de BACEN/LGPD) |

### Competency questions guiam a ontologia

Nada entra na ontologia que não sirva a uma pergunta que o grafo precisa responder — proteção contra over-engineering. As Q1–Q7 do Paper 2 já são as competency questions; cada uma exige elementos específicos:
- Q1/Q4 (shortest/max risk path) → exige `ATTACK_EDGE` derivada + scoring
- Q2 (max impact) → exige `DataAsset` + `STORES` (peso do terminus)
- "Esta chave vazada dá acesso a quê?" → exige `AccessKey` como tipo + `CAN_ACCESS`/`CAN_ESCALATE_TO`
- "O que conserto primeiro?" → exige distinção estrutural vs. acesso (só remediáveis no vertex cover)

### Mapa: schema AWS atual → ontologia

O schema da seção anterior permanece válido; a ontologia o reinterpreta:

| Label atual | Meta-classe | Nota |
|-------------|-------------|------|
| `IAMUser` | Identity → HumanIdentity | ✓ |
| `IAMRole` | Identity → NonHumanIdentity | separar ServiceAccount vs OIDCRole por `trust_policy` |
| `IAMPolicy` | Permission | ✓ |
| `EC2Instance`, `LambdaFunction` | Resource → ComputeNode | ✓ |
| `S3Bucket`, `RDSInstance` | Resource → DataStore | adicionar `STORES → DataAsset` para peso de terminus |
| `SecurityGroup`, `VPC`, `Subnet`, `InternetGateway` | NetworkBoundary | relações estruturais (fora do vertex cover) |
| `Finding` | Finding | alinhar atributos a OCSF |
| **(novo)** `AccessKey`, `PAT`, `DataAsset` | — | nós a introduzir; onde o risco de 2026 mora |

### Extensões: cadeia de suprimentos e OT/IoT

Duas dimensões de ataque que o cenário 2026 exige (vuln de terceiros = acesso inicial #1, 44,5%; IoT/edge como porta de entrada). Ambas são **especialização + inferência** — o core abstrato e as engines não mudam. É o payoff da ontologia em camadas.

#### Dimensão A — Cadeia de suprimentos / terceiros (near-term)

Modela arestas que **saem** para um terceiro e **voltam**. Generaliza a relação `TRUSTS` (mesmo mecanismo do OIDC GitHub→AWS).

| Tipo novo | Meta-classe | O que modela |
|-----------|-------------|--------------|
| `ExternalParty` | **nova meta-classe `ExternalEntity`** | Fornecedor, MSP, provedor de TI, SaaS |
| `ThirdPartyIntegration` | Identity → NonHumanIdentity | App OAuth / token de integração (casos reais: Salesloft Drift, Gainsight) |
| `SoftwareComponent` | Resource | Dependência (SBOM) com CVE — vetor #1 |
| `RemoteAccess` | NetworkBoundary | VPN site-to-site, acesso de fornecedor, firewall (`firmware_version`) |

- **Path estendido**: `ExternalParty[postura fraca] -TRUSTS-> SuaIdentity/Recurso -ATTACK_EDGE*-> DataAsset`
- **Não-escaneável**: `ExternalParty` carrega `posture_score` + `confidence` (via security ratings, questionário, SBOM). Peso de `TRUSTS` reflete a postura → alimenta Q(P) do scoring.
- **SBOM como subgrafo**: `ComputeNode -RUNS-> SoftwareComponent -HAS_FINDING-> CVE`. NER/GRAPHENE enriquece o CVE. Ingestão via Syft/Grype ou Dependency-Track.
- **Inferência nova** — `CAN_ACCESS_VIA_TRUST`: assumindo o terceiro comprometido, o que ele alcança (blast radius pela porta do fornecedor — reusa BlastRadiusEngine, só muda o ponto de partida).

```cypher
-- CAN_ACCESS_VIA_TRUST: alcance de um terceiro comprometido
MATCH (ext:ExternalParty)-[:TRUSTS]->(i:Identity)
MATCH (i)-[:ATTACK_EDGE*0..6]->(r:Resource)
MERGE (ext)-[:CAN_ACCESS_VIA_TRUST {derived: true}]->(r)
```

- **Padrões**: SBOM (CycloneDX/SPDX), SLSA (proveniência de build), MITRE ATT&CK **T1195** (Supply Chain Compromise).

#### Dimensão B — OT / IoT / Industrial (reservado no modelo, connector depois)

Mapeia **IEC 62443 (zonas e conduítes)** direto para nós e arestas. Modelar agora; construir connector só com design partner industrial.

| Tipo novo | Meta-classe | Nota |
|-----------|-------------|------|
| `OTDevice` → PLC, RTU, HMI, SCADAServer, Historian, IoTSensor, Gateway | Resource (subárvore nova) | Ativos de controle |
| `Zone` (nível Purdue 0–5) | NetworkBoundary | Segmentação é o controle primário |
| `Conduit` | relação Zone→Zone | Caminho permitido entre níveis (IEC 62443) |
| `PhysicalProcess` / `SafetyImpact` | **nova meta-classe, irmã de `DataAsset`** | Crown jewel em OT = disponibilidade/safety, não dado |

- **Inversão CIA → AIC**: impacto de comprometer um PLC é físico/safety, não data breach. Scoring de impacto ganha a dimensão `PhysicalProcess` como terminus — sem quebrar o resto.
- **Auth/cripto fracas como peso de aresta**: `COMMUNICATES_VIA {protocol, authenticated: false, encrypted: false}`. Modbus/DNP3/OPC-UA clássico sem auth → π(pivô) ≈ 1.0 (casa com paper 2508.21005).
- **Chokepoint supremo**: fronteira IT/OT (DMZ, "Level 3.5"). Vertex cover deve sempre fazer esse nó emergir.
- **Inferência nova** — `CAN_REACH_OT`: travessia IT→OT. Path típico `Internet -> ativo TI -> [DMZ fraca] -> HMI -> PLC -> PhysicalProcess`.
- **Coleta é PASSIVA** (scan ativo pode derrubar PLC): importar inventário de Nozomi/Claroty/Dragos — mesma estratégia do SharpHound import para AD. Virar a camada de attack-path reasoning sobre o inventário deles, não reinventar coleta.
- **Padrões**: Purdue Model, MITRE ATT&CK **for ICS** (matriz separada), IEC 62443.

#### Sequenciamento

- **Supply chain = extensão natural de curto prazo**: mesmo comprador (CISO/cloud), reusa `TRUSTS`, OIDC e blast radius. Baixo esforço, vetor #1. Entra logo após o core de identidade.
- **OT/IoT = Phase 3+ ou linha separada**: comprador diferente (planta/OT), coleta passiva, ciclo de venda próprio. Enorme no BR (agro, mineração, energia, saneamento). Reservar as meta-classes na ontologia **agora** (core não precisa de retrabalho); construir connector só com design partner.

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

## Research Notes — Papers & Metodologias

### Paper 1: "Start thinking in graphs" (Elmiger et al., 2024)
**Fonte**: Int'l Journal of Information Security. Azure AD attack paths via BloodHound + Neo4j.

#### Regras de design de schema (aplicar ao GraphSec)

1. **"Se você quer começar a travessia num dado, torne-o nó"** — traversals começam em nós, então entidades que são ponto de partida de queries (roles, users, resources) DEVEM ser nós.
2. **"Node-Edge-Node deve ler como uma frase"** — ex: `GlobalAdmin -[ADMIN_TO]-> AzureARM`. Se não lê naturalmente, o schema está errado.
3. **"Substantivos = labels de nó, Verbos = labels de edge"** — manter consistente.
4. **"Direção da edge = como você pensa nos dados"** — subject→verb→object define a direção.
5. **Roles como NÓS, não como edges** — decisão chave dos autores. Permite attack paths role-específicos. **Aplicar ao GraphSec**: IAMRole e IAMPolicy já são nós no nosso schema ✓.

#### Algoritmos de análise de grafo (implementar em `graph/paths.py`)

| Algoritmo | O que revela | Query/Uso no GraphSec |
|-----------|-------------|----------------------|
| **Closeness Centrality** | Nós com menor distância média a todos os outros → entidades mais poderosas | Identificar roles/users mais privilegiados do ambiente |
| **Degree Centrality** | Nós com mais edges (in+out) → entidades mais conectadas | Roles com mais permissões, resources mais acessados |
| **Shortest Path** | Caminho mais curto de A→B | Attack path mínimo internet→dado sensível |
| **Chokepoint Analysis** | Edges mais próximas do alvo que, se removidas, cortam mais paths | Priorização de remediação: "remova ESTA permissão para cortar X% dos paths" |
| **% de alcance** | % de users que alcançam um alvo | "62% dos users chegam ao admin" → métrica de risco |

#### Análise de impacto de remediação (diferencial do GraphSec)

O paper mede: "se eu remover edge X, quantos users perdem acesso ao alvo?"
- Exemplo: remover um `CanGrant` de um ServicePrincipal → acesso ao Global Admin caiu de 62% para 54%.
- **Implementar no GraphSec**: simular remoção de edges e recalcular reachability. Isso gera recomendações priorizadas de remediação — "remova esta policy para reduzir risco em X%".

```cypher
-- Medir % de users com path até um alvo (adaptar para AWS)
MATCH (u:IAMUser)
WITH count(u) as userCount
MATCH (target:S3Bucket {bucket_name: 'dados-clientes'})
MATCH p = shortestPath((u:IAMUser)-[*1..6]->(target))
RETURN 100.0 * count(DISTINCT u) / userCount as percent_com_acesso
```

#### Pipeline de ingestão (referência)

O paper usa: `Script (PowerShell) → JSON files → APOC (apoc.load.json + apoc.merge.relationship) → Neo4j`
- **Adaptar**: nossos connectors boto3 → dataclass → `graph/client.py` que usa driver Neo4j direto (MERGE para idempotência).
- APOC `apoc.merge.relationship` é útil para idempotência — considerar usar ao invés de raw Cypher.

#### Attack path multi-stage real (6 passos)

Exemplo do paper (Azure): `User comprometido → ativa role DevOps → acessa pipeline → extrai credencial de ServicePrincipal → ganha AppRoleAssignment.ReadWrite.All → ganha RoleManagement.ReadWrite.Directory → se torna Global Admin`.

**Insight para GraphSec**: attack paths reais cruzam domínios (IAM ↔ Compute ↔ Data). O grafo PRECISA modelar essas pontes:
- EC2 Instance Profile → IAMRole (ponte compute↔identity)
- Lambda Execution Role → IAMRole (ponte serverless↔identity)
- Trust Policy → cross-account assume (ponte entre contas)

#### Lições de visualização

- **"All shortest paths" gera grafo confuso** (Fig. 18 do paper) — não mostrar tudo. Filtrar por: source específico OU target específico OU severidade.
- **Centrality como entrada** para visualização: nodes com alta centralidade ficam maiores/mais destacados no grafo.
- **Treemap** para degree centrality funciona bem como dashboard summary.

#### Oportunidades que o paper identifica como future work (= diferencial GraphSec)

1. **Automatizar descoberta e ranking de attack paths** via algoritmos de grafo → nosso engine de attack paths
2. **Storage, Functions, network components como novos nós** → nosso schema já contempla S3, RDS, Lambda, VPC ✓
3. **Key vault access, app role permissions como edges** → expandir para KMS, Secrets Manager
4. **Validação comparativa contra outras ferramentas** → benchmark vs Cartography

---

### Paper 2: "It Is Time To Steer" (Palma & Angelini, 2023)
**Fonte**: arXiv 2312.16513. Framework escalável para geração e análise de attack graphs via dados progressivos.

#### Problema central que resolve

Attack graphs tradicionais (BFS/DFS completos) são **O(n²) ou pior** — inviáveis para redes grandes. Paper propõe geração **progressiva** via random walks + teste estatístico (KS) para saber quando o AG parcial é "bom o suficiente".

#### StatAG — Geração progressiva (aplicar ao GraphSec)

- **Random walks** a partir do nó atacante exploram o grafo iterativamente
- A cada iteração, compara distribuição de features dos paths encontrados com a do AG completo (estimada) via **teste KS (Kolmogorov-Smirnov)**
- Três patamares de significância:
  - **Early partial** (α=0.10): exploração rápida, bom para dashboards real-time
  - **Mature partial** (α=0.05): tomada de decisão, bom para relatórios
  - **Definitive partial** (α=0.01): confirmatório, bom para compliance
- **Random walk > BFS/DFS** para sampling: BFS e DFS são biased (visitam mesmos edges), random walk é unbiased → converge mais rápido à distribuição real

**Aplicar ao GraphSec**: para ambientes grandes (>1000 nós), implementar geração progressiva ao invés de enumerar todos os paths. O chat LLM pode rodar em "early partial" para respostas rápidas; relatórios de compliance usam "definitive partial".

#### SteerAG — Steering por query (diferencial forte)

- Treina **decision trees** sobre features dos attack paths já encontrados
- Extrai **regras de steering** (intervalos de features de vulnerabilidades) que direcionam a geração para paths relevantes à query do analista
- Resultado: **recall ~0.95 com apenas 11% da execução** (250 iterações vs 2300 completas)
- Sem steering, recall era ~0.2 no mesmo ponto

**Aplicar ao GraphSec**: quando o analista pergunta "quais paths chegam ao S3 dados-clientes?", o sistema pode priorizar a geração de paths que terminam nesse alvo, ao invés de gerar tudo. Integrar com o chat LLM: a query em linguagem natural vira parâmetros de steering.

#### 7 Queries-padrão de análise (implementar como presets no GraphSec)

| Query | O que busca | Uso no GraphSec |
|-------|------------|-----------------|
| **Q1** Shortest paths risk | Paths mais curtos ponderados por risco | "Qual o path mais rápido até meu dado sensível?" |
| **Q2** Max impact | Paths com maior impacto (CIA do alvo) | "Se comprometido, qual o pior cenário?" |
| **Q3** Max likelihood | Paths mais prováveis de serem explorados | "Onde atacantes provavelmente vão atacar?" |
| **Q4** Max risk | Paths com maior risco (likelihood × impact) | Priorização geral de remediação |
| **Q5** Black swan | Alto impacto + baixa probabilidade | Cenários catastróficos mas improváveis — compliance |
| **Q6** Gray swan | Baixo impacto + alta probabilidade | Ataques rotineiros — operação do dia-a-dia |
| **Q7** Priorização por risco | Ranking geral de paths | Dashboard executivo / CISO |

#### Modelo de risco CVSS (implementar em `graph/risk.py`)

```python
# Exploitability (por vulnerabilidade) — CVSS 3.1
def exploitability(vuln) -> float:
    return round_up(AV * AC * PR * UI)  # métricas CVSS exploitability

# Likelihood de um attack path (normalizado)
def likelihood(attack_path) -> float:
    inv_sum = sum(1.0 / exploitability(v) for v in attack_path.vulns)
    return normalize_0_1(inv_sum)

# Impact (último nó do path) — CVSS 3.1
def impact(attack_path) -> float:
    un = attack_path.target_node
    return 1 - ((1 - un.C) * (1 - un.I) * (1 - un.A))

# Risk = likelihood × impact
def risk(attack_path) -> float:
    return likelihood(attack_path) * impact(attack_path)
```

**Adaptação para cloud**: no GraphSec não temos CVEs tradicionais, mas podemos mapear:
- `AV` (Attack Vector) → rede interna vs internet-facing
- `AC` (Attack Complexity) → número de condições para explorar (MFA? IP restrict?)
- `PR` (Privileges Required) → permissões necessárias para o step
- `UI` (User Interaction) → requer ação humana?
- `C/I/A` do alvo → classificação do dado (PII, financeiro, público)

#### Escalabilidade validada

- Case study: **100 hosts × 100 vulnerabilidades** = 10.000 condições
- Trabalhos anteriores não passavam de ~30 hosts
- Framework é **ortogonal** a ferramentas existentes — pode ser adicionado a qualquer AG engine

#### Oportunidades para o GraphSec

1. **Geração progressiva**: fundamental quando o cliente tem centenas de instâncias EC2 + IAM roles
2. **Steering por query LLM**: o chat traduz pergunta → parâmetros de steering → paths mais relevantes primeiro
3. **Patamares de significância**: UX diferenciada — "resultado rápido (exploratório)" vs "resultado completo (compliance)"
4. **Random walk como default**: substituir BFS/DFS por random walks na enumeração de paths
5. **Graph Neural Networks**: paper sugere como future work para aprender features → considerar para v2+
6. **Combinação de queries**: combinar Q5+Q6 para visão completa (black swans + gray swans)

---

### Paper 3: "Knowledge Graph-Driven Cloud Security Intelligence" (Jones et al., 2025)
**Fonte**: Framework conceitual (não validado empiricamente). Integra attack path reasoning, drift detection preditivo e zero-trust enforcement.

#### Arquitetura de 7 camadas (referência para roadmap GraphSec)

| Camada | Função | Status GraphSec MVP |
|--------|--------|-------------------|
| 1. Data Sources | Multi-cloud telemetry | ✓ AWS (boto3), Azure planned |
| 2. Collection/Normalization | Extração e normalização | ✓ Connectors + schema unificado |
| 3. Temporal Knowledge Graph | Grafo com versionamento temporal | ⬜ Phase 2 — diff de snapshots |
| 4A. Drift Analytics | Detecção de drift de configuração | ⬜ Phase 2 |
| 4B. Attack Reasoning | Análise de attack paths | ✓ Phase 1 core |
| 5. Risk Assessment | Scoring de risco | ✓ Phase 1 (implementar fórmulas) |
| 6. Zero-Trust Enforcement | Decisões de acesso baseadas em risco | ⬜ Phase 3+ |
| 7. Verification/Governance | Feedback loop pós-remediação | ⬜ Phase 2 |

#### Grafo temporal: G_t = (V_t, E_t, A_t) (implementar Phase 2)

Conceito: cada snapshot do grafo é indexado por tempo `t`. Permite:
- **Drift detection**: comparar `G_t` com `G_{t-1}` → detectar mudanças de configuração
- **Análise de tendência**: "esta permissão foi adicionada há 3 dias, por quem?"
- **Compliance temporal**: "quando saímos de compliance?"

**4 tipos de entidade**: Identity, Resource, Security Condition, Control
**6 tipos de edge**: CAN_ACCESS, RUNS_ON, CONNECTED_TO, HAS_VULNERABILITY, EXPOSED_TO, VIOLATES

**Metadata de edge** (adotar no GraphSec):
- `source`: origem do dado (ex: "aws-iam-api", "security-hub")
- `timestamp`: quando coletado
- `validity_interval`: [start, end] — quando a relação é válida
- `confidence`: nível de certeza (1.0 para API direta, <1.0 para inferência)
- `verification_status`: verified | unverified | disputed

#### Drift detection preditivo: D_t = d(x_t, b) (Phase 2)

- `x_t` = configuração observada no tempo t
- `b` = baseline aprovada (golden config)
- **4 estados**: Compliant | Drift detected | Drift predicted | Unknown

**Implementação prática no GraphSec**:
```cypher
-- Detectar drift: edges que existem em G_t mas não em G_{t-1}
MATCH (a)-[r]->(b)
WHERE r.snapshot_id = $current AND NOT EXISTS {
  MATCH (a)-[r2]->(b)
  WHERE r2.snapshot_id = $previous
    AND type(r2) = type(r)
}
RETURN a, type(r) as relacao, b, r.source as origem
```

#### Scoring de risco de attack path: R(P) = C(v_n) · S(P) · Q(P)

- `C(v_n)` = **criticidade do alvo** (asset criticality do último nó)
- `S(P)` = **severidade do path** (baseado nas vulnerabilidades/misconfigs ao longo do caminho)
- `Q(P)` = **qualidade da evidência** (confidence das edges, freshness dos dados)

**Vantagem sobre Paper 2**: inclui quality factor Q(P) — paths baseados em dados stale ou inferidos têm score menor. Implementar no GraphSec: edges coletadas há mais de 24h reduzem Q(P).

#### Zero-trust decision: Z(a) = f(I, R, C, P_s) (Phase 3+)

- `I` = identity risk score (grafo de identidade)
- `R` = resource sensitivity (classificação do ativo)
- `C` = context (horário, localização, device)
- `P_s` = postura de segurança (compliance status)

**5 outcomes**: Allow | Step-up auth | Restrict | Deny/isolate | Escalate

**Aplicação no GraphSec**: mesmo sem enforcement ativo, o scoring pode alimentar recomendações: "este usuário tem risco alto acessando recurso sensível fora do horário → sugerir step-up auth".

#### Riscos de design e controles propostos (adotar)

| Risco | Controle | Prioridade GraphSec |
|-------|----------|-------------------|
| Grafo stale/incompleto | Timestamps, provenance, freshness checks | Alta — MVP |
| False attack paths | Verificar edges críticas, representar incerteza | Alta — MVP |
| Alertas excessivos | Calibrar thresholds de risco, avaliar falsos positivos | Média — Phase 2 |
| Ações automatizadas inseguras | Policy guardrails, approval gates, rollback plans | Baixa — Phase 3 |
| Inconsistências cross-provider | Normalizar schemas preservando semântica por provider | Média — Phase 2 |
| Remediação não verificada | Re-scan para confirmar fix, só fechar finding com evidência | Alta — MVP |

#### Hipóteses testáveis (validar com o GraphSec)

- **H1**: Raciocínio via grafo melhora identificação de attack paths vs findings isolados
- **H2**: Snapshots temporais reduzem tempo para detectar mudanças de segurança
- **H3**: Drift preditivo identifica violações futuras antes do compliance reativo
- **H5**: Provenance + confidence melhoram a proporção de alertas verificáveis

#### Limitações reconhecidas pelo paper

1. Eficácia depende da **qualidade/coverage/freshness** da telemetria cloud
2. Normalização cross-provider pode **perder semântica** se mapeamentos forem broad demais
3. Scores de risco e predições de drift precisam de **calibração com dados representativos**
4. Enforcement automatizado pode causar **service disruption** se estimativas de risco forem imprecisas

#### Oportunidades para o GraphSec

1. **Metadata de edge (confidence + freshness)**: implementar desde o MVP — diferencial vs Cartography que não tem isso
2. **Drift via diff de snapshots**: Phase 2, mas projetar schema com `snapshot_id` desde o início
3. **Quality factor Q(P) no risk scoring**: edges com dados antigos ou inferidos reduzem o score — mais honesto que score estático
4. **Remediation verification loop**: finding só fecha quando re-scan confirma — feature de compliance que CISOs brasileiros precisam (BACEN 4.893)
5. **Explainability**: cada alerta deve ser rastreável até entidades, relações e timestamps no grafo — essencial para auditoria
6. **Risk-based processing**: assets de alta criticidade recebem updates mais frequentes; assets de baixa criticidade ficam em schedule mais lento

---

### Paper 4: "Structuring Security — A Survey of Cybersecurity Ontologies" (Lourenço et al., 2025)
**Fonte**: arXiv 2510.16610. Survey do campo de ontologias de segurança, alinhado à Diretiva NIS 2 + taxonomia JRC. É o mapa do terreno que o GraphSec constrói.

#### Teses do GraphSec validadas pela literatura
- O survey nota que **raciocínio temporal/dinâmico é raro** → o grafo temporal (Paper 3) é diferencial confirmado, não achismo.
- O campo usa majoritariamente OWL + SWRL/SPIN + reasoners (FaCT++, Pellet). Materializar inferência em **Cypher** é a escolha pragmática/performática — manter. Registrar a opção de exportar OWL para verificação formal/interoperabilidade como future work.

#### Padrões reutilizáveis (incorporados na Ontologia)
- **`Control` como meta-classe** (ROSE, construído sobre UFO + a ontologia de risco COVER) → remediação vira "adicionar controle", não só "remover aresta". ✓ incorporado.
- **`Goal`/`Loss`** (TAON goal modeling; COVER loss/value) → terminus com narrativa de negócio. ✓ incorporado.
- **Fase de kill-chain na `ATTACK_EDGE`** (Fronesis, TAON): recon→initial access→…→impact dá arco narrativo ao path. ✓ nos padrões.
- **Decay function na `Activity`** (Vega): atividade recente pesa mais, antiga decai → alimenta Q(P)/freshness. ⬜ implementar no scoring.
- **Activity KG de logs heterogêneos** (Ben-Shimol: serverless cloud → KG unificado + asset criticality) → referência para a meta-classe `Activity`.
- **`CPE` + NIS2/JRC** → ✓ nos padrões.

#### Trabalhos-referência citados (consultar se precisar aprofundar)
Ansarinia (CAPEC/CWE/CVE + SWRL em logs RDF), Fronesis (ATT&CK + Kill Chain), TAON (ciclo APT, FaCT++), Vega (Syslog/CEF live + inferência probabilística + 2500 regras SWRL + decay), ROSE (UFO+COVER; modela threats/vulns/controls/losses/goals), CPARR (case-based reasoning + matriz likelihood-impact + SIEM).

---

### Paper 5: "Ontology-Guided Reverse Thinking (ORT)" (Liu et al., ACL 2025)
**Fonte**: ACL 2025 long.741. Raciocínio LLM sobre a ontologia de um KG. Enriquece o **chat (text-to-Cypher)**, não a estrutura da ontologia.

#### Ideia central (aplicar em `chat/engine.py`)
Parte do **objetivo** da pergunta e raciocina **de trás pra frente** sobre os rótulos da ontologia até as condições conhecidas, podando ramos irrelevantes.
- 3 fases: (1) reconhecer entidades-condição e entidade-alvo; (2) *reverse reasoning* sobre triplos da ontologia — cresce árvore a partir do alvo, poda ramos sem condição, remove ciclos, LLM filtra por relevância; (3) label-paths sobreviventes guiam a query no KG.
- Resultado: Hit@1 89.4 / 72.9 (WebQSP/CWQ) com DeepSeek-v3, supera prompting direto **sem fine-tuning**.

#### Por que casa com o GraphSec
- **Reverse thinking = mindset de attack path**: conhece o crown jewel, trabalha de trás pra frente até a entrada. **Converge com o SteerAG (Paper 2)**, que também enviesa a geração em direção ao alvo.
- **Aplicação concreta**: usar as meta-classes + relações da Ontologia como mapa de rótulos para **restringir** a geração de Cypher → menos alucinação no text-to-Cypher. Upgrade direto do pipeline do chat (combinar com o validator que já existe).

---

*Aguardando mais papers do usuário para adicionar insights.*

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
