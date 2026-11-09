# Blast Radius Engine

> "Este identity foi comprometido — o que ele alcança?"

Dado um identity comprometido (IAMUser, IAMRole ou EC2Instance com instance
profile), o Blast Radius Engine computa **em segundos** tudo que ele alcança no
grafo: recursos, dados sensíveis, roles escaláveis via privilege escalation, e o
caminho exato até cada um. É o primeiro comando de um incident response real —
o analista precisa da resposta na hora, não em horas de análise manual.

## Como funciona

A travessia parte do identity seguindo **apenas arestas de privilégio** —
`CAN_ASSUME`, `HAS_POLICY`, `ALLOWS` (constante `PRIV_EDGES`) — e não o grafo
inteiro. Isso evita ruído (VPC, subnets, SGs) e mantém o resultado em
alcance-de-permissão real.

```
IAMUser/IAMRole/EC2  --CAN_ASSUME-->  IAMRole  --HAS_POLICY-->  IAMPolicy  --ALLOWS-->  S3/RDS/Lambda
```

Pipeline (`BlastRadiusEngine.compute`):

1. **Resolve** o identity por `uid`, `arn`, `instance_id`, `user_name` ou `role_name`.
2. **Cache**: `blast:{uid}:{graph_version}:{max_depth}` no Redis. A versão do grafo
   (`graph:last_sync_ts`) é bumpada ao fim de todo `persist_graph`, então qualquer
   sync de connector invalida o cache automaticamente. TTL de 30 min.
3. **Recursos alcançáveis** (`shortestPath`, dedup por recurso, `*1..max_depth`).
4. **Escalação**: roles alcançáveis e a cadeia de assume até cada uma.
5. **Subgrafo do blast** para renderizar no frontend (`graph_nodes` + `graph_edges`
   com criticidade por nó).
6. **Classificação** de criticidade e de dados, e **summary** em linguagem natural
   (template string — sem LLM: mais rápido, previsível e não falha).

### Classificação

Os `Finding`/`STORES_DATA` podem não estar populados (mesma premissa do
text-to-Cypher), então **dados sensíveis são classificados pelo NOME do recurso**:

| Função | Regra |
|--------|-------|
| `classify_data` | nome contém `pii/pessoal/cpf/cliente` → **pii**; `financ/pagamento/cartão/credit` → **financial**; `public` em bucket → **public** |
| `classify_criticality` | pii/financial → **critical**; S3/RDS → **high**; Lambda → **medium**; EC2 com IP público → **medium**; senão **low** |

## API

Todas as rotas são `GET` (blast radius é leitura; permite cache no browser).

| Rota | Descrição |
|------|-----------|
| `GET /api/blast-radius/{ident}` | Relatório completo (`BlastRadiusReport`). `ident` = uid, ARN, instance_id ou nome. Query params: `max_depth=8`, `include_indirect=true`. |
| `GET /api/blast-radius/{ident}/graph` | Só o subgrafo `{nodes, edges}` para o Cytoscape.js. |
| `GET /api/blast-radius/{ident}/compare/{other}` | Overlap e diferença de alcance entre dois identities (priorizar proteção). |
| `GET /api/blast-radius/ranking?limit=20` | Top identities por tamanho do blast radius — o "quem proteger primeiro", **antes** do incidente. Cacheado 1h. |

404 se o identity não existe. Resultado vem com `partial: true` se a computação
passar de 2s (não bloqueia a API).

### Exemplo de resposta

```json
{
  "compromised_identity": "arn:aws:iam::...:role/ec2-role",
  "compromised_type": "EC2Instance",
  "computation_time_ms": 266,
  "total_resources_reached": 1,
  "total_roles_escalatable": 1,
  "pii_data_exposed": true,
  "max_depth_reached": 3,
  "resources": [
    {
      "uid": "...-dados-pii-...",
      "resource_type": "S3Bucket",
      "hops": 3,
      "path_via": ["CAN_ASSUME", "HAS_POLICY", "ALLOWS"],
      "criticality": "critical",
      "data_classification": "pii"
    }
  ],
  "summary": "... alcanca 1 buckets S3. incluindo dados sensiveis (PII/financeiro). pode assumir 1 role(s) adicional(is). em ate 3 hops."
}
```

## Frontend

- **Trigger**: clique com **botão direito** num nó de identity no grafo
  (IAMUser/IAMRole/EC2Instance) → computa e abre o painel. Também respondível pelo
  chat (ver abaixo).
- **Visualização** (`overlay/blastRender.ts`): o nó comprometido fica vermelho e
  destacado; os recursos alcançados são revelados **camada a camada por hop**
  (efeito de onda, 300ms entre camadas), coloridos por criticidade; **tudo fora do
  blast fica esmaecido** (opacity 0.12). O layout **nunca** é re-rodado — cada nó é
  posicionado individualmente.
- **Painel** (`components/BlastRadius.tsx`): métricas de impacto, lista de recursos
  (clique → centraliza e pulsa o nó no grafo), cadeia de escalação, exportar JSON e
  uma linha de "contenção" (impacto de revogar as credenciais).

Classes Cytoscape: `.blast-origin`, `.blast-reached`, `.blast-visible`,
`.blast-{critical,high,medium,low}`, `.blast-edge`, `.blast-dimmed`.

## Chat

O `chat/engine.py` roteia perguntas de blast radius **antes** do text-to-Cypher
(resposta determinística, sem LLM). Gatilhos: `blast radius <id>`,
`o que <id> alcança`, `se <id> for comprometido`, `token do <id> vazou`,
`impacto do <id>`. Resolve o identity no grafo; se não resolver, cai no fluxo normal.
A resposta traz o summary + recomendação de contenção e os nós do blast para
highlight no grafo.

## Performance

- `shortestPath` do Neo4j é O(n+m) por par — rápido para grafos < 10k nós.
- Travessia limitada a `*1..8` hops (acima disso é teórico demais para IR).
- Índices criados em `apply_constraints()` (`schema.py` → `INDEXES`):
  `IAMUser.arn/user_name`, `IAMRole.arn/role_name`, `S3Bucket.bucket_name`.
- Cache Redis invalidado no sync; ranking em cache de 1h.
- **Target: < 2s** para qualquer blast radius (no lab, ~250–350ms).

## Limitações / decisões

- **Containment** ("simular contenção") hoje é informativo (mostra o impacto de
  revogar). Não há `RemediationEngine` neste codebase ainda — quando existir, o
  botão deve chamá-lo com a aresta de entrada do identity como candidata à remoção.
- **Ranking** roda on-demand com cache de 1h. Para grafos grandes, migrar para uma
  Celery task agendada (1x por sync) e só ler o cache aqui.
- Policies com `Resource: "*"` (wildcard) não geram arestas `ALLOWS` a recursos
  específicos, então um identity com permissão curinga aparece com poucos recursos
  concretos — é uma limitação do connector (extração de recursos), não do engine.

## Testes

- `backend/tests/test_blast_radius.py`: classificação, summary, cache hit,
  invalidação por versão, identity inexistente, e integração contra o grafo vivo
  (guardada por disponibilidade do Neo4j, com assert de `< 2s`).
- `frontend/src/overlay/blastRender.test.ts`: origem marcada, nós adicionados,
  revelação por hop (fake timers), esmaecimento e cleanup.
