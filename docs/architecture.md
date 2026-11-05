# Arquitetura

```
Frontend (React + Cytoscape.js)
      ↓ REST
Backend (FastAPI)
  ├─ /api/graph     → leitura do grafo, attack paths
  ├─ /api/chat      → text-to-Cypher (Claude API)
  ├─ /api/connectors → trigger de sync
  └─ /api/reports   → PDF de compliance
      ↓ Bolt
Neo4j Community
      ↑ sync
Celery Workers (Redis broker)
      ↑ fetch
AWS APIs (boto3): IAM, EC2, S3, RDS, Lambda
```

## Fluxo de ingestão

1. Scheduler ou request HTTP dispara `sync_all()`.
2. Cada connector herda de `BaseConnector`, implementa `get_nodes()` e `get_edges()`.
3. `sync()` da classe base faz MERGE idempotente no Neo4j.

## Fluxo do chat

1. Usuário envia pergunta em `/api/chat/`.
2. `chat/engine.py` monta prompt (schema + few-shots) e chama Claude.
3. `chat/validator.py` recusa qualquer palavra proibida (CREATE/DELETE/etc).
4. Executa em transação READ-ONLY.
5. `chat/formatter.py` reescreve o resultado como resposta natural.
