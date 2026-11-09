# GraphSec

Plataforma open-core de security graph. Veja [CLAUDE.md](CLAUDE.md) para a especificação completa.

## Quick start

```bash
cp .env.example .env
# edite .env: NEO4J_PASSWORD, ANTHROPIC_API_KEY, AWS_*

docker compose up -d
```

- Frontend: http://localhost:5173
- Backend: http://localhost:8000 (docs em `/docs`)
- Neo4j Browser: http://localhost:7474 (bolt://localhost:7687)

## Dev local

```bash
# backend
cd backend
pip install -e ".[dev]"
uvicorn graphsec.main:app --reload

# frontend
cd frontend
npm install
npm run dev
```

## Sync inicial

```bash
cd backend
python -m graphsec.connectors.aws.sync
```

## Testes

```bash
cd backend && pytest -v
```

## Estrutura

Ver [docs/architecture.md](docs/architecture.md), [docs/schema.md](docs/schema.md),
[docs/few-shot-examples.md](docs/few-shot-examples.md).
