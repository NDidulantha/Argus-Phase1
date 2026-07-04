# ARGUS — AI Threat Hunting Platform

Multi-tenant, AI-assisted threat hunting platform for MSSP SOCs.
Phase 1: platform foundation (API service, PostgreSQL + pgvector, structured
logging, tests, CI). No AI components yet by design — see docs/adr/.

## Quickstart (WSL2 Ubuntu)

```bash
uv sync                                  # create .venv and install from uv.lock
cp .env.example .env
docker compose up -d db                  # start Postgres (pgvector)
uv run uvicorn argus.main:app --reload     # run the API locally
```

Verify:

```bash
curl localhost:8000/api/v1/health/live   # {"status":"alive"}
curl localhost:8000/api/v1/health/ready  # {"status":"ready"} once db is up
```

Run everything in containers instead:

```bash
docker compose up --build
```

## Development

```bash
uv run pytest -q          # tests
uv run ruff check .       # lint
```

## Architecture

- `src/argus/api/` — HTTP layer (FastAPI routers, request/response models)
- `src/argus/domain/` — business logic; framework-free
- `src/argus/infrastructure/` — database, external services
- `src/argus/connectors/` — vendor integrations (Wazuh, Cortex XDR, ...)
- `docs/adr/` — architecture decision records

Dependency rule: `api -> domain <- infrastructure`. Nothing imports "up".
