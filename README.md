# role-radar

Pipeline personal de búsqueda laboral: colecta, normaliza, deduplica y prioriza
oportunidades de software engineering, con evaluación LLM a través de un broker
externo y notificación por Telegram.

> Aplicación personal (single-user). Documentación de ingeniería y decisiones en
> [docs/adr/](docs/adr/). Especificaciones del producto en el workspace externo
> de IA (`/home/jmse/homelab/ai/projects/role-radar/`).

## Requisitos

- Python >= 3.13
- [uv](https://docs.astral.sh/uv/) (gestor de entorno y dependencias)

## Setup

```bash
uv sync                       # crea .venv e instala dependencias (incluye dev)
cp .env.example .env          # configuración local (opcional en Fase 0)
```

## Comandos

```bash
make sync        # uv sync
make run         # servidor de desarrollo (uvicorn, recarga automática)
make test        # pytest
make lint        # ruff check
make typecheck   # mypy strict
make fmt         # ruff format + ruff check --fix
make check       # lint + typecheck + test
```

## Health check

```bash
uv run uvicorn role_radar.main:app
curl -s localhost:8000/health
# -> {"status": "ok", "version": "0.1.0", "environment": "dev"}
```

## Estructura

```
src/role_radar/     # paquete principal (src layout)
├── config.py       # Settings vía pydantic-settings (prefijo ROLE_RADAR_)
├── logging.py      # structlog, JSON a stdout
├── main.py         # create_app() + instancia app
└── api/            # routers HTTP (hoy: GET /health)
tests/              # pytest (unit)
docs/adr/           # Registro de Decisiones de Arquitectura
```

## Nota para fases futuras

- El campo `application` que role-radar enviará al LLM Broker (desde Fase 3)
  será **`"role-radar"`** (decisión D1). No implementado aún.
