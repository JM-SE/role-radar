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
make migrate                  # crea la base SQLite (Alembic, Fase 1+)
```

## Comandos

```bash
make sync        # uv sync
make run         # servidor de desarrollo (uvicorn, recarga automática)
make migrate     # alembic upgrade head
make test        # pytest
make lint        # ruff check
make typecheck   # mypy strict
make fmt         # ruff format + ruff check --fix
make check       # lint + typecheck + test
make seed-boards # carga boards Greenhouse del fixture
make collect     # ejecuta una colección manual
uv run role-radar extract --job-id UUID
uv run role-radar extract-pending --limit 10
```

## Health check

```bash
uv run uvicorn role_radar.main:app
curl -s localhost:8000/health
# -> {"status": "ok", "version": "0.1.0", "environment": "dev"}
```

## API (Fase 1–2)

| Método | Path | Descripción |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/profiles` | Crea un perfil candidato (semilla manual, D3) |
| `GET` | `/profiles` | Lista perfiles activos |
| `GET` | `/profiles/{id}` | Detalle de un perfil |
| `GET` | `/jobs?status=&company=&limit=&offset=` | Lista ofertas canónicas |
| `GET` | `/jobs/{id}` | Detalle de oferta + referencias de fuente |

Sin `POST /jobs` ni `POST /runs`: la escritura de ofertas de Fase 2 ocurre solo
en la CLI `collect` (ADR-0003). No se usa Tavily para colectar ofertas.

## Estructura

```
src/role_radar/     # paquete principal (src layout)
├── config.py       # Settings vía pydantic-settings (prefijo ROLE_RADAR_)
├── logging.py      # structlog, JSON a stdout
├── main.py         # create_app() + instancia app
├── domain/         # enums de dominio (máquinas de estado, D12–D14)
├── db/             # engine, session, modelos ORM, seed de fixtures
├── repositories/   # capa de persistencia (I/O, sin reglas de negocio)
├── collectors/     # collectors async (Greenhouse en Fase 2)
├── normalization/   # transformaciones puras
├── dedup/           # señales D6
├── services/        # orquestación de colección
├── discovery/       # propuestas de boards, offline por defecto
└── cli/             # role-radar collect/seed-boards/discover-boards
└── api/            # routers HTTP (health, profiles, jobs) + schemas
alembic/            # migraciones de esquema
fixtures/           # seed JSON (perfil + oferta canónica)
tests/              # pytest (unit + api)
docs/adr/           # Registro de Decisiones de Arquitectura
```

## Nota para fases futuras

- El campo histórico `application` que aparecía en ejemplos previos del broker está
  **SUPERSEDED** por D22: RoleRadar envía `workload="role-radar"` y
  `capability="structured-extraction"`; `application` no existe en el contrato real.
