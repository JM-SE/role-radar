# RoleRadar

Stop skimming job boards. Get one daily digest worth opening.

RoleRadar is a profile-first personal job-search pipeline. It transiently
fetches broad source responses, persists only postings with explicit compatible
title, work-mode, region, hard-constraint, and safe-link evidence, then sends
every newly eligible unseen job through Telegram.

It is a single-user application: one server, one worker, one SQLite database.
Historical jobs remain a review-only calibration backlog.

## Why it exists

Manually reviewing job portals means opening irrelevant postings, missing
geo restrictions, re-reading duplicates, and comparing tech stacks by hand.
RoleRadar turns that into a persistent, observable pipeline:

- **Collect once, from real sources.** Greenhouse and Lever ATS collectors,
  plus a free-source path and a mailbox path for LinkedIn alert emails. No
  authenticated LinkedIn scraping, ever.
- **One canonical job.** Multi-signal deduplication (source + external ID,
  normalized URLs, company + title + location, description fingerprint) keeps
  a single canonical posting with all its source references.
- **LLM for facts, code for numbers.** A structured-extraction model pulls
  facts (seniority, remote policy, skills, languages, salary) with Pydantic
  validation and evidence — but the score is always computed by seven pure,
  debuggable code signals. The model never invents a compatibility number.
- **Deep evaluation enriches; it does not gate.** At most ten jobs per run may
  receive optional model reasoning. Every eligible job remains deliverable with
  its preliminary score when no deep result exists.
- **All eligible results, once.** Telegram messages are deterministic,
  multipart batches of at most five items. Global recipient/job reservations
  prevent duplicate delivery across restarts and later runs.

## How it works

```text
collect → normalize → deduplicate → extract → score → deep-evaluate → notify
Greenhouse   cleanup    multi-signal   LLM +      7 pure     reasoning   Telegram
Lever/ATS    + IDs      canonical job  Pydantic   signals    model       daily
free/mailbox               │           evidence    code-only  top/ambiguous digest
                           ▼
                    SQLite (WAL, single writer)
```

1. A **scheduled run** (`role-radar run create --reason scheduled`) is the
   only launch path that enables discovery and Telegram. Manual/custom reasons
   do neither.
2. **Collection** fetches broadly but applies profile intake before
   deduplication or persistence; source stats distinguish structural rejects
   from profile rejections.
3. **Extraction and scoring** establish immutable structured facts and
   product eligibility for each admitted job.
4. **Deep evaluation** is optional enrichment, capped at ten jobs.
5. **Notify** reserves and delivers every eligible unseen current-run job in
   ordered multipart Telegram batches. Historical reprocessed jobs are never
   sent.

The LLM is consumed through an external broker service (see
[LLM Broker](https://github.com/JM-SE/llm-broker)): RoleRadar sends
`workload="role-radar"` plus a capability name and never manages models,
queues, or GPU state itself. A `fake` provider is the default, so the whole
pipeline runs and tests with no network and no model.

## Quick start

Requirements: Python >= 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
git clone <your-copy-of-the-repo> && cd role-radar
uv sync                       # create .venv, install dependencies (incl. dev)
cp .env.example .env          # local config (fake LLM provider by default)
make migrate                  # create the SQLite database (Alembic)
make seed-boards              # load curated Greenhouse boards fixture
```

Run the dev server and check health (`make run` uses uvicorn's default
port 8000):

```bash
make run
curl -s localhost:8000/health
# -> {"status": "ok", "version": "0.1.0", "environment": "dev"}
```

In the systemd deployment the port is mandatory in the `EnvironmentFile`
(`ROLE_RADAR_API_PORT`, operational example `8010`); the unit binds
`uvicorn role_radar.main:app --host 127.0.0.1 --port ${ROLE_RADAR_API_PORT}`.

Trigger a scheduled run and process it with the worker (scheduled runs are
the only path that enables discovery plus Telegram):

```bash
uv run role-radar run create --reason scheduled
uv run role-radar worker
uv run role-radar run list
```

Browse results:

```bash
curl -s "localhost:8000/jobs?limit=5"
```

Full verification: `make check` (ruff + mypy strict + pytest).

## Configuration

All settings use the `ROLE_RADAR_` prefix (`src/role_radar/config.py`).
`ROLE_RADAR_DATABASE_URL` from the process environment is authoritative; the
working-directory default is `sqlite:///./data/role-radar.db`. Defaults use
fake LLM providers and disabled notifications.

| Area | Key variables |
|---|---|
| Database | `ROLE_RADAR_DATABASE_URL` |
| LLM (fake default) | `ROLE_RADAR_LLM_PROVIDER=fake`, `ROLE_RADAR_DEEP_EVALUATION_PROVIDER=fake` |
| LLM (real broker) | `ROLE_RADAR_BROKER_URL`, `ROLE_RADAR_BROKER_TOKEN`, `ROLE_RADAR_BROKER_WORKLOAD=role-radar` |
| Telegram | `ROLE_RADAR_TELEGRAM_BOT_TOKEN`, recipient/chat settings |

`feedback review --scope reprocessed --limit 20` presents deterministic
historical calibration evidence. Labels are evidence only: they never
automatically alter profile intake, ranking, discovery, or delivery policy.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/profiles` | List active candidate profiles |
| `POST` | `/profiles` | Create a candidate profile (manual seed) |
| `GET` | `/profiles/{id}` | Profile detail |
| `GET` | `/jobs?status=&company=&limit=&offset=` | List canonical jobs |
| `GET` | `/jobs/{id}` | Job detail + source references |
| `POST` | `/runs` | Create a run intent (`202`); the worker executes it |
| `GET` | `/runs` | List runs |
| `GET` | `/runs/{id}` | Run detail + stats |
| `GET` | `/sources`, `/sources/{id}` | Read-only source catalog |

The worker is the pipeline's only writer. Direct `collect` / `extract` /
`score` commands exist for dev and tests but are blocked unless
`ROLE_RADAR_ALLOW_DIRECT_PIPELINE_WRITES=true` (never in production).

## CLI

```bash
make sync        # uv sync
make run         # dev server (uvicorn, auto-reload)
make migrate     # alembic upgrade head
make test        # pytest
make lint        # ruff check
make typecheck   # mypy strict
make fmt         # ruff format + ruff check --fix
make check       # lint + typecheck + test
make seed-boards # load curated Greenhouse boards fixture
make collect     # manual in-process collection (requires --profile-id)
uv run role-radar run create --reason scheduled
uv run role-radar run list
uv run role-radar run show --run-id UUID
uv run role-radar worker
```

```bash
uv run role-radar feedback review --run RUN_ID --scope reprocessed --limit 20
uv run role-radar feedback summary --run RUN_ID --scope reprocessed
```

`role-radar --help` lists the full surface, including `source` catalog
management (local-only mutations with revision checks; creation disabled),
`discover-boards` (proposals only, never auto-enabled), and offline
`evaluation` / `acquisition` harnesses.

## Source catalog

Sources are a local control plane, not an open input: mutations require the
current revision, creation is always disabled, and the HTTP API is read-only
(`GET /source-types`, `/sources`, `/sources/{id}` with the public Greenhouse
projection only). No arbitrary URLs, credentials, discovery, or dynamic
adapters over HTTP.

## Stack and layout

- **Python 3.13**, FastAPI, Pydantic v2, SQLAlchemy 2 + Alembic, SQLite
  (WAL, foreign keys, single-writer worker), httpx, structlog (JSON logs).
- **Tooling:** `uv`, ruff (lint + format), mypy strict, pytest (+ hypothesis
  for property tests), `Makefile` as the command surface.
- **Deploy:** systemd service + timer invoking the CLI (`deploy/systemd/`).
  `ROLE_RADAR_API_PORT` is required in the production `EnvironmentFile`; the
  operational example uses `8010` (port `8000` belongs to another app and is
  not RoleRadar's).

```text
src/role_radar/
├── config.py          # Settings via pydantic-settings (ROLE_RADAR_*)
├── main.py            # create_app() + app instance
├── api/               # HTTP routers (health, profiles, jobs, runs, sources)
├── cli/               # role-radar commands (runs, worker, sources, eval)
├── worker/            # Pipeline sequencer + runner (sole writer)
├── services/          # per-stage orchestration (collection … notifications)
├── collectors/        # Greenhouse, Lever, free-source, mailbox producers
├── discovery/         # board proposals, offline by default
├── normalization/     # pure text/URL/company transforms
├── dedup/             # multi-signal dedup
├── extraction/        # versioned prompts + schemas + validation
├── matching/          # hard filters + seven deterministic signals
├── deep_evaluation/   # shortlist queue + reasoning-model evaluation
├── broker/            # LLMProvider protocol + broker/fake clients
├── notifications/     # digest selection + deterministic Telegram renderer
├── repositories/      # persistence layer (no business rules)
├── db/                # engine, session, ORM models, fixture seeds
└── domain/            # state machines and enums
alembic/               # schema migrations
fixtures/              # seed JSON (profile + canonical job)
tests/                 # pytest (unit + integration)
docs/adr/              # architecture decision records
deploy/systemd/        # production service + timer
```

Engineering decisions live in [docs/adr/](docs/adr/); integrations and
operations notes in `docs/integrations/` and `docs/operations/`.

## Roadmap and non-goals

Built and working: ATS collection, normalization, dedup, structured
extraction with evidence, deterministic scoring, persistent worker, source
catalog, Telegram digest.

Deliberately out of scope: auto-applying to jobs, CV generation, RAG/vector
search, agent frameworks, Celery/Redis/Kafka, multi-worker distribution,
authenticated LinkedIn scraping or any login automation, and storing model
chain-of-thought. A larger reasoning model is only adopted if a controlled
evaluation proves the current one fails at ranking — see the evaluation
harnesses under `src/role_radar/evaluation/`.

## Notes for operators

- Every run ends with a summary (`collected`, `new_jobs`, `duplicates`,
  `prefiltered`, `profile_rejected`, `extracted`, `deep_evaluated`,
  `notified`, `failed`) for observability.
- Logs are structured (`run_id`, `job_id`, `source`, `stage`, `status`) and
  never contain PII, tokens, credentials, or full model payloads.
