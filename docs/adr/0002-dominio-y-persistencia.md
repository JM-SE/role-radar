# ADR-0002 — Dominio y persistencia (Fase 1)

- **Fecha:** 2026-08-01
- **Estado:** Aceptado
- **Decisiones vinculantes:** D12, D13, D14, D15, D16 (sesión de planificación 2026-08-01)

## Contexto

Fase 1 introduce el modelo de datos (6 tablas), los repositorios de persistencia,
la API mínima de consulta y el seed de fixtures. El pipeline (collect → normalize →
dedup → extract → score → deep eval → notify) se implementa en fases posteriores,
pero las máquinas de estado y las tablas sobre las que se apoyará deben quedar
fijadas ahora.

## Decisiones

1. **`JobSearchRunStatus` tiene exactamente 10 estados** (D12):
   `pending, collecting, normalizing, extracting, scoring, deep_evaluating,
   notifying, completed, failed, cancelled`. No existe un 11.º estado: la
   deduplicación y el prefiltrado son sub-pasos del pipeline, representados como
   `RunJobStage` (`deduplicated`, `prefiltered`) y contadores en
   `JobSearchRun.stats_json` (p. ej. `duplicates`, `prefiltered`).
2. **`JobStatus` tiene 4 estados** (D13): `new, active, expired, archived`.
3. **`RunJob` nace en la migración inicial** (D14) como journal por etapa de cada
   oferta dentro de una ejecución: `RunJobStage` (8 etapas) y `RunJobStatus`
   (`pending, in_progress, succeeded, failed, skipped`), con unicidad compuesta
   `(run_id, job_id, stage)`. Sin lógica de worker en F1.
4. **API mínima de Fase 1** (D15): `GET /jobs`, `GET /jobs/{id}`,
   `POST /profiles`, `GET /profiles`, `GET /profiles/{id}` + seed de fixtures.
   Sin `POST /runs` ni endpoints de `/sources`.
5. **SQLAlchemy 2.0 sincrónico sobre SQLite** (D16): `Mapped[]`/`mapped_column`,
   enums almacenados como texto (`native_enum=False` con los valores del StrEnum),
   JSON portable de SQLAlchemy, IDs UUID `str(uuid4())` con guiones y timestamps
   UTC timezone-aware.
6. **Enums únicos en `domain/enums.py`**: ni `models.py` ni los schemas los
   redefinen; los modelos los referencian y se almacenan por valor.

## Consecuencias

- **Política de escritura SQLite (single-writer):** en régimen de producción el
  único escritor del pipeline (Job, JobSourceReference, transiciones de
  JobSearchRun, RunJob, extracciones, scores…) será el Worker (Fase 5+). La API
  escribe perfiles (y en el futuro feedback e intenciones de run). La escritura
  de jobs vía seed/tests en F1 es una **excepción explícita**, no un patrón de
  producción (no se expone `POST /jobs`).
- **Pragmas SQLite** (WAL, `foreign_keys=ON`, `busy_timeout=5000`) aplicados por
  listener de conexión en `db/engine.py`; los repositorios son agnósticos del
  dialecto (sin SQL crudo específico).
- **Migraciones con Alembic**: la migración inicial `phase01_initial` crea las 6
  tablas. `metadata.create_all` solo se usa en tests (DB in-memory); la API no
  crea esquema en runtime (el lifecycle solo asegura el directorio de la DB).
- **Patrón repositorio**: `repositories/*` hacen `add + flush` (los IDs y
  defaults se materializan) pero no `commit`; el commit lo gestiona el orquestador
  (`get_session` en la API, la sesión del test/seed). Los routers son thin y no
  abren engines.
- **Tests** usan SQLite in-memory con `StaticPool` y `create_all`, con override
  de `get_session` en `conftest.py` (mismo contrato de commit que producción).

## Referencias

- Espec de producto y fase: workspace externo de IA
  (`/home/jmse/homelab/ai/projects/role-radar/`), decisión log
  `2026-08-01-phase-01-domain-persistence-decisions.md`.
- Handoff §10 (modelo de datos) y §21 (DoD).
