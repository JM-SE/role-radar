# ADR-0001 — Stack y layout del proyecto

- **Fecha:** 2026-07-31
- **Estado:** Aceptado
- **Decisiones vinculantes:** D1, D2, D7, D8 (sesión de planificación 2026-07-31)

## Contexto

role-radar arranca como un proyecto nuevo basado en el handoff `RoleRadar-Handoff.txt`.
Las decisiones de ingeniería de cimientos deben quedar registradas en el repositorio,
y las fases siguientes deben poder crecer sin rehacer la estructura.

## Decisiones

1. **Nombre del producto:** `role-radar` (D1). Es el valor de `application` que se
   enviará al LLM Broker a partir de Fase 3.
2. **Paquete Python:** `role_radar` bajo layout `src/` (D2, D7):
   `src/role_radar/`. El layout `src/` evita conflictos accidentales de importación
   y facilita el empaquetado.
3. **Logging estructurado:** `structlog` con salida JSON a stdout (D8), campos base
   `timestamp`, `level`, `event`. Los campos de contexto de dominio (`run_id`,
   `job_id`, `source`, `stage`, …) se agregarán cuando exista dominio.

## Consecuencias

- Los módulos de dominio nacerán dentro de `src/role_radar/` cuando tengan
  responsabilidad real; no se crean módulos vacíos por adelantado.
- El layout `src/` implica que el paquete debe instalarse (editable) para ejecutarse;
  `uv sync` lo resuelve.
- El resto del stack (FastAPI, pydantic-settings con prefijo `ROLE_RADAR_`, uv,
  mypy strict, Ruff, pytest) queda fijado en `pyproject.toml` como fuente única
  de verdad.
