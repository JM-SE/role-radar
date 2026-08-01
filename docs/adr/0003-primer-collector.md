# ADR-0003 — Primer collector Greenhouse

## Estado

Aceptada para Fase 2.

## Contexto

Fase 2 necesita cerrar el camino `collector → normalización → deduplicación →
base de datos` sin introducir todavía LLM, worker ni broker. Greenhouse expone
un listado JSON y, cuando el listado no incluye contenido, un detalle HTML.

## Decisiones

- `GreenhouseCollector` es asíncrono y usa `httpx.AsyncClient`; no conoce la
  base de datos ni la normalización.
- Los repositorios siguen siendo síncronos y solo hacen `add + flush`; el
  caller es responsable del `commit`.
- `CollectionService` orquesta el pipeline y tampoco hace commit. La CLI abre
  la sesión, ejecuta `asyncio.run`, hace `commit` o `rollback` y cierra la
  sesión.
- Los boards son filas `Source` de tipo `greenhouse`, con `board_token` en
  `configuration`. `seed-boards` puede activar únicamente lo que diga el
  fixture; `discover-boards` siempre propone `enabled=False`.
- El path `collect` no invoca ningún `SearchProvider`. El proveedor por defecto
  de discovery es `NullSearchProvider`; no hay cliente Tavily en esta fase.
- La deduplicación usa las señales ordenadas D6 y un hash SHA-256 del texto de
  descripción normalizado. No hay fuzzy matching.

## Consecuencias

La CLI F2 es un escritor en proceso único. Esta es una excepción explícita y
temporal (D21): el régimen de producción con worker único escritor se
introducirá en F5. Los tests HTTP usan `httpx.MockTransport`, por lo que no
dependen de Greenhouse ni de Tavily reales.
