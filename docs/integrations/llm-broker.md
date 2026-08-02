# Integración operativa con LLM Broker

Esta integración es opcional en Fase 3. El default local es `fake`, por lo que
no requiere red.

## Provisionamiento

El operador debe garantizar que:

- existe la capability `structured-extraction` y está mapeada al backend/modelo
  elegido por la policy;
- el backend declara structured output si la policy lo exige;
- existe la workload policy `role-radar` con permiso para esa capability;
- existe una credential cliente con grant a esa workload.

## Configuración

Configurar mediante variables `ROLE_RADAR_LLM_PROVIDER`, `ROLE_RADAR_BROKER_URL`,
`ROLE_RADAR_BROKER_TOKEN`, `ROLE_RADAR_BROKER_WORKLOAD` y
`ROLE_RADAR_BROKER_STRUCTURED_EXTRACTION_CAPABILITY`. Los límites de espera,
polling y reconciliation también se pueden ajustar con las variables del
`.env.example`.

La smoke test contra un entorno real es opcional y está fuera del DoD de Fase 3.
Los tests del proyecto usan Fake o `httpx.MockTransport`.

## Rollback y compatibilidad

Para volver a ejecución offline, usar `ROLE_RADAR_LLM_PROVIDER=fake`. Los
ejemplos `default`/`instruct` de documentación del broker son ejemplos, no un
contrato obligatorio de RoleRadar. No se envía `application`: la integración
usa workload y capability según D22.
