# ADR-0004 — Integración con LLM Broker

## Estado

Aceptada para Fase 3.

## Decisión

RoleRadar usa el task protocol v0.1.0 del LLM Broker mediante un adapter async y
envía exclusivamente `workload="role-radar"` y
`capability="structured-extraction"`. No selecciona modelo, backend, provider,
priority ni usa el parámetro histórico `application`.

La integración exige Bearer, `Idempotency-Key` determinística y
`Prefer: wait=N`. Un timeout de submit se reconcilia con el mismo body y key,
con un número acotado de submits; un timeout de polling no cancela la task
durable. Solo la capa de contenido puede hacer un correctivo, una vez.

`FakeLLMProvider` es el default y todos los tests son offline. El broker real
requiere configuración explícita. `model_identifier` es nullable y el broker
no lo proporciona. Se persisten únicamente capability, task id, finish reason,
contadores de usage y payload validado.

## Seguridad y límites

El token vive en `SecretStr`; la key de idempotencia, prompts, schemas, output
inválido y cuerpos HTTP no se escriben en logs, CLI ni base de datos. `trace`
solo admite metadata acotada (`job_id`, `extraction_id`, versiones). Los errores
HTTP se reducen a una allowlist RFC7807 segura.

## Consecuencias

El operador debe provisionar la policy workload/capability y sus credentials
fuera de RoleRadar. `structured-extraction` debe mapearse al backend elegido y
su política puede exigir structured output. El rollback operativo es
`ROLE_RADAR_LLM_PROVIDER=fake`. Este ADR no modifica ni requiere cambios en el
repositorio `llm-broker`.
