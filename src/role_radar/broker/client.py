"""Cliente async del task protocol v0.1.0 del LLM Broker."""

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Mapping
from typing import Any, Literal

import httpx

from role_radar.broker.protocols import (
    LLMProvider,
    ProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)
from role_radar.execution_budget import (
    CanaryAmbiguousAttempt,
    CanaryDeferred,
    reserve_logical_call,
    reserve_network_attempt,
    settle_network_attempt,
)
from role_radar.extraction.schema import assert_broker_compatible

_GENERATION_KEYS = {"max_tokens", "temperature", "top_p", "top_k", "min_p", "seed", "stop"}
_TRACE_KEYS = {
    "job_id",
    "extraction_id",
    "deep_evaluation_id",
    "score_id",
    "prompt_version",
    "schema_version",
}
_ERROR_CLASSES = {
    "client_invalid",
    "policy_rejected",
    "backend_rejected",
    "output_invalid",
    "transient_unsent",
    "transient_safe",
    "indeterminate",
    "internal",
}
_FINISH_REASONS = {"stop", "length", "content_filter", "unknown"}


def derive_idempotency_key(
    *,
    job_id: str,
    input_hash: str,
    prompt_version: str,
    schema_version: str,
    corrective_attempt: Literal[0, 1],
) -> str:
    """Deriva la key normativa sin incluir secretos ni selección de modelo."""
    values = (job_id, input_hash, prompt_version, schema_version, str(corrective_attempt))
    encoded = "\x1f".join(f"{len(value)}:{value}" for value in values).encode("utf-8")
    return f"rr-extract-{hashlib.sha256(encoded).hexdigest()}"


def derive_deep_idempotency_key(
    *,
    operation_id: str,
    input_hash: str,
    prompt_version: str,
    schema_version: str,
    corrective_attempt: Literal[0, 1],
) -> str:
    values = (operation_id, input_hash, prompt_version, schema_version, str(corrective_attempt))
    encoded = "\x1f".join(f"{len(value)}:{value}" for value in values).encode("utf-8")
    return f"rr-deep-{hashlib.sha256(encoded).hexdigest()}"


class LLMBrokerClient(LLMProvider):
    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        workload: str = "role-radar",
        capability: str = "structured-extraction",
        prefer_wait_seconds: int = 10,
        poll_interval_seconds: float = 1.0,
        result_timeout_seconds: float = 300.0,
        submit_reconcile_attempts: int = 3,
        http_timeout_seconds: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not token:
            raise ValueError("broker token is required")
        if not 0 <= prefer_wait_seconds <= 30:
            raise ValueError("broker wait must be between 0 and 30 seconds")
        if (
            poll_interval_seconds <= 0
            or result_timeout_seconds <= 0
            or submit_reconcile_attempts < 1
        ):
            raise ValueError("broker timing settings are invalid")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._workload = workload
        self._capability = capability
        self._prefer_wait_seconds = prefer_wait_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._result_timeout_seconds = result_timeout_seconds
        self._submit_reconcile_attempts = submit_reconcile_attempts
        self._client = http_client or client or httpx.AsyncClient(timeout=http_timeout_seconds)
        self._owns_client = http_client is None and client is None

    async def __aenter__(self) -> "LLMBrokerClient":
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult:
        self._validate_request(request)
        body = self._body(request)
        if self._capability == "deep-job-evaluation":
            key = derive_deep_idempotency_key(
                operation_id=request.operation_id,
                input_hash=request.input_hash,
                prompt_version=request.prompt_version,
                schema_version=request.schema_version,
                corrective_attempt=request.corrective_attempt,
            )
        else:
            key = derive_idempotency_key(
                job_id=request.operation_id,
                input_hash=request.input_hash,
                prompt_version=request.prompt_version,
                schema_version=request.schema_version,
                corrective_attempt=request.corrective_attempt,
            )
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Idempotency-Key": key,
            "Prefer": f"wait={self._prefer_wait_seconds}",
            "Content-Type": "application/json",
        }
        logical_token = reserve_logical_call("broker_calls")
        try:
            response = await self._submit(body, headers, request.operation_id)
            if response.status_code == 200:
                result = self._parse_result(response, None)
            elif response.status_code not in (201, 202):
                raise self._http_error(response)
            else:
                task_id = self._parse_task_id(response)
                result = await self._poll(task_id)
        except (CanaryAmbiguousAttempt, CanaryDeferred):
            raise
        except Exception:
            if logical_token is not None:
                raise CanaryAmbiguousAttempt("canary_broker_call_unresolved") from None
            raise
        settle_network_attempt(logical_token)
        return result

    def _validate_request(self, request: StructuredGenerationRequest) -> None:
        if request.capability != self._capability:
            raise ProviderError(kind="request_invalid", code="capability_mismatch")
        trace = request.trace
        if len(trace) > 16 or any(key not in _TRACE_KEYS for key in trace):
            raise ProviderError(kind="request_invalid", code="trace_invalid")
        if any(not isinstance(value, str) or len(value) > 256 for value in trace.values()):
            raise ProviderError(kind="request_invalid", code="trace_invalid")
        try:
            assert_broker_compatible(request.response_schema)
        except ValueError as exc:
            del exc
            raise ProviderError(kind="request_invalid", code="schema_invalid") from None
        if request.generation is not None and any(
            key not in _GENERATION_KEYS for key in request.generation
        ):
            raise ProviderError(kind="request_invalid", code="generation_invalid")

    def _body(self, request: StructuredGenerationRequest) -> dict[str, Any]:
        body: dict[str, Any] = {
            "workload": self._workload,
            "capability": request.capability,
            "messages": [message.model_dump(mode="json") for message in request.messages],
            "response": {"kind": "json_schema", "schema": request.response_schema},
        }
        if request.generation is not None:
            body["generation"] = request.generation
        if request.trace:
            body["trace"] = request.trace
        return body

    async def _submit(
        self, body: dict[str, Any], headers: dict[str, str], operation_id: str
    ) -> httpx.Response:
        del operation_id
        last_error: ProviderError | None = None
        for attempt in range(self._submit_reconcile_attempts):
            token = reserve_network_attempt("broker_attempts")
            try:
                response = await self._client.post(
                    f"{self._base_url}/v1/tasks", json=body, headers=headers
                )
                settle_network_attempt(token)
                return response
            except httpx.TimeoutException:
                if token is not None:
                    # The next attempt reuses this operation's idempotency key;
                    # the still-pending logical reservation blocks crash replay.
                    settle_network_attempt(token)
                last_error = ProviderError(kind="submit_unknown", code="timeout", retryable=True)
            except httpx.RequestError:
                if token is not None:
                    settle_network_attempt(token)
                last_error = ProviderError(kind="submit_unknown", code="transport", retryable=True)
            if attempt + 1 < self._submit_reconcile_attempts:
                await asyncio.sleep(min(0.05 * (attempt + 1), 1.0))
        assert last_error is not None
        raise last_error

    def _parse_task_id(self, response: httpx.Response) -> str:
        payload = self._json_object(response)
        task_id = payload.get("id")
        if not isinstance(task_id, str) or not 1 <= len(task_id) <= 128:
            raise ProviderError(kind="response_invalid", code="task_id_missing")
        return task_id

    async def _poll(self, task_id: str) -> StructuredGenerationResult:
        deadline = time.monotonic() + self._result_timeout_seconds
        url = f"{self._base_url}/v1/tasks/{task_id}/result"
        while True:
            token = reserve_network_attempt("broker_attempts")
            try:
                response = await self._client.get(
                    url, headers={"Authorization": f"Bearer {self._token}"}
                )
                settle_network_attempt(token)
            except (httpx.TimeoutException, httpx.RequestError):
                if token is not None:
                    raise CanaryAmbiguousAttempt("canary_broker_poll_ambiguous") from None
                raise ProviderError(
                    kind="pending_timeout", code="poll_transport", provider_task_id=task_id
                ) from None
            if response.status_code != 200:
                raise self._http_error(response, provider_task_id=task_id)
            payload = self._json_object(response)
            status = payload.get("status")
            if status == "pending":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProviderError(
                        kind="pending_timeout", code="deadline", provider_task_id=task_id
                    )
                await asyncio.sleep(min(self._poll_interval_seconds, remaining))
                continue
            return self._parse_result(response, task_id)

    def _parse_result(
        self, response: httpx.Response, task_id: str | None
    ) -> StructuredGenerationResult:
        payload = self._json_object(response)
        status = payload.get("status")
        if status == "succeeded":
            result = payload.get("result")
            if not isinstance(result, Mapping):
                raise ProviderError(
                    kind="response_invalid", code="result_missing", provider_task_id=task_id
                )
            content = result.get("content")
            finish_reason = result.get("finish_reason", "unknown")
            usage = result.get("usage")
            if not isinstance(content, str) or finish_reason not in _FINISH_REASONS:
                raise ProviderError(
                    kind="response_invalid", code="result_invalid", provider_task_id=task_id
                )
            safe_usage = self._usage(usage)
            return StructuredGenerationResult(
                content=content,
                provider_task_id=task_id,
                model_identifier=None,
                finish_reason=finish_reason,
                usage=safe_usage,
            )
        if status == "failed":
            error = payload.get("error")
            if not isinstance(error, Mapping):
                raise ProviderError(
                    kind="response_invalid", code="error_missing", provider_task_id=task_id
                )
            error_class = error.get("class")
            code = error.get("code")
            if error_class not in _ERROR_CLASSES or not isinstance(code, str):
                raise ProviderError(
                    kind="response_invalid", code="error_invalid", provider_task_id=task_id
                )
            raise ProviderError(
                kind=error_class,
                error_class=error_class,
                code=self._safe_scalar(code, "error"),
                retryable=error_class in {"transient_unsent", "transient_safe"},
                provider_task_id=task_id,
            )
        if status in {"cancelled", "expired"}:
            raise ProviderError(kind=status, code=status, provider_task_id=task_id)
        if status != "pending":
            raise ProviderError(
                kind="response_invalid", code="status_invalid", provider_task_id=task_id
            )
        raise ProviderError(
            kind="response_invalid", code="pending_without_poll", provider_task_id=task_id
        )

    def _json_object(self, response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError):
            raise ProviderError(kind="response_invalid", code="json_invalid") from None
        if not isinstance(payload, dict):
            raise ProviderError(kind="response_invalid", code="object_expected")
        return payload

    @staticmethod
    def _usage(value: object) -> dict[str, int]:
        if not isinstance(value, Mapping):
            raise ProviderError(kind="response_invalid", code="usage_invalid")
        allowed = {"prompt_tokens", "completion_tokens", "total_tokens"}
        if set(value) != allowed or any(
            not isinstance(item, int) or item < 0 for item in value.values()
        ):
            raise ProviderError(kind="response_invalid", code="usage_invalid")
        return {str(key): int(item) for key, item in value.items()}

    def _http_error(
        self, response: httpx.Response, provider_task_id: str | None = None
    ) -> ProviderError:
        mapping = {
            401: "authentication",
            403: "authorization_or_policy",
            409: "idempotency_conflict",
            422: "request_invalid",
            429: "rate_limited",
            503: "unavailable",
        }
        kind = mapping.get(
            response.status_code, "not_found" if response.status_code == 404 else "http_error"
        )
        code = f"http_{response.status_code}"
        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict) and isinstance(payload.get("code"), str):
            code = self._safe_scalar(payload["code"], code)
        return ProviderError(
            kind=kind,
            code=code,
            status=response.status_code,
            provider_task_id=provider_task_id,
        )

    @staticmethod
    def _safe_scalar(value: str, fallback: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.:-]", "_", value)[:128]
        return safe or fallback
