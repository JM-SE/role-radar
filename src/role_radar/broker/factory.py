"""Selección explícita de provider; nunca hace I/O durante import/startup."""

from typing import Any

import httpx

from role_radar.broker.client import LLMBrokerClient
from role_radar.broker.fake import FakeLLMProvider
from role_radar.broker.protocols import LLMProvider
from role_radar.config import Settings


class ProviderConfigurationError(ValueError):
    """Configuración ausente sin incluir valores sensibles en el mensaje."""


def create_llm_provider(
    settings: Settings,
    *,
    http_client: httpx.AsyncClient | None = None,
    fake_responses: Any = None,
) -> LLMProvider:
    if settings.llm_provider == "fake":
        if fake_responses is not None:
            return FakeLLMProvider(responses=fake_responses)
        return FakeLLMProvider()
    if settings.broker_url is None or settings.broker_token is None:
        raise ProviderConfigurationError("broker provider requires explicit URL and token")
    return LLMBrokerClient(
        base_url=settings.broker_url,
        token=settings.broker_token.get_secret_value(),
        workload=settings.broker_workload,
        capability=settings.broker_structured_extraction_capability,
        prefer_wait_seconds=settings.broker_prefer_wait_seconds,
        poll_interval_seconds=settings.broker_poll_interval_seconds,
        result_timeout_seconds=settings.broker_result_timeout_seconds,
        submit_reconcile_attempts=settings.broker_submit_reconcile_attempts,
        http_timeout_seconds=settings.http_timeout_seconds,
        http_client=http_client,
    )


def create_deep_llm_provider(
    settings: Settings,
    *,
    http_client: httpx.AsyncClient | None = None,
    fake_responses: Any = None,
) -> LLMProvider:
    """Build a separate capability provider; physical model selection stays in broker."""
    if settings.deep_evaluation_provider == "fake":
        return (
            FakeLLMProvider(responses=fake_responses)
            if fake_responses is not None
            else FakeLLMProvider(
                result={
                    "fit_score": 50,
                    "decision": "needs_review",
                    "strengths": [],
                    "gaps": [],
                    "model_concerns": [],
                    "uncertainties": [],
                    "recommended_action": "review",
                    "confidence": 0.5,
                }
            )
        )
    if settings.broker_url is None or settings.broker_token is None:
        raise ProviderConfigurationError("deep broker provider requires explicit URL and token")
    return LLMBrokerClient(
        base_url=settings.broker_url,
        token=settings.broker_token.get_secret_value(),
        workload=settings.broker_workload,
        capability=settings.broker_deep_job_evaluation_capability,
        prefer_wait_seconds=settings.broker_prefer_wait_seconds,
        poll_interval_seconds=settings.broker_poll_interval_seconds,
        result_timeout_seconds=settings.deep_evaluation_timeout_seconds,
        submit_reconcile_attempts=settings.broker_submit_reconcile_attempts,
        http_timeout_seconds=settings.http_timeout_seconds,
        http_client=http_client,
    )
