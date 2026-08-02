"""Contratos y adaptadores de proveedores LLM."""

from role_radar.broker.protocols import (
    LLMMessage,
    LLMProvider,
    ProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)

__all__ = [
    "LLMMessage",
    "LLMProvider",
    "ProviderError",
    "StructuredGenerationRequest",
    "StructuredGenerationResult",
]
