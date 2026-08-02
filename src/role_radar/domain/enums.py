"""Enums de dominio de role-radar (máquinas de estado y tipos).

Las tres máquinas de estado son independientes (D12-D14):
- ``JobSearchRunStatus``: ciclo de la ejecución (10 estados, D12).
- ``JobStatus``: ciclo de vida de la oferta canónica (D13).
- ``RunJobStage`` / ``RunJobStatus``: journal por etapa de cada oferta dentro de
  una ejecución (D14).
"""

from enum import StrEnum


class JobSearchRunStatus(StrEnum):
    """Ciclo de la ejecución (handoff §10.1, D12 - exactamente 10 estados).

    La deduplicación y el prefiltrado NO son estados de run: son sub-pasos del
    pipeline y contadores en ``JobSearchRun.stats_json``.
    """

    PENDING = "pending"
    COLLECTING = "collecting"
    NORMALIZING = "normalizing"
    EXTRACTING = "extracting"
    SCORING = "scoring"
    DEEP_EVALUATING = "deep_evaluating"
    NOTIFYING = "notifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobStatus(StrEnum):
    """Ciclo de vida de la oferta canónica (D13)."""

    NEW = "new"
    ACTIVE = "active"
    EXPIRED = "expired"
    ARCHIVED = "archived"


class RunJobStage(StrEnum):
    """Etapa del pipeline registrada por oferta dentro de una ejecución (D14)."""

    COLLECTED = "collected"
    NORMALIZED = "normalized"
    DEDUPLICATED = "deduplicated"
    PREFILTERED = "prefiltered"
    EXTRACTED = "extracted"
    SCORED = "scored"
    DEEP_EVALUATED = "deep_evaluated"
    NOTIFIED = "notified"


class RunJobStatus(StrEnum):
    """Resultado de una etapa en el journal RunJob (D14)."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class ExtractionStatus(StrEnum):
    """Estado durable de una extracción estructurada (Fase 3)."""

    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    NEEDS_REVIEW = "needs_review"
    FAILED = "failed"


class SourceType(StrEnum):
    """Tipo de fuente de ofertas (handoff §9; extensible)."""

    GREENHOUSE = "greenhouse"
    LEVER = "lever"
    ASHBY = "ashby"
    WORKABLE = "workable"
    WEB_SEARCH = "web_search"
    EMAIL = "email"
    LINKEDIN_PUBLIC = "linkedin_public"
    MANUAL = "manual"
    OTHER = "other"


class DeepEvaluationStatus(StrEnum):
    """Lifecycle of one immutable deep-evaluation operation (F6)."""

    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    NEEDS_REVIEW = "needs_review"
    FAILED = "failed"


class DeepDecision(StrEnum):
    STRONG_MATCH = "strong_match"
    POSSIBLE_MATCH = "possible_match"
    WEAK_MATCH = "weak_match"
    REJECT = "reject"
    NEEDS_REVIEW = "needs_review"


class RecommendedAction(StrEnum):
    APPLY = "apply"
    REVIEW = "review"
    IGNORE = "ignore"
