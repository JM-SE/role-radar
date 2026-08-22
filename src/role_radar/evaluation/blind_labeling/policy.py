"""Central F10.2 policy, pins, limits, and stable protocol values."""
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import re
from types import MappingProxyType
from typing import Final

DATASET_ID: Final = "f1135149bfd832ad706632a209136e6a425b49d0928f61f540e8bf9658dc37cb"
CORPUS_SHA256: Final = "28993cab8b93942c4f91e37aca18b2d53feff029de4422aca0e5ba6b93e70233"
PILOT_SHA256: Final = "1890ca8da12505578a4551a325d675e248ebc39b7477ee72cf799df4ff55c869"
PILOT_FILE_SHA256: Final = "bc01bae75b65dbd970bae0f3371b1dc52bbc98aa5c4bb4a13a6628cfb5dd18dc"
HOLDOUT_SHA256: Final = "2b313ba001ad866df114688bf57bd326d7291212f4a0ff456ccbf2a90d3a5a11"
PROFILE_ID: Final = "e4aec18c-90fa-4553-ae3e-9e4655223683"
PROFILE_VERSION: Final = 2
PROFILE_SCHEMA: Final = 1
PROFILE_SHA256: Final = "609601723c1510a2908fde05dac58378b5ad96e6ca9a6a1384aba5a3078a5a3b"
CODE_COMMIT: Final = "d084ce8ed0298cb813a03eccb73181c12786afac"
ALEMBIC_HEAD: Final = "f101b_continuous"

PROTOCOL_VERSION: Final = "f10.2-blind-labeling-v1"
RUBRIC_VERSION: Final = "f10.2-rubric-v1"
PILOT_ITEM_SCHEMA: Final = "f10.2-pilot-item-v1"
DRAFT_SCHEMA: Final = "f10.2-draft-v1"
DECISION_SCHEMA: Final = "f10.2-decision-v1"
AUDIT_SCHEMA: Final = "f10.2-audit-event-v1"
REVIEW_PLAN_SCHEMA: Final = "f10.2-review-plan-v1"
REVIEW_REPORT_SCHEMA: Final = "f10.2-review-report-v1"
RUBRIC_SCHEMA: Final = "f10.2-rubric-schema-v1"
INTERNAL_MANIFEST_SCHEMA: Final = "f10.2-internal-manifest-v1"
EXTERNAL_MANIFEST_SCHEMA: Final = "f10.2-external-manifest-v1"
CLI_OUTPUT_SCHEMA: Final = "f10.2-cli-output-v1"
LABELSET_ID_SCHEMA: Final = "f10.2-labelset-id-v1"

PILOT_COUNT: Final = 50
REVIEW_NON_MAYBE_LIMIT: Final = 10
NOTE_MAX_CODEPOINTS: Final = 280
MAX_PILOT_FILE_BYTES: Final = 16 * 1024 * 1024
MAX_PILOT_LINE_BYTES: Final = 1024 * 1024
MAX_DRAFT_BYTES: Final = 16 * 1024 * 1024
MAX_AUDIT_EVENTS: Final = 10_000
SOURCE_ROOT: Final = "/opt/role-radar/data/evaluation/f10.1c"
OUTPUT_ROOT: Final = "/opt/role-radar/data/evaluation/f10.2"
PILOT_FILENAME: Final = "pilot-label-view.jsonl"

EXIT_OK: Final = 0
EXIT_USAGE: Final = 2
EXIT_BLOCKED: Final = 3
EXIT_INTEGRITY: Final = 4
EXIT_CANCELLED: Final = 130
EXIT_INTERNAL: Final = 70

LABEL_DOMAINS: Final = MappingProxyType(
    {
        "apply": (
            "role_match", "skills_match", "seniority_match", "location_work_mode_match",
            "compensation_match", "career_interest", "company_domain_interest", "other_positive",
        ),
        "maybe": (
            "role_scope_unclear", "skills_fit_unclear", "seniority_fit_unclear",
            "location_work_mode_unclear", "compensation_unclear", "authorization_language_unclear",
            "description_incomplete", "other_uncertainty",
        ),
        "reject": (
            "role_mismatch", "skills_mismatch", "seniority_mismatch", "location_work_mode_mismatch",
            "compensation_mismatch", "authorization_language_mismatch", "schedule_contract_mismatch",
            "career_mismatch", "company_domain_mismatch", "other_negative",
        ),
    }
)
LABEL_DEFINITIONS: Final = MappingProxyType(
    {
        "apply": "The user would submit an application based on the frozen evidence and frozen baseline profile.",
        "maybe": "The user might apply, but decisive information is missing or ambiguous. It is never a weak apply, and absence of information is not automatically negative.",
        "reject": "The user would not apply based on the frozen evidence and frozen baseline profile.",
    }
)

_DOMAIN_PREFIX = "f10.2:"
DOMAIN_RUBRIC: Final = _DOMAIN_PREFIX + "rubric-v1"
DOMAIN_DRAFT: Final = _DOMAIN_PREFIX + "draft-v1"
DOMAIN_FIRST_PASS: Final = _DOMAIN_PREFIX + "first-pass-v1"
DOMAIN_REVIEW_SAMPLE: Final = _DOMAIN_PREFIX + "review-sample-v1"
DOMAIN_REVIEW_ORDER: Final = _DOMAIN_PREFIX + "review-order-v1"
DOMAIN_REVIEW_PLAN: Final = _DOMAIN_PREFIX + "review-plan-v1"
DOMAIN_FINAL_LABELS: Final = _DOMAIN_PREFIX + "final-labels-v1"
DOMAIN_REVIEW_REPORT: Final = _DOMAIN_PREFIX + "review-report-v1"
DOMAIN_AUDIT: Final = _DOMAIN_PREFIX + "audit-v1"
DOMAIN_LABELSET: Final = _DOMAIN_PREFIX + "labelset-id-v1"
DOMAIN_START: Final = _DOMAIN_PREFIX + "start-challenge-v1"
DOMAIN_REOPEN: Final = _DOMAIN_PREFIX + "reopen-challenge-v1"
DOMAIN_FINALIZE: Final = _DOMAIN_PREFIX + "finalize-challenge-v1"

HEX64: Final = re.compile(r"^[0-9a-f]{64}$")
OPAQUE_ID: Final = re.compile(r"^[0-9a-f]{24}$")
CANARY_PATTERNS: Final = (
    re.compile(r"(?:https?://|www\.|\b[a-z0-9.-]+\.[a-z]{2,}(?:/|\b))", re.I),
    re.compile(r"\b(?:pipeline|score|scoring|rank|ranking|variant|prompt|model output|llm|broker)\b", re.I),
    re.compile(r"\b(?:password|secret|api key|access token|bearer|private key|credential)\b", re.I),
    re.compile(r"\b(?:sk-[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,})\b"),
)


def semantic_hash(domain: str, value: object) -> str:
    import json

    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(domain.encode("ascii") + b"\0" + payload.encode("utf-8")).hexdigest()


def challenge(domain: str, value: object) -> str:
    return semantic_hash(domain, value)


__all__ = [name for name in globals() if name.isupper()] + ["challenge", "semantic_hash"]
