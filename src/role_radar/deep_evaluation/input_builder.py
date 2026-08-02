"""Allowlisted projection used as Thinking input; never accepts descriptions/raw HTML."""

import hashlib
import json
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from role_radar.domain.profile import CandidateProfileV1

from .contracts import DeepEvaluationCandidateV1, EvidenceReferenceV1
from .policy import DeepEvaluationPolicyV1

INPUT_VERSION = "deep-input-v1"
MAX_INPUT_BYTES = 32 * 1024


class DeepJobInputV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    job_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=240)
    company: str = Field(min_length=1, max_length=240)
    normalized_location: str | None = Field(default=None, max_length=240)


class DeepProfileInputV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    title: str | None = Field(default=None, max_length=240)
    years_of_experience: StrictInt | None = Field(default=None, ge=0)
    target_roles: tuple[str, ...] = Field(default=(), max_length=32)
    target_titles: tuple[str, ...] = Field(default=(), max_length=32)
    core_skills: tuple[str, ...] = Field(default=(), max_length=32)
    secondary_skills: tuple[str, ...] = Field(default=(), max_length=32)
    regions: tuple[str, ...] = Field(default=(), max_length=32)
    remote_only: StrictBool = False
    employment_preferences: tuple[str, ...] = Field(default=(), max_length=32)
    languages: dict[str, str] = Field(default_factory=dict)
    excluded_roles: tuple[str, ...] = Field(default=(), max_length=32)
    excluded_technologies: tuple[str, ...] = Field(default=(), max_length=32)
    hard_constraints: dict[str, Any] = Field(default_factory=dict)

    @field_validator("languages")
    @classmethod
    def language_limit(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 32:
            raise ValueError("profile list limit exceeded")
        return value


class DeepExtractionInputV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    validation_status: str
    extraction_id: str = Field(min_length=1, max_length=128)
    fields: dict[str, Any]
    evidence: tuple[EvidenceReferenceV1, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def bounded_fields(self) -> "DeepExtractionInputV1":
        _assert_bounded(self.fields)
        return self


class PreliminaryInputV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    job_score_id: str = Field(min_length=1, max_length=128)
    score: StrictInt = Field(ge=0, le=100)
    signals: tuple[dict[str, Any], ...] = Field(max_length=16)
    blockers: tuple[dict[str, Any], ...] = Field(max_length=16)
    ambiguities: tuple[dict[str, Any], ...] = Field(max_length=16)


class QuestionInputV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    code: str = Field(min_length=1, max_length=128)
    field: str = Field(min_length=1, max_length=128)
    question: str = Field(min_length=1, max_length=240)
    evidence: tuple[EvidenceReferenceV1, ...] = Field(min_length=1, max_length=3)


class DeepEvaluationInputV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    input_version: str = INPUT_VERSION
    job: DeepJobInputV1
    profile: DeepProfileInputV1
    extraction: DeepExtractionInputV1
    preliminary: PreliminaryInputV1
    questions: tuple[QuestionInputV1, ...] = Field(max_length=8)
    policy_version: str = Field(min_length=1, max_length=64)
    policy_hash: str = Field(min_length=1, max_length=64)
    prompt_version: str = Field(min_length=1, max_length=64)
    schema_version: str = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def bounded_serialization(self) -> "DeepEvaluationInputV1":
        encoded = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        if len(encoded.encode()) > MAX_INPUT_BYTES:
            raise ValueError("deep input exceeds 32 KiB")
        return self

    def input_hash(self) -> str:
        encoded = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()


def _project_profile(profile: dict[str, Any]) -> DeepProfileInputV1:
    canonical = CandidateProfileV1.model_validate(profile).model_dump(mode="python")
    canonical.pop("soft_preferences", None)
    return DeepProfileInputV1.model_validate(canonical)


def _project_extraction(extraction_id: str, extraction: dict[str, Any]) -> DeepExtractionInputV1:
    fields: dict[str, Any] = {}
    evidence: list[EvidenceReferenceV1] = []
    for field, value in extraction.items():
        if field not in {
            "seniority",
            "remote_policy",
            "regions",
            "employment_type",
            "required_skills",
            "preferred_skills",
            "languages",
            "years_experience",
            "salary",
            "work_authorization",
        }:
            continue
        fields[field] = value
        items = value if isinstance(value, list) else [value]
        for index, item in enumerate(items):
            if (
                isinstance(item, dict)
                and isinstance(item.get("evidence"), str)
                and item["evidence"].strip()
            ):
                if len(item["evidence"]) > 240:
                    raise ValueError("extraction evidence exceeds 240 characters")
                evidence.append(
                    EvidenceReferenceV1(
                        "extraction", f"{field}[{index}].evidence", item["evidence"]
                    )
                )
    return DeepExtractionInputV1(
        validation_status="valid",
        extraction_id=extraction_id,
        fields=fields,
        evidence=tuple(evidence[:32]),
    )


def _assert_bounded(value: Any) -> None:
    if isinstance(value, str) and len(value) > 240:
        raise ValueError("deep fact exceeds 240 characters")
    if isinstance(value, (list, tuple)):
        if len(value) > 32:
            raise ValueError("deep list exceeds 32 elements")
        for item in value:
            _assert_bounded(item)
    elif isinstance(value, dict):
        for item in value.values():
            _assert_bounded(item)


def build_deep_input(
    candidate: DeepEvaluationCandidateV1,
    *,
    profile: dict[str, Any] | None = None,
    extraction: dict[str, Any] | None = None,
    policy_hash: str = "",
    policy_version: str = "deep-selector-v1",
    prompt_version: str = "deep-prompt-v1",
    schema_version: str = "deep-evaluation-v1",
) -> DeepEvaluationInputV1:
    profile_payload = profile or candidate.profile
    extraction_payload = extraction or candidate.extraction
    if profile_payload is None or extraction_payload is None or candidate.extraction_id is None:
        raise ValueError("exact profile and extraction are required")
    if (
        len(candidate.signals) > 16
        or len(candidate.blockers) > 16
        or len(candidate.ambiguities) > 16
    ):
        raise ValueError("preliminary list exceeds 16 elements")
    questions = tuple(
        QuestionInputV1(
            code=item.code, field=item.field, question=item.question, evidence=item.evidence
        )
        for item in candidate.resolvable_ambiguities[:8]
    )
    return DeepEvaluationInputV1(
        job=DeepJobInputV1(
            job_id=candidate.job_id,
            title=candidate.title,
            company=candidate.company,
            normalized_location=candidate.normalized_location,
        ),
        profile=_project_profile(profile_payload),
        extraction=_project_extraction(candidate.extraction_id, extraction_payload),
        preliminary=PreliminaryInputV1(
            job_score_id=candidate.job_score_id,
            score=candidate.preliminary_score,
            signals=candidate.signals,
            blockers=candidate.blockers,
            ambiguities=candidate.ambiguities,
        ),
        questions=questions,
        policy_version=policy_version,
        policy_hash=policy_hash or DeepEvaluationPolicyV1().policy_hash,
        prompt_version=prompt_version,
        schema_version=schema_version,
    )
