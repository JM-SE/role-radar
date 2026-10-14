"""Modelos Pydantic del payload de extracción y su evidencia."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ValueState = Literal["specified", "not_specified", "unknown"]


class _ExtractionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TextEvidence(_ExtractionModel):
    state: ValueState = "unknown"
    value: str | None = None
    evidence: str | None = None


class IntegerEvidence(_ExtractionModel):
    state: ValueState = "unknown"
    value: int | None = None
    evidence: str | None = None


class EvidenceItem(_ExtractionModel):
    """List item with optional per-item state (models emit it; broker validates it).

    The broker validates model output against this schema before RoleRadar sees
    it, so any field the model plausibly emits must be declared here. `state`
    defaults to specified (a listed item is asserted present); unknown honors
    an explicit model abstention without failing the whole extraction.
    """

    state: ValueState = "specified"
    value: str = Field(min_length=1)
    evidence: str | None = None


class SalaryEvidence(_ExtractionModel):
    state: ValueState = "unknown"
    min: int | float | None = Field(default=None, ge=0)
    max: int | float | None = Field(default=None, ge=0)
    currency: str | None = None
    period: str | None = None
    evidence: str | None = None

    @model_validator(mode="after")
    def salary_range_is_coherent(self) -> "SalaryEvidence":
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError("salary min cannot exceed max")
        return self


class JobExtractionPayload(_ExtractionModel):
    """Únicamente los diez campos de extracción comprometidos por F3."""

    seniority: TextEvidence = Field(default_factory=TextEvidence)
    remote_policy: TextEvidence = Field(default_factory=TextEvidence)
    regions: list[EvidenceItem] = Field(default_factory=list)
    employment_type: TextEvidence = Field(default_factory=TextEvidence)
    required_skills: list[EvidenceItem] = Field(default_factory=list)
    preferred_skills: list[EvidenceItem] = Field(default_factory=list)
    languages: list[EvidenceItem] = Field(default_factory=list)
    years_experience: IntegerEvidence = Field(default_factory=IntegerEvidence)
    salary: SalaryEvidence = Field(default_factory=SalaryEvidence)
    work_authorization: TextEvidence = Field(default_factory=TextEvidence)
