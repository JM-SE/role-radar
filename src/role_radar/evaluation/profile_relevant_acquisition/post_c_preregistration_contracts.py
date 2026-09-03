"""Pure, strict contracts for the offline post-Gate-C preregistration seal.

This module deliberately contains no filesystem, database, provider, or runtime
imports.  A seal is an identity for an already completed, locally verified
operation; it is not an authorization to execute that operation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from role_radar.discovery.planner_v2 import DiscoveryQueryPlanV2
from role_radar.evaluation.profile_relevant_acquisition.contracts import SeedInputs
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorization,
    GateCProvenance,
    gate_b_packet_sha256,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_service import GateCResult
from role_radar.evaluation.profile_relevant_acquisition.source_plan import SourcePlan
from role_radar.sources.identity import canonical_source_key

HEX64: Final = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
SCHEMA_VERSION: Final = "f10.1f-post-c-preregistration-v1"


class PostCPreregistrationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _text(value: object, code: str) -> None:
    if type(value) is not str or not value.strip():
        raise PostCPreregistrationError(code)


@dataclass(frozen=True, slots=True)
class PostCPreregistrationRequest:
    """All immutable bindings required to issue one seal; no defaults."""

    operation_id: str
    lineage_id: str
    authorization: GateCAuthorization
    accepted_gate_b: AcceptedGateBBinding
    query_plan: DiscoveryQueryPlanV2
    gate_c_result: GateCResult
    source_plan: SourcePlan
    gate_c_report: object
    provenance: GateCProvenance
    seeds: SeedInputs
    artifact_class: str
    target_corpus_count: int
    target_pilot_count: int
    target_holdout_count: int

    def __post_init__(self) -> None:
        _text(self.operation_id, "post_c_operation_invalid")
        _text(self.lineage_id, "post_c_lineage_invalid")
        if not isinstance(self.authorization, GateCAuthorization):
            raise PostCPreregistrationError("post_c_authorization_required")
        if not isinstance(self.accepted_gate_b, AcceptedGateBBinding):
            raise PostCPreregistrationError("post_c_gate_b_binding_invalid")
        if not isinstance(self.query_plan, DiscoveryQueryPlanV2):
            raise PostCPreregistrationError("post_c_query_plan_invalid")
        if not isinstance(self.gate_c_result, GateCResult):
            raise PostCPreregistrationError("post_c_gate_c_result_invalid")
        if self.gate_c_result.public.result != "completed":
            raise PostCPreregistrationError("post_c_gate_c_not_completed")
        if not isinstance(self.source_plan, SourcePlan):
            raise PostCPreregistrationError("post_c_source_plan_invalid")
        if self.gate_c_result.source_plan is not self.source_plan:
            raise PostCPreregistrationError("post_c_source_plan_substituted")
        if self.gate_c_result.report is not self.gate_c_report:
            raise PostCPreregistrationError("post_c_report_substituted")
        if self.gate_c_report is None:
            raise PostCPreregistrationError("post_c_report_invalid")
        if not isinstance(self.provenance, GateCProvenance):
            raise PostCPreregistrationError("post_c_provenance_invalid")
        if not isinstance(self.seeds, SeedInputs):
            raise PostCPreregistrationError("post_c_seeds_invalid")
        if self.artifact_class != "offline_private_report_only":
            raise PostCPreregistrationError("post_c_artifact_class_invalid")
        if any(
            type(value) is not int or value < 0
            for value in (
                self.target_corpus_count,
                self.target_pilot_count,
                self.target_holdout_count,
            )
        ):
            raise PostCPreregistrationError("post_c_cardinality_invalid")
        self._validate_bindings()

    def _validate_bindings(self) -> None:
        auth, packet, report, prov = (
            self.authorization,
            self.accepted_gate_b.packet,
            self.accepted_gate_b.report,
            self.provenance,
        )
        if gate_b_packet_sha256(packet) != self.accepted_gate_b.packet_sha256:
            raise PostCPreregistrationError("post_c_gate_b_packet_hash_mismatch")
        if report.result != "ready" or report.code != "gate_b_packet_ready":
            raise PostCPreregistrationError("post_c_gate_b_not_ready")
        if auth.operation_id != self.operation_id or auth.lineage_id != self.lineage_id:
            raise PostCPreregistrationError("post_c_operation_lineage_mismatch")
        if prov.candidate_commit_sha256 != packet.code_commit_sha256:
            raise PostCPreregistrationError("post_c_candidate_commit_mismatch")
        if prov.policy_id != packet.policy_id:
            raise PostCPreregistrationError("post_c_policy_id_mismatch")
        if (
            auth.provenance != prov
            or prov.gate_b_packet_sha256 != self.accepted_gate_b.packet_sha256
        ):
            raise PostCPreregistrationError("post_c_provenance_mismatch")
        if (
            self.source_plan.operation_id != self.operation_id
            or self.source_plan.lineage_id != self.lineage_id
        ):
            raise PostCPreregistrationError("post_c_source_plan_binding_mismatch")
        if self.source_plan.source_plan_sha256 != self.gate_c_result.public.source_plan_sha256:
            raise PostCPreregistrationError("post_c_source_plan_hash_mismatch")
        report_hash = getattr(self.gate_c_report, "report_sha256", None)
        if report_hash != self.gate_c_result.public.report_sha256:
            raise PostCPreregistrationError("post_c_report_hash_mismatch")
        if self.gate_c_result.public.plan_sha256 != self.query_plan.plan_sha256:
            raise PostCPreregistrationError("post_c_plan_hash_mismatch")
        if prov.query_plan_sha256 != self.query_plan.plan_sha256:
            raise PostCPreregistrationError("post_c_query_plan_binding_mismatch")
        if self.source_plan.seed != self.seeds or self.seeds != SeedInputs(
            packet.selection_seed, packet.partition_seed
        ):
            raise PostCPreregistrationError("post_c_seed_mismatch")
        comparisons = (
            (self.source_plan.namespace, prov.namespace, "namespace"),
            (self.source_plan.root, prov.approved_root, "root"),
            (self.source_plan.per_board_cap, auth.per_board_cap, "cap"),
            (self.source_plan.per_company_cap, auth.per_company_cap, "cap"),
            (self.source_plan.budget.maximum, auth.budget_units, "budget"),
        )
        if any(left != right for left, right, _ in comparisons):
            raise PostCPreregistrationError("post_c_binding_mismatch")
        if self.source_plan.budget.budget_id != self.accepted_gate_b.packet_sha256:
            raise PostCPreregistrationError("post_c_budget_binding_mismatch")
        if (
            prov.window_start_utc != packet.window_start_utc
            or prov.window_end_utc != packet.window_end_utc
            or not prov.window_start_utc < prov.cutoff_utc <= prov.window_end_utc
        ):
            raise PostCPreregistrationError("post_c_window_mismatch")
        if (
            packet.corpus_count != self.target_corpus_count
            or packet.pilot_count != self.target_pilot_count
            or packet.holdout_count != self.target_holdout_count
        ):
            raise PostCPreregistrationError("post_c_cardinality_mismatch")
        binding = self.query_plan.profile_binding
        if (
            binding.profile_id != packet.profile_id
            or str(binding.row_version) != packet.profile_version
            or binding.canonical_profile_sha256 != packet.profile_sha256
            or self.query_plan.policy_version != packet.policy_version
            or self.query_plan.policy_sha256 != packet.policy_sha256
        ):
            raise PostCPreregistrationError("post_c_profile_policy_mismatch")
        if not self.source_plan.source_configs or any(
            set(item) != {"family", "source_key", "configuration_version", "configuration"}
            or item["family"] not in {"greenhouse", "lever"}
            or item["configuration_version"] != 1
            for item in self.source_plan.source_configs
        ):
            raise PostCPreregistrationError("post_c_source_plan_nonofficial")
        for item in self.source_plan.source_configs:
            try:
                configuration = item["configuration"]
                if not isinstance(configuration, Mapping):
                    raise PostCPreregistrationError("post_c_source_plan_substituted")
                source_key = canonical_source_key(str(item["family"]), dict(configuration))
                if source_key != item["source_key"]:
                    raise PostCPreregistrationError("post_c_source_plan_substituted")
            except (TypeError, ValueError) as exc:
                raise PostCPreregistrationError("post_c_source_plan_substituted") from exc
        expected_quotas = {
            "MAX_BRAVE_REQUESTS_PER_RUN": auth.max_brave_requests,
            "MAX_TAVILY_REQUESTS_PER_RUN": auth.max_tavily_requests,
            "MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN": auth.max_board_candidates,
            "MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN": auth.max_board_verifications,
            "MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN": auth.max_wire_attempts,
        }
        if any(self.query_plan.limits.get(key) != value for key, value in expected_quotas.items()):
            raise PostCPreregistrationError("post_c_quota_binding_mismatch")
        if any(
            type(getattr(self.query_plan, name)) is not int or getattr(self.query_plan, name) <= 0
            for name in (
                "max_brave_requests_per_run",
                "max_tavily_requests_per_run",
                "max_unique_board_candidates_per_run",
                "max_unique_board_verifications_per_run",
                "max_verification_wire_attempts_per_run",
            )
        ):
            raise PostCPreregistrationError("post_c_quota_invalid")

    def payload(self) -> dict[str, object]:
        auth = self.authorization
        p = self.provenance
        packet = self.accepted_gate_b.packet
        return {
            "schema_version": SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "lineage_id": self.lineage_id,
            "gate_b_packet_sha256": self.accepted_gate_b.packet_sha256,
            "gate_b_report_sha256": hashlib.sha256(
                json.dumps(
                    self.accepted_gate_b.report.as_dict(), sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest(),
            "plan_sha256": self.query_plan.plan_sha256,
            "query_plan_identity": {
                "schema_version": self.query_plan.schema_version,
                "planner_version": self.query_plan.planner_version,
            },
            "source_plan_sha256": self.source_plan.source_plan_sha256,
            "source_plan": {
                "version": self.source_plan.version,
                "source_configs": [dict(item) for item in self.source_plan.source_configs],
            },
            "gate_c_report_sha256": self.gate_c_result.public.report_sha256,
            "provenance": {name: getattr(p, name) for name in p.__dataclass_fields__},
            "candidate_commit_sha256": packet.code_commit_sha256,
            "profile_id": packet.profile_id,
            "profile_version": packet.profile_version,
            "profile_sha256": packet.profile_sha256,
            "policy_id": packet.policy_id,
            "policy_version": packet.policy_version,
            "policy_sha256": packet.policy_sha256,
            "namespace": self.source_plan.namespace,
            "approved_root": self.source_plan.root,
            "seeds": {
                "selection_seed": self.seeds.selection_seed,
                "partition_seed": self.seeds.partition_seed,
            },
            "caps": {
                "per_board": self.source_plan.per_board_cap,
                "per_company": self.source_plan.per_company_cap,
            },
            "quotas": dict(self.query_plan.limits),
            "cardinality": {
                "corpus": self.target_corpus_count,
                "pilot": self.target_pilot_count,
                "holdout": self.target_holdout_count,
            },
            "budget": {
                "id": self.source_plan.budget.budget_id,
                "maximum": self.source_plan.budget.maximum,
            },
            "artifact_class": self.artifact_class,
            "authorization": {
                "gate": auth.gate,
                "mode": auth.mode,
                "report_only": auth.report_only,
                "expires_at_utc": auth.expires_at_utc,
                "max_brave_requests": auth.max_brave_requests,
                "max_tavily_requests": auth.max_tavily_requests,
                "max_board_candidates": auth.max_board_candidates,
                "max_board_verifications": auth.max_board_verifications,
                "max_wire_attempts": auth.max_wire_attempts,
            },
            "window": {
                "start": p.window_start_utc,
                "end": p.window_end_utc,
                "cutoff": p.cutoff_utc,
            },
        }


@dataclass(frozen=True, slots=True)
class PostCPreregistrationSeal:
    operation_id: str
    canonical_bytes: bytes
    preregistration_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.canonical_bytes) is not bytes
            or hashlib.sha256(self.canonical_bytes).hexdigest() != self.preregistration_sha256
        ):
            raise PostCPreregistrationError("post_c_seal_hash_mismatch")


def build_seal(request: PostCPreregistrationRequest) -> PostCPreregistrationSeal:
    try:
        raw = json.dumps(
            request.payload(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PostCPreregistrationError("post_c_canonical_invalid") from exc
    return PostCPreregistrationSeal(request.operation_id, raw, hashlib.sha256(raw).hexdigest())


class PrivateSealWriter(Protocol):
    approved_root: str

    def write(self, seal: PostCPreregistrationSeal) -> None: ...
    def read(self, operation_id: str) -> bytes | None: ...


_REQUEST_FIELDS = frozenset(PostCPreregistrationRequest.__dataclass_fields__)


def parse_post_c_preregistration_request(value: object) -> PostCPreregistrationRequest:
    """Parse only an already-constructed object graph; never coerce or default."""
    if not isinstance(value, Mapping) or set(value) != _REQUEST_FIELDS | {"schema_version"}:
        raise PostCPreregistrationError("post_c_request_fields_invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise PostCPreregistrationError("post_c_request_schema_invalid")
    fields = dict(value)
    fields.pop("schema_version")
    try:
        return PostCPreregistrationRequest(**fields)
    except PostCPreregistrationError:
        raise
    except (TypeError, ValueError) as exc:
        raise PostCPreregistrationError("post_c_request_invalid") from exc


def validate_post_c_request(request: PostCPreregistrationRequest) -> None:
    """Re-run the frozen request's complete pure binding validation."""
    if not isinstance(request, PostCPreregistrationRequest):
        raise PostCPreregistrationError("post_c_request_invalid")
    request.__post_init__()


__all__ = [
    "PostCPreregistrationError",
    "PostCPreregistrationRequest",
    "PostCPreregistrationSeal",
    "PrivateSealWriter",
    "build_seal",
    "parse_post_c_preregistration_request",
]
