"""Pure final label bundle construction and semantic identity."""
# ruff: noqa: E501

from __future__ import annotations

import json
from typing import Any

from role_radar.evaluation.blind_labeling.contracts import (
    AuditKind,
    PilotSnapshot,
    SessionPhase,
    SessionState,
)
from role_radar.evaluation.blind_labeling.policy import (
    ALEMBIC_HEAD,
    CODE_COMMIT,
    CORPUS_SHA256,
    DATASET_ID,
    DOMAIN_LABELSET,
    DOMAIN_REVIEW_REPORT,
    EXTERNAL_MANIFEST_SCHEMA,
    HEX64,
    HOLDOUT_SHA256,
    INTERNAL_MANIFEST_SCHEMA,
    LABEL_DEFINITIONS,
    LABEL_DOMAINS,
    LABELSET_ID_SCHEMA,
    OPAQUE_ID,
    PILOT_FILE_SHA256,
    PILOT_SHA256,
    PROFILE_ID,
    PROFILE_SCHEMA,
    PROFILE_SHA256,
    PROFILE_VERSION,
    PROTOCOL_VERSION,
    REVIEW_REPORT_SCHEMA,
    RUBRIC_SCHEMA,
    RUBRIC_VERSION,
    current_pilot_count,
    semantic_hash,
)
from role_radar.evaluation.blind_labeling.session import final_decisions
from role_radar.evaluation.blind_labeling.validation import (
    ValidationError,
    canonical_line,
    decision_dict,
    decision_from_dict,
)


def rubric_payload() -> dict[str, Any]:
    return {
        "schema_version": RUBRIC_SCHEMA,
        "version": RUBRIC_VERSION,
        "protocol": PROTOCOL_VERSION,
        "definitions": dict(LABEL_DEFINITIONS),
        "reasons": {key: list(value) for key, value in LABEL_DOMAINS.items()},
        "evidence": {
            "allowed_fields": ["opaque_id", "title", "company", "location", "description"],
            "forbidden_fields": ["score", "rank", "pipeline", "model", "prompt", "llm", "broker"],
        },
        "notes": {"max_codepoints": 280, "maybe_optional": True, "other_required": True},
        "canary_warning": "Canary checks are imperfect; the operator remains responsible for sensitive content.",
    }


def rubric_hash() -> str:
    return semantic_hash("f10.2:rubric-v1", rubric_payload())


def _audit_semantics(state: SessionState) -> list[dict[str, Any]]:
    records = [
        {
            "kind": event.kind.value,
            "phase": event.phase.value,
            "generation": event.generation,
            "item_id": event.item_id,
            "before": event.before,
            "after": event.after,
        }
        for event in state.audit_events
    ]
    return _audit_record_semantics(records)


def _audit_record_semantics(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lifecycle: list[dict[str, Any]] = []
    grouped: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for record in records:
        if record["kind"] in {AuditKind.FINALIZED.value, AuditKind.FINALIZATION_INTENT.value}:
            continue
        semantic = {
            "kind": record["kind"],
            "phase": record["phase"] if record["item_id"] is None else "item_mutation",
            "generation": record["generation"],
            "item_id": record["item_id"],
            "before": record["before"],
            "after": record["after"],
        }
        if record["item_id"] is None:
            lifecycle.append(semantic)
        else:
            grouped.setdefault((record["generation"], record["item_id"]), []).append(semantic)
    lifecycle_order = {
        AuditKind.STARTED.value: 0,
        AuditKind.FIRST_PASS_SEALED.value: 1,
        AuditKind.REOPENED.value: 2,
    }
    lifecycle.sort(
        key=lambda value: (
            value["generation"],
            lifecycle_order.get(value["kind"], 99),
            value["kind"],
        )
    )
    return lifecycle + [
        {"generation": generation, "item_id": item_id, "events": events}
        for (generation, item_id), events in sorted(grouped.items())
    ]


def _review_payload(state: SessionState) -> dict[str, Any]:
    first = dict(state.first_pass)
    reviews = {value.item_id: value for value in state.review_decisions}
    adjudications = {value.item_id: value.decision for value in state.adjudications}
    items = []
    for item_id in sorted(reviews):
        review = reviews[item_id]
        items.append(
            {
                "item_id": item_id,
                "first_pass": decision_dict(first[item_id]),
                "review": decision_dict(review.decision),
                "matches_first_pass": review.matches_first_pass,
                "adjudication": (
                    decision_dict(adjudications[item_id]) if item_id in adjudications else None
                ),
                "final": decision_dict(adjudications.get(item_id, review.decision)),
            }
        )
    return {
        "schema_version": REVIEW_REPORT_SCHEMA,
        "review_plan_sha256": state.review_plan.plan_sha256 if state.review_plan else None,
        "reviewed_count": len(state.review_decisions),
        "matched_count": sum(1 for value in state.review_decisions if value.matches_first_pass),
        "discrepant_count": sum(
            1 for value in state.review_decisions if not value.matches_first_pass
        ),
        "adjudicated_count": len(state.adjudications),
        "consistency": "descriptive_only",
        "items": items,
    }


def build_bundle(
    snapshot: PilotSnapshot, state: SessionState, finalized_at: str
) -> tuple[dict[str, bytes], dict[str, Any], str]:
    decisions = final_decisions(state)
    labels = [
        {"opaque_id": item.opaque_id, "decision": decision_dict(decisions[item.opaque_id])}
        for item in sorted(snapshot.items, key=lambda value: value.opaque_id)
    ]
    labels_hash = semantic_hash("f10.2:final-labels-v1", labels)
    review = _review_payload(state)
    review_hash = semantic_hash("f10.2:review-report-v1", review)
    audit_hash = semantic_hash("f10.2:audit-v1", _audit_semantics(state))
    rubric = rubric_payload()
    rubric_sha = rubric_hash()
    preimage = {
        "schema": LABELSET_ID_SCHEMA,
        "dataset_id": DATASET_ID,
        "corpus_sha256": CORPUS_SHA256,
        "pilot_sha256": PILOT_SHA256,
        "pilot_view_sha256": PILOT_FILE_SHA256,
        "holdout_sha256": HOLDOUT_SHA256,
        "profile": [PROFILE_ID, PROFILE_VERSION, PROFILE_SCHEMA, PROFILE_SHA256],
        "protocol": PROTOCOL_VERSION,
        "rubric": [RUBRIC_VERSION, rubric_sha],
        "review_plan_sha256": review["review_plan_sha256"],
        "labels_sha256": labels_hash,
        "review_sha256": review_hash,
        "audit_sha256": audit_hash,
    }
    labelset_id = semantic_hash("f10.2:labelset-id-v1", preimage)
    internal = {
        "schema_version": INTERNAL_MANIFEST_SCHEMA,
        "dataset_id": DATASET_ID,
        "labelset_id": labelset_id,
        "counts": {
            "total": current_pilot_count(),
            "reviewed": len(state.review_decisions),
            "adjudicated": len(state.adjudications),
        },
        "frozen": {
            "corpus_sha256": CORPUS_SHA256,
            "pilot_sha256": PILOT_SHA256,
            "pilot_view_sha256": PILOT_FILE_SHA256,
            "holdout_sha256": HOLDOUT_SHA256,
        },
        "profile": {
            "id": PROFILE_ID,
            "version": PROFILE_VERSION,
            "schema": PROFILE_SCHEMA,
            "sha256": PROFILE_SHA256,
        },
        "protocol": PROTOCOL_VERSION,
        "protocol_schema": "f10.2-cli-output-v1",
        "rubric": {"version": RUBRIC_VERSION, "sha256": rubric_sha},
        "review_plan_sha256": review["review_plan_sha256"],
        "semantic_hashes": {"labels": labels_hash, "review": review_hash, "audit": audit_hash},
        "alembic_head": ALEMBIC_HEAD,
        "code_commit": CODE_COMMIT,
        "finalized_at": finalized_at,
        "preimage": preimage,
    }
    audit_events = tuple(
        event for event in state.audit_events if event.kind is not AuditKind.FINALIZED
    )
    payloads = {
        "labels.jsonl": b"".join(canonical_line(value) for value in labels),
        "audit.jsonl": b"".join(
            canonical_line(
                {
                    "revision": event.revision,
                    "kind": event.kind.value,
                    "phase": event.phase.value,
                    "generation": event.generation,
                    "item_id": event.item_id,
                    "before": event.before,
                    "after": event.after,
                    "occurred_at": event.occurred_at,
                }
            )
            for event in audit_events
        ),
        "review-report.json": canonical_line(review),
        "rubric.json": canonical_line(rubric),
        "internal-manifest.json": canonical_line(internal),
    }
    return payloads, internal, labelset_id


def external_manifest(internal: dict[str, Any], file_hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": EXTERNAL_MANIFEST_SCHEMA,
        "status": "finalized",
        "dataset_id": internal["dataset_id"],
        "labelset_id": internal["labelset_id"],
        "count": current_pilot_count(),
        "reviewed_count": internal["counts"]["reviewed"],
        "adjudicated_count": internal["counts"]["adjudicated"],
        "frozen": internal["frozen"],
        "profile": internal["profile"],
        "protocol": internal["protocol"],
        "rubric": internal["rubric"],
        "file_hashes": file_hashes,
        "finalized_at": internal["finalized_at"],
    }


def validate_final_bundle(payloads: dict[str, bytes], labelset_id: str) -> dict[str, Any]:
    expected_names = {
        "labels.jsonl",
        "audit.jsonl",
        "review-report.json",
        "rubric.json",
        "internal-manifest.json",
    }
    if set(payloads) != expected_names or HEX64.fullmatch(labelset_id) is None:
        raise ValidationError("final_bundle_invalid")

    def parse_object(name: str) -> dict[str, Any]:
        value = json.loads(payloads[name].decode("utf-8"))
        if not isinstance(value, dict) or canonical_line(value) != payloads[name]:
            raise ValidationError("final_bundle_invalid")
        return value

    labels: list[dict[str, Any]] = []
    for line in payloads["labels.jsonl"].splitlines(keepends=True):
        value = json.loads(line.decode("utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != {"opaque_id", "decision"}
            or canonical_line(value) != line
        ):
            raise ValidationError("final_labels_invalid")
        if (
            not isinstance(value["opaque_id"], str)
            or OPAQUE_ID.fullmatch(value["opaque_id"]) is None
        ):
            raise ValidationError("final_labels_invalid")
        decision_from_dict(value["decision"])
        labels.append(value)
    if len(labels) != current_pilot_count() or [value["opaque_id"] for value in labels] != sorted(
        value["opaque_id"] for value in labels
    ):
        raise ValidationError("final_labels_invalid")
    if len({value["opaque_id"] for value in labels}) != current_pilot_count():
        raise ValidationError("final_labels_invalid")
    labels_by_id = {value["opaque_id"]: value["decision"] for value in labels}

    review = parse_object("review-report.json")
    if (
        set(review)
        != {
            "schema_version",
            "review_plan_sha256",
            "reviewed_count",
            "matched_count",
            "discrepant_count",
            "adjudicated_count",
            "consistency",
            "items",
        }
        or review["schema_version"] != REVIEW_REPORT_SCHEMA
    ):
        raise ValidationError("final_review_invalid")
    if not all(
        isinstance(review[key], int) and review[key] >= 0
        for key in ("reviewed_count", "matched_count", "discrepant_count", "adjudicated_count")
    ):
        raise ValidationError("final_review_invalid")
    if review["matched_count"] + review["discrepant_count"] != review["reviewed_count"]:
        raise ValidationError("final_review_invalid")
    if (
        review["consistency"] != "descriptive_only"
        or not isinstance(review["items"], list)
        or HEX64.fullmatch(review["review_plan_sha256"] or "") is None
        or len(review["items"]) != review["reviewed_count"]
    ):
        raise ValidationError("final_review_invalid")
    review_item_ids: set[str] = set()
    for item in review["items"]:
        if not isinstance(item, dict) or set(item) != {
            "item_id",
            "first_pass",
            "review",
            "matches_first_pass",
            "adjudication",
            "final",
        }:
            raise ValidationError("final_review_invalid")
        if (
            not isinstance(item["item_id"], str)
            or OPAQUE_ID.fullmatch(item["item_id"]) is None
            or item["item_id"] in review_item_ids
        ):
            raise ValidationError("final_review_invalid")
        review_item_ids.add(item["item_id"])
        decision_from_dict(item["first_pass"])
        decision_from_dict(item["review"])
        first_decision = decision_from_dict(item["first_pass"])
        review_decision = decision_from_dict(item["review"])
        final_decision = decision_from_dict(item["final"])
        if item["matches_first_pass"] != (first_decision == review_decision):
            raise ValidationError("final_review_invalid")
        if item["adjudication"] is not None:
            if item["matches_first_pass"]:
                raise ValidationError("final_review_invalid")
            adjudication = decision_from_dict(item["adjudication"])
            if final_decision != adjudication:
                raise ValidationError("final_review_invalid")
        elif not item["matches_first_pass"] or final_decision != review_decision:
            raise ValidationError("final_review_invalid")
        if item["item_id"] not in labels_by_id or labels_by_id[item["item_id"]] != item["final"]:
            raise ValidationError("final_review_invalid")
        if not isinstance(item["matches_first_pass"], bool):
            raise ValidationError("final_review_invalid")

    rubric = parse_object("rubric.json")
    if rubric != rubric_payload():
        raise ValidationError("final_rubric_invalid")
    internal = parse_object("internal-manifest.json")
    expected_internal = {
        "schema_version",
        "dataset_id",
        "labelset_id",
        "counts",
        "frozen",
        "profile",
        "protocol",
        "protocol_schema",
        "rubric",
        "review_plan_sha256",
        "semantic_hashes",
        "alembic_head",
        "code_commit",
        "finalized_at",
        "preimage",
    }
    if set(internal) != expected_internal or internal["labelset_id"] != labelset_id:
        raise ValidationError("final_manifest_invalid")
    if internal["dataset_id"] != DATASET_ID or internal["protocol"] != PROTOCOL_VERSION:
        raise ValidationError("final_manifest_invalid")
    if (
        internal["protocol_schema"] != "f10.2-cli-output-v1"
        or internal["code_commit"] != CODE_COMMIT
    ):
        raise ValidationError("final_manifest_invalid")
    if internal["rubric"] != {"version": RUBRIC_VERSION, "sha256": rubric_hash()}:
        raise ValidationError("final_manifest_invalid")
    if internal["review_plan_sha256"] != review["review_plan_sha256"]:
        raise ValidationError("final_manifest_invalid")
    if internal["frozen"] != {
        "corpus_sha256": CORPUS_SHA256,
        "pilot_sha256": PILOT_SHA256,
        "pilot_view_sha256": PILOT_FILE_SHA256,
        "holdout_sha256": HOLDOUT_SHA256,
    }:
        raise ValidationError("final_manifest_invalid")
    if internal["profile"] != {
        "id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "schema": PROFILE_SCHEMA,
        "sha256": PROFILE_SHA256,
    }:
        raise ValidationError("final_manifest_invalid")
    if internal["alembic_head"] != ALEMBIC_HEAD or not isinstance(internal["finalized_at"], str):
        raise ValidationError("final_manifest_invalid")
    if set(internal["semantic_hashes"]) != {"labels", "review", "audit"}:
        raise ValidationError("final_manifest_invalid")
    if set(internal["counts"]) != {"total", "reviewed", "adjudicated"}:
        raise ValidationError("final_manifest_invalid")
    if (
        internal["counts"]["total"] != current_pilot_count()
        or internal["counts"]["reviewed"] != review["reviewed_count"]
        or internal["counts"]["adjudicated"] != review["adjudicated_count"]
    ):
        raise ValidationError("final_manifest_invalid")
    if internal["semantic_hashes"]["labels"] != semantic_hash("f10.2:final-labels-v1", labels):
        raise ValidationError("final_manifest_invalid")
    if internal["semantic_hashes"]["review"] != semantic_hash(DOMAIN_REVIEW_REPORT, review):
        raise ValidationError("final_manifest_invalid")
    audit_records = [
        json.loads(line.decode("utf-8"))
        for line in payloads["audit.jsonl"].splitlines(keepends=True)
    ]
    if not audit_records or audit_records[0].get("kind") != AuditKind.STARTED.value:
        raise ValidationError("final_audit_invalid")
    if any(
        not isinstance(record, dict)
        or set(record)
        != {"revision", "kind", "phase", "generation", "item_id", "before", "after", "occurred_at"}
        or type(record["revision"]) is not int
        or record["revision"] < 1
        or type(record["generation"]) is not int
        or record["generation"] < 0
        or not isinstance(record["occurred_at"], str)
        or not isinstance(record["item_id"], str | None)
        or not isinstance(record["before"], dict | None)
        or not isinstance(record["after"], dict | None)
        or canonical_line(record) != line
        for record, line in zip(
            audit_records, payloads["audit.jsonl"].splitlines(keepends=True), strict=True
        )
    ):
        raise ValidationError("final_audit_invalid")
    if [record["revision"] for record in audit_records] != list(range(1, len(audit_records) + 1)):
        raise ValidationError("final_audit_invalid")
    try:
        for record in audit_records:
            AuditKind(record["kind"])
            SessionPhase(record["phase"])
    except (TypeError, ValueError) as exc:
        raise ValidationError("final_audit_invalid") from exc
    if internal["semantic_hashes"]["audit"] != semantic_hash(
        "f10.2:audit-v1", _audit_record_semantics(audit_records)
    ):
        raise ValidationError("final_manifest_invalid")
    preimage = internal["preimage"]
    expected_preimage_keys = {
        "schema",
        "dataset_id",
        "corpus_sha256",
        "pilot_sha256",
        "pilot_view_sha256",
        "holdout_sha256",
        "profile",
        "protocol",
        "rubric",
        "review_plan_sha256",
        "labels_sha256",
        "review_sha256",
        "audit_sha256",
    }
    if (
        not isinstance(preimage, dict)
        or set(preimage) != expected_preimage_keys
        or preimage.get("labels_sha256") != internal["semantic_hashes"]["labels"]
        or preimage.get("review_sha256") != internal["semantic_hashes"]["review"]
        or preimage.get("audit_sha256") != internal["semantic_hashes"]["audit"]
        or preimage.get("dataset_id") != DATASET_ID
        or preimage.get("schema") != LABELSET_ID_SCHEMA
        or preimage.get("corpus_sha256") != CORPUS_SHA256
        or preimage.get("pilot_sha256") != PILOT_SHA256
        or preimage.get("pilot_view_sha256") != PILOT_FILE_SHA256
        or preimage.get("holdout_sha256") != HOLDOUT_SHA256
        or preimage.get("protocol") != PROTOCOL_VERSION
        or preimage.get("profile") != [PROFILE_ID, PROFILE_VERSION, PROFILE_SCHEMA, PROFILE_SHA256]
        or preimage.get("rubric") != [RUBRIC_VERSION, rubric_hash()]
        or preimage.get("review_plan_sha256") != review["review_plan_sha256"]
    ):
        raise ValidationError("final_manifest_invalid")
    if semantic_hash(DOMAIN_LABELSET, preimage) != labelset_id:
        raise ValidationError("final_manifest_invalid")
    return internal


__all__ = [
    "build_bundle",
    "external_manifest",
    "rubric_hash",
    "rubric_payload",
    "validate_final_bundle",
]
