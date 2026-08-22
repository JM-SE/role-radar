"""Atomic draft and immutable final persistence for F10.2."""
# ruff: noqa: E501

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from role_radar.evaluation.blind_labeling.contracts import (
    Adjudication,
    AuditEvent,
    AuditKind,
    ReviewDecision,
    ReviewPlan,
    SessionPhase,
    SessionState,
)
from role_radar.evaluation.blind_labeling.filesystem import (
    FilesystemError,
    atomic_write,
    ensure_private_root,
    locked,
    publish_no_replace,
    read_bounded,
)
from role_radar.evaluation.blind_labeling.policy import (
    DRAFT_SCHEMA,
    MAX_AUDIT_EVENTS,
    MAX_DRAFT_BYTES,
    OUTPUT_ROOT,
)
from role_radar.evaluation.blind_labeling.validation import (
    ValidationError,
    canonical_line,
    decision_dict,
    decision_from_dict,
)


class StoreError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _state_dict(state: SessionState) -> dict[str, Any]:
    return {
        "dataset_id": state.dataset_id,
        "pilot_sha256": state.pilot_sha256,
        "pilot_view_sha256": state.pilot_view_sha256,
        "rubric_version": state.rubric_version,
        "rubric_sha256": state.rubric_sha256,
        "protocol_version": state.protocol_version,
        "revision": state.revision,
        "phase": state.phase.value,
        "first_pass": [[key, decision_dict(value)] for key, value in state.first_pass],
        "first_pass_sha256": state.first_pass_sha256,
        "generation": state.generation,
        "review_plan": None if state.review_plan is None else {
            "generation": state.review_plan.generation,
            "first_pass_sha256": state.review_plan.first_pass_sha256,
            "item_ids": list(state.review_plan.item_ids),
            "plan_sha256": state.review_plan.plan_sha256,
        },
        "review_decisions": [
            {"item_id": value.item_id, "decision": decision_dict(value.decision), "matches_first_pass": value.matches_first_pass}
            for value in state.review_decisions
        ],
        "adjudications": [{"item_id": value.item_id, "decision": decision_dict(value.decision)} for value in state.adjudications],
        "audit_events": [
            {"revision": value.revision, "kind": value.kind.value, "phase": value.phase.value, "generation": value.generation, "item_id": value.item_id, "before": value.before, "after": value.after, "occurred_at": value.occurred_at}
            for value in state.audit_events
        ],
        "finalization_intent": state.finalization_intent,
    }


def _state_from_dict(value: dict[str, Any]) -> SessionState:
    try:
        plan_value = value["review_plan"]
        plan = None if plan_value is None else ReviewPlan(int(plan_value["generation"]), str(plan_value["first_pass_sha256"]), tuple(str(item) for item in plan_value["item_ids"]), str(plan_value["plan_sha256"]))
        events = tuple(
            AuditEvent(int(item["revision"]), AuditKind(item["kind"]), SessionPhase(item["phase"]), int(item["generation"]), item["item_id"], item["before"], item["after"], str(item["occurred_at"]))
            for item in value["audit_events"]
        )
        state = SessionState(
            str(value["dataset_id"]), str(value["pilot_sha256"]), str(value["pilot_view_sha256"]),
            str(value["rubric_version"]), str(value["rubric_sha256"]), str(value["protocol_version"]),
            int(value["revision"]), SessionPhase(value["phase"]),
            tuple((str(item[0]), decision_from_dict(item[1])) for item in value["first_pass"]),
            value["first_pass_sha256"], int(value["generation"]), plan,
            tuple(ReviewDecision(str(item["item_id"]), decision_from_dict(item["decision"]), bool(item["matches_first_pass"])) for item in value["review_decisions"]),
            tuple(Adjudication(str(item["item_id"]), decision_from_dict(item["decision"])) for item in value["adjudications"]),
            events, value.get("finalization_intent"),
        )
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise StoreError("draft_state_invalid") from exc
    if len(state.audit_events) > MAX_AUDIT_EVENTS or state.revision != len(state.audit_events):
        raise StoreError("draft_state_invalid")
    return state


class LabelingStore:
    def __init__(self, root: Path | None = None, *, dataset_id: str, rubric_version: str) -> None:
        self.root = root or Path(OUTPUT_ROOT)
        self.dataset_id = dataset_id
        self.rubric_version = rubric_version

    @property
    def session_root(self) -> Path:
        return self.root / self.dataset_id / self.rubric_version

    @property
    def draft_root(self) -> Path:
        return self.session_root / "draft"

    @property
    def state_path(self) -> Path:
        return self.draft_root / "state.json"

    @property
    def lock_path(self) -> Path:
        return self.draft_root / ".lock"

    def exists(self) -> bool:
        return self.state_path.is_file() and not self.state_path.is_symlink()

    def load(self) -> SessionState:
        try:
            raw = json.loads(read_bounded(self.state_path, MAX_DRAFT_BYTES).decode("utf-8"))
            if not isinstance(raw, dict) or raw.get("schema_version") != DRAFT_SCHEMA:
                raise StoreError("draft_schema_invalid")
            payload = raw.get("payload")
            if not isinstance(payload, dict):
                raise StoreError("draft_payload_invalid")
            import hashlib
            expected = hashlib.sha256(canonical_line(payload)).hexdigest()
            if raw.get("payload_sha256") != expected:
                raise StoreError("draft_payload_tampered")
            return _state_from_dict(payload)
        except StoreError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreError("draft_read_failed") from exc

    def create(self, state: SessionState) -> None:
        ensure_private_root(self.root)
        self.draft_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        payload = _state_dict(state)
        envelope = {"schema_version": DRAFT_SCHEMA, "payload": payload, "payload_sha256": __import__("hashlib").sha256(canonical_line(payload)).hexdigest()}
        with locked(self.lock_path, create=True):
            atomic_write(self.state_path, canonical_line(envelope))

    def save(self, state: SessionState, *, expected_revision: int) -> None:
        ensure_private_root(self.root)
        with locked(self.lock_path, create=False):
            current = self.load()
            if current.revision != expected_revision:
                raise StoreError("stale_revision")
            payload = _state_dict(state)
            envelope = {"schema_version": DRAFT_SCHEMA, "payload": payload, "payload_sha256": __import__("hashlib").sha256(canonical_line(payload)).hexdigest()}
            atomic_write(self.state_path, canonical_line(envelope))

    def publish_final(self, *, labelset_id: str, payloads: dict[str, bytes], internal: dict[str, Any]) -> Path:
        final_root = self.session_root / "final"
        ensure_private_root(final_root)
        target = final_root / labelset_id
        expected = {"labels.jsonl", "audit.jsonl", "review-report.json", "rubric.json", "internal-manifest.json"}
        if set(payloads) != expected:
            raise StoreError("final_files_invalid")
        full = dict(payloads)
        full["checksums.sha256"] = "".join(
            f"{__import__('hashlib').sha256(full[name]).hexdigest()}  {name}\n" for name in sorted(payloads)
        ).encode("ascii")
        staging = Path(tempfile.mkdtemp(prefix=f".{labelset_id}.", dir=final_root))
        os.chmod(staging, 0o700)
        try:
            for name, data in full.items():
                path = staging / name
                path.write_bytes(data)
                os.chmod(path, 0o600)
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
            with locked(final_root / ".lock"):
                if target.exists() or target.is_symlink():
                    if self.verify_final(labelset_id) and all(
                        (target / name).read_bytes() == value for name, value in full.items()
                    ):
                        return target
                    raise StoreError("final_conflict")
                publish_no_replace(staging, target)
            return target
        except (OSError, FilesystemError) as exc:
            raise StoreError("final_publish_failed") from exc
        finally:
            if staging.exists():
                for item in staging.iterdir():
                    item.unlink()
                staging.rmdir()

    def verify_final(self, labelset_id: str) -> bool:
        target = self.session_root / "final" / labelset_id
        names = {"labels.jsonl", "audit.jsonl", "review-report.json", "rubric.json", "internal-manifest.json", "checksums.sha256"}
        try:
            if target.is_symlink() or not target.is_dir() or {item.name for item in target.iterdir()} != names:
                return False
            if stat.S_IMODE(target.stat().st_mode) != 0o700 or any(
                item.is_symlink() or stat.S_IMODE(item.stat().st_mode) != 0o600
                for item in target.iterdir()
            ):
                return False
            entries = (target / "checksums.sha256").read_text(encoding="ascii").splitlines()
            if len(entries) != 5:
                return False
            import hashlib
            for entry in entries:
                digest, separator, name = entry.partition("  ")
                if separator != "  " or name not in names - {"checksums.sha256"} or hashlib.sha256((target / name).read_bytes()).hexdigest() != digest:
                    return False
            return sum(1 for _ in (target / "labels.jsonl").open("rb")) == 50
        except (OSError, UnicodeError, ValueError):
            return False

    def final_manifest(self, labelset_id: str) -> tuple[dict[str, Any], dict[str, str]]:
        if not self.verify_final(labelset_id):
            raise StoreError("final_integrity_failed")
        target = self.session_root / "final" / labelset_id
        try:
            internal = json.loads((target / "internal-manifest.json").read_text(encoding="utf-8"))
            hashes: dict[str, str] = {}
            for entry in (target / "checksums.sha256").read_text(encoding="ascii").splitlines():
                digest, separator, name = entry.partition("  ")
                if separator != "  ":
                    raise StoreError("final_checksum_invalid")
                hashes[name] = digest
            if not isinstance(internal, dict):
                raise StoreError("final_manifest_invalid")
            return internal, hashes
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise StoreError("final_manifest_invalid") from exc


__all__ = ["LabelingStore", "StoreError"]
