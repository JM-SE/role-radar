"""Atomic draft and immutable final persistence for F10.2."""
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from role_radar.evaluation.blind_labeling.contracts import (
    Adjudication,
    AuditEvent,
    AuditKind,
    FinalizationIntent,
    ReviewDecision,
    ReviewPlan,
    SessionPhase,
    SessionState,
)
from role_radar.evaluation.blind_labeling.filesystem import (
    FilesystemError,
    atomic_write,
    ensure_private_root,
    fsync_directory,
    locked,
    open_private_directory,
    publish_no_replace,
    read_bounded,
    read_bounded_fd,
)
from role_radar.evaluation.blind_labeling.materialization import validate_final_bundle
from role_radar.evaluation.blind_labeling.policy import (
    DRAFT_SCHEMA,
    HEX64,
    MAX_AUDIT_EVENTS,
    MAX_DRAFT_BYTES,
    MAX_FINAL_FILE_BYTES,
    OUTPUT_ROOT,
)
from role_radar.evaluation.blind_labeling.session import validate_state
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
    intent = state.finalization_intent
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
            {
                "item_id": value.item_id,
                "decision": decision_dict(value.decision),
                "matches_first_pass": value.matches_first_pass,
            }
            for value in state.review_decisions
        ],
        "adjudications": [
            {"item_id": value.item_id, "decision": decision_dict(value.decision)}
            for value in state.adjudications
        ],
        "audit_events": [
            {
                "revision": value.revision,
                "kind": value.kind.value,
                "phase": value.phase.value,
                "generation": value.generation,
                "item_id": value.item_id,
                "before": value.before,
                "after": value.after,
                "occurred_at": value.occurred_at,
            }
            for value in state.audit_events
        ],
        "finalization_intent": None if intent is None else {
            "challenge_sha256": intent.challenge_sha256,
            "draft_revision": intent.draft_revision,
            "draft_payload_sha256": intent.draft_payload_sha256,
            "labelset_id": intent.labelset_id,
            "final_labels_sha256": intent.final_labels_sha256,
            "review_report_sha256": intent.review_report_sha256,
            "audit_sha256": intent.audit_sha256,
            "finalized_at": intent.finalized_at,
        },
    }


def state_payload_hash(state: SessionState) -> str:
    return hashlib.sha256(canonical_line(_state_dict(state))).hexdigest()


def _state_from_dict(value: dict[str, Any]) -> SessionState:
    expected_keys = {
        "dataset_id", "pilot_sha256", "pilot_view_sha256", "rubric_version", "rubric_sha256",
        "protocol_version", "revision", "phase", "first_pass", "first_pass_sha256",
        "generation", "review_plan", "review_decisions", "adjudications", "audit_events",
        "finalization_intent",
    }
    try:
        if set(value) != expected_keys:
            raise StoreError("draft_state_invalid")
        plan_value = value["review_plan"]
        if plan_value is not None and not isinstance(plan_value, dict):
            raise StoreError("draft_state_invalid")
        plan = None if plan_value is None else ReviewPlan(
            plan_value["generation"],
            plan_value["first_pass_sha256"],
            tuple(plan_value["item_ids"]),
            plan_value["plan_sha256"],
        )
        events = tuple(
            AuditEvent(
                item["revision"],
                AuditKind(item["kind"]),
                SessionPhase(item["phase"]),
                item["generation"],
                item["item_id"],
                item["before"],
                item["after"],
                item["occurred_at"],
            )
            for item in value["audit_events"]
        )
        intent_value = value["finalization_intent"]
        if intent_value is not None and not isinstance(intent_value, dict):
            raise StoreError("draft_state_invalid")
        intent = None if intent_value is None else FinalizationIntent(
            intent_value["challenge_sha256"],
            intent_value["draft_revision"],
            intent_value["draft_payload_sha256"],
            intent_value["labelset_id"],
            intent_value["final_labels_sha256"],
            intent_value["review_report_sha256"],
            intent_value["audit_sha256"],
            intent_value["finalized_at"],
        )
        state = SessionState(
            value["dataset_id"],
            value["pilot_sha256"],
            value["pilot_view_sha256"],
            value["rubric_version"],
            value["rubric_sha256"],
            value["protocol_version"],
            value["revision"],
            SessionPhase(value["phase"]),
            tuple((item[0], decision_from_dict(item[1])) for item in value["first_pass"]),
            value["first_pass_sha256"],
            value["generation"],
            plan,
            tuple(
                ReviewDecision(
                    item["item_id"],
                    decision_from_dict(item["decision"]),
                    item["matches_first_pass"],
                )
                for item in value["review_decisions"]
            ),
            tuple(
                Adjudication(item["item_id"], decision_from_dict(item["decision"]))
                for item in value["adjudications"]
            ),
            events,
            intent,
        )
        validate_state(state)
        return state
    except StoreError:
        raise
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise StoreError("draft_state_invalid") from exc


class LabelingStore:
    def __init__(self, root: Path | None = None, *, dataset_id: str, rubric_version: str) -> None:
        self.root = root or Path(OUTPUT_ROOT)
        self.dataset_id = dataset_id
        self.rubric_version = rubric_version

    @property
    def session_root(self) -> Path:
        return self.root / self.dataset_id / self.rubric_version

    @property
    def dataset_root(self) -> Path:
        return self.root / self.dataset_id

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
        try:
            directory_fd = open_private_directory(self.draft_root)
        except (OSError, FilesystemError):
            return False
        try:
            fd = os.open(self.state_path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                os.fstat(fd)
                return True
            finally:
                os.close(fd)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        finally:
            os.close(directory_fd)

    def load(self) -> SessionState:
        try:
            raw = json.loads(read_bounded(self.state_path, MAX_DRAFT_BYTES).decode("utf-8"))
            if not isinstance(raw, dict) or set(raw) != {"schema_version", "payload", "payload_sha256"}:
                raise StoreError("draft_schema_invalid")
            payload = raw["payload"]
            if not isinstance(payload, dict) or raw["schema_version"] != DRAFT_SCHEMA:
                raise StoreError("draft_payload_invalid")
            expected = hashlib.sha256(canonical_line(payload)).hexdigest()
            if raw["payload_sha256"] != expected:
                raise StoreError("draft_payload_tampered")
            state = _state_from_dict(payload)
            validate_state(
                state,
                expected_dataset_id=self.dataset_id,
                expected_rubric_version=self.rubric_version,
            )
            return state
        except StoreError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreError("draft_read_failed") from exc

    def create(self, state: SessionState) -> None:
        try:
            validate_state(
                state,
                expected_dataset_id=self.dataset_id,
                expected_rubric_version=self.rubric_version,
            )
        except Exception as exc:
            raise StoreError(getattr(exc, "code", "draft_state_invalid")) from exc
        ensure_private_root(self.root)
        ensure_private_root(self.dataset_root)
        ensure_private_root(self.session_root)
        if self.draft_root.exists():
            raise StoreError("session_exists")
        ensure_private_root(self.draft_root)
        payload = _state_dict(state)
        envelope = {
            "schema_version": DRAFT_SCHEMA,
            "payload": payload,
            "payload_sha256": hashlib.sha256(canonical_line(payload)).hexdigest(),
        }
        encoded = canonical_line(envelope)
        if len(encoded) > MAX_DRAFT_BYTES or len(state.audit_events) > MAX_AUDIT_EVENTS:
            raise StoreError("draft_limit_exceeded")
        with locked(self.lock_path, create=True):
            atomic_write(self.state_path, encoded)

    def save(self, state: SessionState, *, expected_revision: int) -> None:
        ensure_private_root(self.root, create=False)
        ensure_private_root(self.dataset_root, create=False)
        ensure_private_root(self.session_root, create=False)
        with locked(self.lock_path, create=False):
            current = self.load()
            if current.revision != expected_revision or state.revision != current.revision + 1:
                raise StoreError("stale_revision")
            try:
                validate_state(
                    state,
                    expected_dataset_id=self.dataset_id,
                    expected_rubric_version=self.rubric_version,
                )
            except Exception as exc:
                raise StoreError(getattr(exc, "code", "draft_state_invalid")) from exc
            payload = _state_dict(state)
            envelope = {
                "schema_version": DRAFT_SCHEMA,
                "payload": payload,
                "payload_sha256": hashlib.sha256(canonical_line(payload)).hexdigest(),
            }
            encoded = canonical_line(envelope)
            if len(encoded) > MAX_DRAFT_BYTES or len(state.audit_events) > MAX_AUDIT_EVENTS:
                raise StoreError("draft_limit_exceeded")
            atomic_write(self.state_path, encoded)

    def publish_final(self, *, labelset_id: str, payloads: dict[str, bytes], internal: dict[str, Any]) -> Path:
        if HEX64.fullmatch(labelset_id) is None:
            raise StoreError("labelset_id_invalid")
        ensure_private_root(self.root)
        ensure_private_root(self.dataset_root)
        ensure_private_root(self.session_root)
        final_root = self.session_root / "final"
        ensure_private_root(final_root)
        target = final_root / labelset_id
        expected = {"labels.jsonl", "audit.jsonl", "review-report.json", "rubric.json", "internal-manifest.json"}
        if set(payloads) != expected:
            raise StoreError("final_files_invalid")
        full = dict(payloads)
        full["checksums.sha256"] = "".join(
            f"{hashlib.sha256(full[name]).hexdigest()}  {name}\n" for name in sorted(payloads)
        ).encode("ascii")
        try:
            validate_final_bundle(payloads, labelset_id)
        except (TypeError, ValueError, KeyError) as exc:
            raise StoreError("final_files_invalid") from exc
        staging = Path(tempfile.mkdtemp(prefix=f".{labelset_id}.", dir=final_root))
        staging_identity = os.lstat(staging)
        os.chmod(staging, 0o700)
        try:
            for name, data in full.items():
                path = staging / name
                path.write_bytes(data)
                os.chmod(path, 0o600)
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
            fsync_directory(staging)
            with locked(final_root / ".lock"):
                if target.exists() or target.is_symlink():
                    try:
                        existing_payloads, _ = self._final_payloads(labelset_id)
                    except StoreError:
                        existing_payloads = None
                    if existing_payloads is not None and all(
                        existing_payloads.get(name) == value for name, value in payloads.items()
                    ):
                        return target
                    raise StoreError("final_conflict")
                publish_no_replace(staging, target)
            return target
        except (OSError, FilesystemError) as exc:
            raise StoreError("final_publish_failed") from exc
        finally:
            self._cleanup_staging(staging, staging_identity)

    @staticmethod
    def _cleanup_staging(staging: Path, original: os.stat_result) -> None:
        parent_fd: int | None = None
        staging_fd: int | None = None
        try:
            parent_fd = open_private_directory(staging.parent)
            staging_fd = os.open(
                staging.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            current = os.fstat(staging_fd)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                return
            for name in os.listdir(staging_fd):
                os.unlink(name, dir_fd=staging_fd)
            current_path = os.lstat(staging)
            if (current_path.st_dev, current_path.st_ino) == (original.st_dev, original.st_ino):
                os.rmdir(staging.name, dir_fd=parent_fd)
        except (OSError, RuntimeError):
            return
        finally:
            if staging_fd is not None:
                os.close(staging_fd)
            if parent_fd is not None:
                os.close(parent_fd)

    def _final_payloads(self, labelset_id: str) -> tuple[dict[str, bytes], dict[str, str]]:
        if HEX64.fullmatch(labelset_id) is None:
            raise StoreError("labelset_id_invalid")
        ensure_private_root(self.root, create=False)
        ensure_private_root(self.dataset_root, create=False)
        ensure_private_root(self.session_root, create=False)
        final_root = self.session_root / "final"
        ensure_private_root(final_root, create=False)
        target = self.session_root / "final" / labelset_id
        directory_fd = open_private_directory(target)
        try:
            names = {
                "labels.jsonl", "audit.jsonl", "review-report.json", "rubric.json",
                "internal-manifest.json", "checksums.sha256",
            }
            if set(os.listdir(directory_fd)) != names:
                raise StoreError("final_integrity_failed")
            checksums = read_bounded_fd(directory_fd, "checksums.sha256", MAX_FINAL_FILE_BYTES)
            entries = checksums.decode("ascii").splitlines()
            expected_names = sorted(names - {"checksums.sha256"})
            parsed: list[tuple[str, str]] = []
            for entry in entries:
                digest, separator, name = entry.partition("  ")
                if separator != "  " or HEX64.fullmatch(digest) is None or name not in expected_names:
                    raise StoreError("final_checksum_invalid")
                parsed.append((name, digest))
            if [name for name, _digest in parsed] != expected_names:
                raise StoreError("final_checksum_invalid")
            payloads = {
                name: read_bounded_fd(directory_fd, name, MAX_FINAL_FILE_BYTES)
                for name in expected_names
            }
            if any(hashlib.sha256(payloads[name]).hexdigest() != digest for name, digest in parsed):
                raise StoreError("final_checksum_mismatch")
            return payloads, dict(parsed)
        finally:
            os.close(directory_fd)

    def verify_final(self, labelset_id: str) -> bool:
        try:
            payloads, _hashes = self._final_payloads(labelset_id)
            validate_final_bundle(payloads, labelset_id)
            return True
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, FilesystemError, StoreError):
            return False

    def final_manifest(self, labelset_id: str) -> tuple[dict[str, Any], dict[str, str]]:
        try:
            payloads, hashes = self._final_payloads(labelset_id)
            internal = validate_final_bundle(payloads, labelset_id)
            return internal, hashes
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, FilesystemError, StoreError) as exc:
            raise StoreError("final_manifest_invalid") from exc


__all__ = ["LabelingStore", "StoreError", "state_payload_hash"]
