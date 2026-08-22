"""Thin F10.2 orchestration; no prompting or low-level filesystem logic."""
# ruff: noqa: E501

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from role_radar.evaluation.blind_labeling.contracts import (
    Decision,
    FinalizedBundle,
    PilotSnapshot,
    SessionPhase,
    SessionState,
)
from role_radar.evaluation.blind_labeling.materialization import (
    build_bundle,
    external_manifest,
    rubric_hash,
)
from role_radar.evaluation.blind_labeling.pilot_source import PilotSource
from role_radar.evaluation.blind_labeling.policy import (
    DATASET_ID,
    DOMAIN_FINALIZE,
    DOMAIN_REOPEN,
    DOMAIN_START,
    PILOT_COUNT,
    PILOT_FILE_SHA256,
    PILOT_SHA256,
    PROFILE_ID,
    PROFILE_SCHEMA,
    PROFILE_SHA256,
    PROFILE_VERSION,
    PROTOCOL_VERSION,
    RUBRIC_VERSION,
    challenge,
)
from role_radar.evaluation.blind_labeling.session import (
    SessionError,
    adjudicate,
    mark_finalized,
    new_session,
    reopen,
    save_first_pass,
    save_review,
    seal_for_review,
)
from role_radar.evaluation.blind_labeling.store import LabelingStore, StoreError
from role_radar.evaluation.blind_labeling.validation import ValidationError


class RuntimeErrorCode(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class BlindLabelingRuntime:
    def __init__(self, source: PilotSource, store: LabelingStore, *, clock: Any = _now) -> None:
        self.source = source
        self.store = store
        self.clock = clock

    def _snapshot(self) -> PilotSnapshot:
        try:
            return self.source.load()
        except Exception as exc:
            if hasattr(exc, "code"):
                raise RuntimeErrorCode(str(exc.code)) from exc
            raise RuntimeErrorCode("pilot_preflight_failed") from exc

    def _state(self) -> SessionState:
        try:
            return self.store.load()
        except StoreError as exc:
            raise RuntimeErrorCode(exc.code) from exc

    def status(self) -> dict[str, Any]:
        snapshot = self._snapshot()
        state = None
        if self.store.exists():
            state = self._state()
        payload: dict[str, Any] = {
            "schema_version": "f10.2-cli-output-v1",
            "status": "ready" if state is None else state.phase.value,
            "dataset_id": snapshot.dataset_id,
            "pilot_count": len(snapshot.items),
            "pilot_sha256": snapshot.pilot_sha256,
            "pilot_view_sha256": snapshot.pilot_view_sha256,
            "profile_id": PROFILE_ID,
            "profile_version": PROFILE_VERSION,
            "profile_schema": PROFILE_SCHEMA,
            "profile_sha256": PROFILE_SHA256,
            "rubric": RUBRIC_VERSION,
            "rubric_sha256": rubric_hash(),
            "protocol": PROTOCOL_VERSION,
            "completed_count": 0 if state is None else len(state.first_pass),
            "review_count": 0 if state is None else len(state.review_decisions),
            "adjudication_count": 0 if state is None else len(state.adjudications),
        }
        if state is None:
            preimage = {"dataset_id": DATASET_ID, "pilot_sha256": PILOT_SHA256, "pilot_view_sha256": PILOT_FILE_SHA256, "profile": [PROFILE_ID, PROFILE_VERSION, PROFILE_SCHEMA, PROFILE_SHA256], "rubric": [RUBRIC_VERSION, payload["rubric_sha256"]], "protocol": PROTOCOL_VERSION, "count": PILOT_COUNT}
            digest = challenge(DOMAIN_START, preimage)
            payload["acknowledgement"] = f"START F10.2 dataset_id={DATASET_ID} pilot_sha256={PILOT_SHA256} pilot_view_sha256={PILOT_FILE_SHA256} profile_id={PROFILE_ID} profile_version=2 profile_schema=1 profile_sha256={PROFILE_SHA256} rubric={RUBRIC_VERSION} rubric_sha256={payload['rubric_sha256']} protocol={PROTOCOL_VERSION} count=50 challenge_sha256={digest}"
        elif state.review_plan is not None and state.phase not in {SessionPhase.FINALIZED}:
            digest = challenge(DOMAIN_REOPEN, {"dataset_id": state.dataset_id, "revision": state.revision, "draft_payload_sha256": self._payload_hash(state), "first_pass_sha256": state.first_pass_sha256, "review_plan_sha256": state.review_plan.plan_sha256})
            payload["acknowledgement"] = f"REOPEN F10.2 dataset_id={DATASET_ID} rubric={RUBRIC_VERSION} protocol={PROTOCOL_VERSION} draft_revision={state.revision} draft_payload_sha256={self._payload_hash(state)} first_pass_sha256={state.first_pass_sha256} review_plan_sha256={state.review_plan.plan_sha256} challenge_sha256={digest}"
        return payload

    @staticmethod
    def _payload_hash(state: object) -> str:
        import hashlib

        from role_radar.evaluation.blind_labeling.store import _state_dict
        from role_radar.evaluation.blind_labeling.validation import canonical_line

        return hashlib.sha256(canonical_line(_state_dict(state))).hexdigest()  # type: ignore[arg-type]

    def _finalized_at(self, state: SessionState) -> str:
        if state.finalization_intent is not None:
            value = state.finalization_intent.get("finalized_at")
            if isinstance(value, str):
                return value
        return state.audit_events[-1].occurred_at if state.audit_events else self.clock()

    def start(self, acknowledgement: str) -> dict[str, Any]:
        snapshot = self._snapshot()
        if self.store.exists():
            raise RuntimeErrorCode("session_exists")
        status = self.status()
        expected = status.get("acknowledgement")
        if acknowledgement != expected:
            raise RuntimeErrorCode("acknowledgement_mismatch")
        state = new_session(snapshot, RUBRIC_VERSION, str(status["rubric_sha256"]), PROTOCOL_VERSION, self.clock())
        try:
            self.store.create(state)
        except (OSError, StoreError) as exc:
            raise RuntimeErrorCode("draft_create_failed") from exc
        return {"schema_version": "f10.2-cli-output-v1", "status": "labeling", "dataset_id": DATASET_ID, "count": PILOT_COUNT}

    def save_first_pass(self, item_id: str, decision: Decision) -> dict[str, Any]:
        state = self._state()
        next_state = save_first_pass(state, item_id, decision, self.clock(), expected_revision=state.revision)
        try:
            self.store.save(next_state, expected_revision=state.revision)
        except StoreError as exc:
            raise RuntimeErrorCode(exc.code) from exc
        return {"status": next_state.phase.value, "completed_count": len(next_state.first_pass)}

    def begin_review(self) -> dict[str, Any]:
        state = self._state()
        snapshot = self._snapshot()
        try:
            next_state = seal_for_review(state, snapshot, self.clock())
            if next_state is not state:
                self.store.save(next_state, expected_revision=state.revision)
        except (SessionError, StoreError) as exc:
            raise RuntimeErrorCode(getattr(exc, "code", "review_failed")) from exc
        return {"status": next_state.phase.value, "review_count": len(next_state.review_plan.item_ids) if next_state.review_plan else 0}

    def save_review(self, item_id: str, decision: Decision) -> dict[str, Any]:
        state = self._state()
        next_state = save_review(state, item_id, decision, self.clock(), expected_revision=state.revision)
        self.store.save(next_state, expected_revision=state.revision)
        return {"status": next_state.phase.value, "reviewed_count": len(next_state.review_decisions)}

    def adjudicate(self, item_id: str, decision: Decision) -> dict[str, Any]:
        state = self._state()
        next_state = adjudicate(state, item_id, decision, self.clock(), expected_revision=state.revision)
        self.store.save(next_state, expected_revision=state.revision)
        return {"status": next_state.phase.value, "adjudicated_count": len(next_state.adjudications)}

    def reopen(self, acknowledgement: str) -> dict[str, Any]:
        state = self._state()
        expected = self.status().get("acknowledgement")
        if acknowledgement != expected:
            raise RuntimeErrorCode("acknowledgement_mismatch")
        next_state = reopen(state, self.clock(), expected_revision=state.revision)
        self.store.save(next_state, expected_revision=state.revision)
        return {"status": next_state.phase.value, "generation": next_state.generation}

    def preview_finalize(self) -> dict[str, Any]:
        state = self._state()
        snapshot = self._snapshot()
        try:
            payloads, internal, labelset_id = build_bundle(
                snapshot, state, self._finalized_at(state)
            )
        except (SessionError, ValidationError, ValueError) as exc:
            raise RuntimeErrorCode(str(getattr(exc, "code", "not_ready_to_finalize"))) from exc
        import hashlib
        hashes = {name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()}
        draft_revision = state.revision
        if state.finalization_intent is not None:
            value = state.finalization_intent.get("draft_revision")
            if isinstance(value, int):
                draft_revision = value
        digest = challenge(
            DOMAIN_FINALIZE,
            {
                "dataset_id": DATASET_ID,
                "revision": draft_revision,
                "labels": internal["semantic_hashes"]["labels"],
                "review": internal["semantic_hashes"]["review"],
                "audit": internal["semantic_hashes"]["audit"],
                "labelset_id": labelset_id,
            },
        )
        return {
            "schema_version": "f10.2-cli-output-v1",
            "status": "ready_to_finalize",
            "dataset_id": DATASET_ID,
            "labelset_id": labelset_id,
            "count": PILOT_COUNT,
            "file_hashes": hashes,
            "challenge": (
                f"FINALIZE F10.2 dataset_id={DATASET_ID} rubric={RUBRIC_VERSION} "
                f"protocol={PROTOCOL_VERSION} draft_revision={draft_revision} "
                f"final_labels_sha256={internal['semantic_hashes']['labels']} "
                f"review_report_sha256={internal['semantic_hashes']['review']} "
                f"audit_sha256={internal['semantic_hashes']['audit']} "
                f"labelset_id={labelset_id} count=50 challenge_sha256={digest}"
            ),
        }

    def finalize(self, acknowledgement: str) -> FinalizedBundle:
        preview = self.preview_finalize()
        if acknowledgement != preview["challenge"]:
            raise RuntimeErrorCode("acknowledgement_mismatch")
        snapshot = self._snapshot()
        state = self._state()
        finalized_at = self._finalized_at(state)
        if state.finalization_intent is None:
            state = replace(
                state,
                finalization_intent={
                    "finalized_at": finalized_at,
                    "draft_revision": state.revision,
                },
            )
            try:
                self.store.save(state, expected_revision=state.revision)
            except StoreError as exc:
                raise RuntimeErrorCode(exc.code) from exc
        payloads, internal, labelset_id = build_bundle(snapshot, state, finalized_at)
        try:
            self.store.publish_final(
                labelset_id=labelset_id,
                payloads=payloads,
                internal=internal,
            )
        except StoreError as exc:
            raise RuntimeErrorCode(exc.code) from exc
        state = self._state()
        if state.phase is SessionPhase.FINALIZED:
            return FinalizedBundle(
                labelset_id,
                {"status": "finalized", "labelset_id": labelset_id, "count": 50},
            )
        try:
            finalized = mark_finalized(state, self.clock())
            self.store.save(finalized, expected_revision=state.revision)
        except (SessionError, StoreError) as exc:
            raise RuntimeErrorCode(getattr(exc, "code", "final_state_failed")) from exc
        return FinalizedBundle(
            labelset_id,
            {"status": "finalized", "labelset_id": labelset_id, "count": 50},
        )

    def verify(self, labelset_id: str) -> dict[str, Any]:
        try:
            internal, hashes = self.store.final_manifest(labelset_id)
        except StoreError as exc:
            raise RuntimeErrorCode(exc.code) from exc
        manifest = external_manifest(internal, hashes)
        manifest["status"] = "verified"
        return manifest


__all__ = ["BlindLabelingRuntime", "RuntimeErrorCode"]
