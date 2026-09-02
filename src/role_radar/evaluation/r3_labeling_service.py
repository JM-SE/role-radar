"""Thin synthetic-only R3 authority over the established blind-labeling core."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from role_radar.evaluation.blind_labeling.contracts import Decision, FinalizedBundle, PilotSnapshot
from role_radar.evaluation.blind_labeling.policy import RUBRIC_VERSION, pilot_count_scope
from role_radar.evaluation.blind_labeling.runtime import BlindLabelingRuntime, RuntimeErrorCode
from role_radar.evaluation.blind_labeling.store import LabelingStore
from role_radar.evaluation.r3_labeling_authorization import (
    PUBLIC_BLOCK_CODES,
    R3Authorization,
    R3AuthorizationError,
    validate_authorization,
)
from role_radar.evaluation.r3_labeling_input_adapter import (
    SyntheticGateFPublication,
    adapt_pilot_view,
)


class _SnapshotSource:
    def __init__(self, snapshot: PilotSnapshot) -> None:
        self._snapshot = snapshot

    def load(self) -> PilotSnapshot:
        return self._snapshot


class R3LabelingService:
    """The only supported entry point is an injected synthetic publication."""

    def __init__(
        self,
        authorization: R3Authorization,
        publication: SyntheticGateFPublication,
        *,
        root: Path,
        clock: Callable[[], str] | None = None,
        runtime_factory: Callable[..., BlindLabelingRuntime] = BlindLabelingRuntime,
    ) -> None:
        try:
            binding = validate_authorization(authorization, publication.binding)
            snapshot = adapt_pilot_view(publication, binding)
        except R3AuthorizationError:
            raise
        self._snapshot = snapshot
        self._active_count = binding.count
        kwargs: dict[str, Any] = {
            "root": root,
            "dataset_id": binding.dataset_id,
            "rubric_version": RUBRIC_VERSION,
        }
        store = LabelingStore(**kwargs)
        source = _SnapshotSource(snapshot)
        runtime_kwargs: dict[str, Any] = {
            "source": source,
            "store": store,
            "dataset_id": binding.dataset_id,
            "pilot_sha256": binding.pilot_sha256,
            "pilot_view_sha256": binding.pilot_view_sha256,
        }
        if clock is not None:
            runtime_kwargs["clock"] = clock
        self._runtime = runtime_factory(**runtime_kwargs)

    @property
    def snapshot(self) -> PilotSnapshot:
        return self._snapshot

    @staticmethod
    def _public(result: dict[str, Any]) -> dict[str, str | int]:
        allowed = {
            "status",
            "count",
            "completed_count",
            "review_count",
            "reviewed_count",
            "adjudicated_count",
            "generation",
            "labelset_id",
            "dataset_id",
        }
        return {
            key: value
            for key, value in result.items()
            if key in allowed and isinstance(value, (str, int))
        }

    def _call(self, method: Callable[..., Any], *args: Any) -> Any:
        with pilot_count_scope(self._active_count):
            return method(*args)

    def start(self, acknowledgement: str | None = None) -> dict[str, str | int]:
        if acknowledgement is None:
            status = self._call(self._runtime.status)
            acknowledgement = str(status["acknowledgement"])
        return self._public(self._call(self._runtime.start, acknowledgement))

    def save_first_pass(self, item_id: str, decision: Decision) -> dict[str, str | int]:
        return self._public(self._call(self._runtime.save_first_pass, item_id, decision))

    def begin_review(self) -> dict[str, str | int]:
        return self._public(self._call(self._runtime.begin_review))

    def save_review(self, item_id: str, decision: Decision) -> dict[str, str | int]:
        return self._public(self._call(self._runtime.save_review, item_id, decision))

    def adjudicate(self, item_id: str, decision: Decision) -> dict[str, str | int]:
        return self._public(self._call(self._runtime.adjudicate, item_id, decision))

    def preview_finalize(self) -> dict[str, str | int]:
        return self._public(self._call(self._runtime.preview_finalize))

    def finalize(self, acknowledgement: str | None = None) -> dict[str, str | int]:
        if acknowledgement is None:
            preview = self._call(self._runtime.preview_finalize)
            acknowledgement = str(preview["challenge"])
        bundle: FinalizedBundle = self._call(self._runtime.finalize, acknowledgement)
        return {
            "status": "finalized",
            "labelset_id": bundle.labelset_id,
            "count": len(self._snapshot.items),
        }


__all__ = ["PUBLIC_BLOCK_CODES", "R3LabelingService", "RuntimeErrorCode"]
