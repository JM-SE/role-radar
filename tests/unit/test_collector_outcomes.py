"""Contracts and conservation invariants for bounded collector outcomes."""

from datetime import UTC, datetime

import pytest

from role_radar.collectors.outcomes import (
    CollectionFailure,
    CollectionMetrics,
    CollectionSuccess,
    CollectorFailureCode,
    RejectionCounts,
)
from role_radar.domain.dto import RawJob


def _job() -> RawJob:
    return RawJob(
        source="greenhouse",
        external_id="1",
        title="Engineer",
        company="Acme",
        description="Build APIs",
        source_url="https://boards.greenhouse.io/acme/jobs/1",
        collected_at=datetime.now(UTC),
    )


def test_success_conserves_data_items_and_is_immutable() -> None:
    rejection = RejectionCounts(invalid_item=1, duplicate_identical=1)
    outcome = CollectionSuccess(
        status="partial",
        jobs=(_job(),),
        metrics=CollectionMetrics(
            provider_items=3,
            accepted_items=1,
            rejected_items=1,
            duplicate_items=1,
        ),
        rejection_counts=rejection,
    )
    assert outcome.jobs == (outcome.jobs[0],)
    with pytest.raises((AttributeError, TypeError)):
        outcome.status = "ok"  # type: ignore[misc]


def test_empty_success_is_usable_and_all_invalid_is_failure() -> None:
    empty = CollectionSuccess(status="ok", jobs=(), metrics=CollectionMetrics())
    assert empty.jobs == ()
    with pytest.raises(ValueError):
        CollectionSuccess(
            status="partial",
            jobs=(),
            metrics=CollectionMetrics(),
        )
    failure = CollectionFailure(
        status="failed",
        error_code=CollectorFailureCode.NO_VALID_ITEMS,
        metrics=CollectionMetrics(
            provider_items=2,
            rejected_items=2,
        ),
        rejection_counts=RejectionCounts(invalid_item=2),
    )
    assert failure.status == "failed"
    assert not hasattr(failure, "source_id")
    assert not hasattr(failure, "jobs")


def test_invalid_metrics_are_rejected() -> None:
    with pytest.raises(ValueError):
        CollectionMetrics(wire_bytes=-1)
    with pytest.raises(ValueError):
        CollectionSuccess(
            status="ok",
            jobs=(_job(),),
            metrics=CollectionMetrics(accepted_items=1),
        )
