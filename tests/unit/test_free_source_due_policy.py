from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from role_radar.free_sources.due_policy import (
    JOBICY_CADENCE,
    is_due,
    next_slot,
    reserve_one_slot,
)
from role_radar.free_sources.terms import (
    JOBICY_TERMS_POLICY_VERSION,
    JobicyTermsAcceptance,
    validate_jobicy_terms,
)


def test_jobicy_due_boundary_and_no_catch_up_burst() -> None:
    slot = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
    assert not is_due(slot, slot - timedelta(seconds=1))
    assert is_due(slot, slot)
    assert reserve_one_slot(slot, slot + timedelta(hours=9)) == slot
    assert next_slot(slot) == slot + JOBICY_CADENCE


def test_due_policy_requires_fresh_complete_terms_acknowledgement() -> None:
    now = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
    assert validate_jobicy_terms(None, now=now) == "terms_missing"
    acceptance = JobicyTermsAcceptance(
        terms_url="https://jobicy.com/terms-and-conditions",
        reviewed_at=now,
        policy_version=JOBICY_TERMS_POLICY_VERSION,
        fair_use_ack=True,
        preserve_destination_ack=True,
        no_redistribution_ack=True,
    )
    assert validate_jobicy_terms(acceptance, now=now) is None
    assert (
        validate_jobicy_terms(
            replace(acceptance, policy_version="old-policy"),
            now=now,
        )
        == "terms_changed"
    )


def test_due_policy_rejects_naive_clock() -> None:
    with pytest.raises(ValueError):
        is_due(datetime(2026, 8, 9, 12, 0), datetime(2026, 8, 9, 12, 0, tzinfo=UTC))
