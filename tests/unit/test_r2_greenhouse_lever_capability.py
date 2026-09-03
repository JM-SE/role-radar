from datetime import UTC, datetime

import pytest

from role_radar.evaluation.r2_greenhouse_lever_capability import (
    ALLOWED_FAMILIES,
    GreenhouseLeverVerification,
)


def test_scope_is_exact_and_claims_are_sealed() -> None:
    assert ALLOWED_FAMILIES == ("greenhouse", "lever")
    with pytest.raises(TypeError):
        GreenhouseLeverVerification("greenhouse", "x")


def test_verification_is_frozen() -> None:
    assert GreenhouseLeverVerification.__dataclass_params__.frozen
    assert datetime.now(UTC).tzinfo is UTC
