from datetime import UTC, datetime, timedelta

import pytest

from role_radar.evaluation.r2_operational_authorization import AuthorizationError, OperationPacket
from role_radar.evaluation.r2_operational_capabilities import (
    IndependentCapabilityVerifier,
    ProductionR2Capability,
    validate_capability,
)


def packet() -> OperationPacket:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return OperationPacket(
        "op-1",
        "c",
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        "f" * 64,
        "namespace",
        "root",
        now,
        now + timedelta(hours=1),
        "a" * 64,
        "b" * 64,
        1,
        1,
        1,
        1,
        "capability",
        "approval",
        "a" * 64,
        now + timedelta(hours=1),
        "nonce",
        ("a" * 64,),
    )


def test_capability_requires_independent_approval_and_exact_plan() -> None:
    value = IndependentCapabilityVerifier().verify("capability", packet().source_plan_sha256)
    assert validate_capability(value, packet()) is value
    with pytest.raises(AuthorizationError):
        validate_capability(
            IndependentCapabilityVerifier().verify("capability", "a" * 64), packet()
        )
    with pytest.raises(AuthorizationError):
        validate_capability(True, packet())


def test_public_constructor_cannot_supply_verification() -> None:
    with pytest.raises(TypeError):
        ProductionR2Capability("capability", packet().source_plan_sha256, True)
