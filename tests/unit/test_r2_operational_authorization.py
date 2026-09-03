from datetime import UTC, datetime, timedelta

import pytest

from role_radar.evaluation.r2_operational_authorization import (
    AuthorizationError,
    OperationPacket,
    authorize_packet,
    parse_operation_packet,
)

H = "a" * 64


def packet() -> OperationPacket:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return OperationPacket(
        "op-1",
        "c",
        H,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        "f" * 64,
        "namespace",
        "root",
        now,
        now + timedelta(hours=1),
        H,
        "b" * 64,
        1,
        1,
        1,
        1,
        "capability",
        "approval",
        H,
        now + timedelta(hours=1),
        "nonce",
        (H,),
    )


class Verifier:
    def __init__(self, value: bool = True) -> None:
        self.value = value

    def verify(self, _packet: OperationPacket, _reference: str) -> bool:
        return self.value


def test_packet_is_canonical_and_strict() -> None:
    parsed = parse_operation_packet(packet().canonical_dict())
    assert parsed.packet_sha256 == packet().packet_sha256
    with pytest.raises(AuthorizationError) as error:
        parse_operation_packet({**packet().canonical_dict(), "unexpected": 1})
    assert error.value.code == "malformed_packet"


def test_authorization_rejects_expiry_replay_and_unverified_approval() -> None:
    with pytest.raises(AuthorizationError, match="expired"):
        authorize_packet(packet(), Verifier(), now=datetime(2026, 1, 1, 2, tzinfo=UTC))
    with pytest.raises(AuthorizationError, match="replay"):
        authorize_packet(
            packet(),
            Verifier(),
            now=datetime(2026, 1, 1, tzinfo=UTC),
            used_nonces=frozenset({"nonce"}),
        )
    with pytest.raises(AuthorizationError, match="approval_invalid"):
        authorize_packet(packet(), Verifier(False), now=datetime(2026, 1, 1, tzinfo=UTC))
