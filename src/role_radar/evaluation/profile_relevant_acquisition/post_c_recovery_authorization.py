"""Pure authorization contracts for recovered Gate C Post-C."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

HEX64: Final = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
APPROVAL: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
IDENTITY: Final = HEX64
UTC_RFC3339: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$", re.ASCII)
ACTION: Final = "offline_preregistration"
STATE: Final = "completed_partial"
TERMINAL: Final = "multiple_budgets_exhausted"
RECOVERED_OPERATION_ID: Final = "ca3fbc4d-7f8e-49a6-8263-c1fdd69bbad5"
RECOVERED_OPERATION_SHA256: Final = (
    "6233bfc55cd8568d0c981dcab4ce10b6121f31d1721734cd886eebf4f780f749"
)
RECOVERED_PROFILE_ID: Final = "818eded4-2f69-4e66-ad12-cd0749e4ab3e"
RECOVERED_PROFILE_VERSION: Final = 2
RECOVERED_PROFILE_SHA256: Final = "2a01d22969d3a8811a3816adba699ffad3e2946ae2e54527e0495c63cc467918"
RECOVERED_POLICY_SHA256: Final = "387ed6fa43c2be8001cf10a1b1fb645eead6f6cecefb606e450d53bd016f1cc0"
RECOVERED_PLAN_SHA256: Final = "e7ea8287e7cb1d1d4f2f32ffb8c0db84b1889bf70be404a96778b34a9afc2b95"
RECOVERED_REPORT_SHA256: Final = "3f816b91d078e9f91ed78422f44189d61f265dee582a1daa4387337638817de0"
RECOVERED_SOURCE_PLAN_SHA256: Final = (
    "def7b57e24be9eb0f360c4b06ede67de9f71e105657afad8efc8820b69dd9846"
)
RECOVERED_EVIDENCE_SHA256: Final = (
    "11a6283a0026e19fc0275f45ac47da34894c91a9e0b8d051a9b5e4a7cebadd4c"
)
RECOVERED_SOURCE_KEYS: Final = (
    "greenhouse:twilio",
    "greenhouse:grafanalabs",
    "greenhouse:similarweb",
    "greenhouse:stackline",
    "greenhouse:postman",
    "greenhouse:figma",
)
RECOVERED_SEARCH_REQUEST_IDENTITIES: Final = (
    "fc4279038bd0630bdd8bd36e4c4541264ac460f70d8a86b217a348a35766fa37",
    "3e2181315a125d6852c7e1e3ca502c218990cdbfac210b4097782bb39daea998",
    "585e5aae3a20cd034aa78a064940365a59427d7f9e97b7be04f5a8e1816c7d28",
    "e0ce0d1a7b0a2918abf590139b370e1f8dbe8196b72eaebb23c08d6585614131",
)
RECOVERED_OFFICIAL_REQUEST_IDENTITIES: Final = (
    "2d6b7e9670378e31e0cc6c3787075b22d46ef7fdb6da17b5f5cb5277ed7aea09",
    "7af2a6c4b3ae6f85273ea346f176f8d6892278db2242b12ebcc521385ee66985",
    "a0fb48201f3dda291bc9437d24b4e8629ee12d66fc7f2c9061ff75c7cb72be8e",
    "964da20b8183f454d8dc0ae06d469176ce6975982618ca82ad36329b564ce066",
    "2a824ff99c9d044d4786aea414a933bec5abaab98b0be51bdedc3e13e24edd39",
    "c3bddb5fdaf4ae5e5caebdbfa0138e212d3115b435a6a8a63b4fe59d7a767af0",
    "502db48087234f5e008d1e9a7888d098ef8489085f40d012518c95db573cdfe5",
    "b321c2f6b69334039a725670bca9d60f785088e37834fa5ee8460bedfb0a2dd0",
)
HISTORICAL_PACKET_SHA256: Final = "7088f09efce0b4c921d89010a5d6909568dcb16e1516a3151f13bbfa15624d0f"
RECOVERY_MANIFEST_SHA256: Final = "a4f273f59015c00580509d0c697eb7a4d5f131fb46d1e237b21cbf1a93a58d1b"
RECOVERY_VERDICT_SHA256: Final = "a4ec7f1d35a28dd21df7cd118092a70b501a38f69696664a8967a82cf5ef4c0d"


class PostCRecoveryAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _utc(value: str, code: str) -> datetime:
    if UTC_RFC3339.fullmatch(value) is None:
        raise PostCRecoveryAuthorizationError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PostCRecoveryAuthorizationError(code) from exc
    return parsed


@dataclass(frozen=True, slots=True)
class PostCAuthorization:
    """Fresh operator authority for one offline local Post-C effect."""

    action: str
    approval_reference: str
    operator_id: str
    window_start_utc: str
    expires_at_utc: str
    historical_root: str
    recovery_root: str
    output_root: str
    operation_id: str
    operation_sha256: str
    profile_id: str
    profile_version: int
    profile_sha256: str
    policy_sha256: str
    plan_sha256: str
    report_sha256: str
    source_plan_sha256: str
    evidence_sha256: str
    historical_approval_reference: str
    source_keys: tuple[str, ...]
    search_request_identities: tuple[str, ...]
    official_request_identities: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.action != ACTION or APPROVAL.fullmatch(self.approval_reference) is None:
            raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_invalid")
        if APPROVAL.fullmatch(self.historical_approval_reference) is None:
            raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_invalid")
        if type(self.profile_version) is not int or self.profile_version < 1:
            raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_invalid")
        for value in (
            self.operator_id,
            self.window_start_utc,
            self.expires_at_utc,
            self.historical_root,
            self.recovery_root,
            self.output_root,
            self.operation_id,
            self.profile_id,
        ):
            if type(value) is not str or not value.strip():
                raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_invalid")
        roots = tuple(
            Path(value) for value in (self.historical_root, self.recovery_root, self.output_root)
        )
        if any(not root.is_absolute() for root in roots):
            raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_invalid")
        if any(".." in root.parts for root in roots):
            raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_invalid")
        for left_index, left in enumerate(roots):
            for right in roots[left_index + 1 :]:
                if left == right or left in right.parents or right in left.parents:
                    raise PostCRecoveryAuthorizationError("post_c_recovery_roots_overlap")
        start = _utc(self.window_start_utc, "post_c_recovery_window_invalid")
        expiry = _utc(self.expires_at_utc, "post_c_recovery_window_invalid")
        if not start < expiry:
            raise PostCRecoveryAuthorizationError("post_c_recovery_window_invalid")
        hashes = (
            self.operation_sha256,
            self.profile_sha256,
            self.policy_sha256,
            self.plan_sha256,
            self.report_sha256,
            self.source_plan_sha256,
            self.evidence_sha256,
        )
        if any(type(value) is not str or HEX64.fullmatch(value) is None for value in hashes):
            raise PostCRecoveryAuthorizationError("post_c_recovery_hash_invalid")
        if not self.operation_id.strip() or len(self.operation_id) > 128:
            raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_invalid")
        if (
            type(self.source_keys) is not tuple
            or type(self.search_request_identities) is not tuple
            or type(self.official_request_identities) is not tuple
        ):
            raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_invalid")
        if any(type(value) is not str or not value.strip() for value in self.source_keys):
            raise PostCRecoveryAuthorizationError("post_c_recovery_sources_invalid")
        for identities in (self.search_request_identities, self.official_request_identities):
            if any(
                type(value) is not str or IDENTITY.fullmatch(value) is None for value in identities
            ):
                raise PostCRecoveryAuthorizationError("post_c_recovery_identity_invalid")
        if (
            len(self.source_keys) != 6
            or len(set(self.source_keys)) != 6
            or len(set(self.search_request_identities)) != len(self.search_request_identities)
            or len(set(self.official_request_identities)) != len(self.official_request_identities)
            or not self.official_request_identities
        ):
            raise PostCRecoveryAuthorizationError("post_c_recovery_sources_invalid")
        if self.window_start_utc != start.isoformat().replace(
            "+00:00", "Z"
        ) or self.expires_at_utc != expiry.isoformat().replace("+00:00", "Z"):
            raise PostCRecoveryAuthorizationError("post_c_recovery_window_invalid")

    def validate_current(self, now: datetime) -> None:
        if now.tzinfo is not UTC:
            raise PostCRecoveryAuthorizationError("post_c_recovery_clock_invalid")
        start = _utc(self.window_start_utc, "post_c_recovery_window_invalid")
        expiry = _utc(self.expires_at_utc, "post_c_recovery_window_invalid")
        if not start <= now < expiry:
            raise PostCRecoveryAuthorizationError("post_c_recovery_authorization_expired")

    def is_current(self, now: datetime | None = None) -> bool:
        try:
            self.validate_current(now or datetime.now(UTC))
        except PostCRecoveryAuthorizationError:
            return False
        return True

    @property
    def authorization_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def canonical_bytes(self) -> bytes:
        import json

        return json.dumps(
            {name: getattr(self, name) for name in self.__dataclass_fields__},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def validate_recovered_anchors(self) -> None:
        expected = (
            self.operation_id == RECOVERED_OPERATION_ID,
            self.operation_sha256 == RECOVERED_OPERATION_SHA256,
            self.profile_id == RECOVERED_PROFILE_ID,
            self.profile_version == RECOVERED_PROFILE_VERSION,
            self.profile_sha256 == RECOVERED_PROFILE_SHA256,
            self.policy_sha256 == RECOVERED_POLICY_SHA256,
            self.plan_sha256 == RECOVERED_PLAN_SHA256,
            self.report_sha256 == RECOVERED_REPORT_SHA256,
            self.source_plan_sha256 == RECOVERED_SOURCE_PLAN_SHA256,
            self.evidence_sha256 == RECOVERED_EVIDENCE_SHA256,
            self.source_keys == RECOVERED_SOURCE_KEYS,
            self.search_request_identities == RECOVERED_SEARCH_REQUEST_IDENTITIES,
            self.official_request_identities == RECOVERED_OFFICIAL_REQUEST_IDENTITIES,
        )
        if not all(expected):
            raise PostCRecoveryAuthorizationError("post_c_recovery_trust_anchor_mismatch")


__all__ = [
    "ACTION",
    "HISTORICAL_PACKET_SHA256",
    "RECOVERED_EVIDENCE_SHA256",
    "RECOVERED_OFFICIAL_REQUEST_IDENTITIES",
    "RECOVERED_OPERATION_ID",
    "RECOVERED_OPERATION_SHA256",
    "RECOVERED_PLAN_SHA256",
    "RECOVERED_POLICY_SHA256",
    "RECOVERED_PROFILE_ID",
    "RECOVERED_PROFILE_SHA256",
    "RECOVERED_PROFILE_VERSION",
    "RECOVERED_REPORT_SHA256",
    "RECOVERED_SEARCH_REQUEST_IDENTITIES",
    "RECOVERED_SOURCE_KEYS",
    "RECOVERED_SOURCE_PLAN_SHA256",
    "RECOVERY_MANIFEST_SHA256",
    "RECOVERY_VERDICT_SHA256",
    "STATE",
    "TERMINAL",
    "PostCAuthorization",
    "PostCRecoveryAuthorizationError",
]
