"""Versioned HMAC identities for transient planner queries."""

import hashlib
import hmac
from collections.abc import Iterable

from role_radar.discovery.contracts import PlannedQuery, QueryIdentity


class QueryKeyFactory:
    DOMAIN = b"role-radar/discovery-query-key/v1\0"

    def __init__(self, secret: bytes | bytearray | str) -> None:
        value = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if not value:
            raise ValueError("query HMAC secret must not be empty")
        self._secret = value

    def key(self, query: PlannedQuery, *, planner_version: str) -> str:
        message = (
            self.DOMAIN
            + planner_version.encode("utf-8")
            + b"\0"
            + query.canonical_query.encode("utf-8")
        )
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def identities(
        self, queries: Iterable[PlannedQuery], *, planner_version: str
    ) -> tuple[QueryIdentity, ...]:
        return tuple(
            QueryIdentity(
                q.ordinal,
                q.family,
                q.provider_intent,
                self.key(q, planner_version=planner_version),
            )
            for q in queries
        )

    def planner_hash(self, identities: Iterable[QueryIdentity], *, planner_version: str) -> str:
        payload = "\n".join(
            f"{item.ordinal}|{item.family}|{item.provider_intent.value}|{item.query_key}"
            for item in identities
        )
        return hmac.new(
            self._secret,
            self.DOMAIN + planner_version.encode("utf-8") + b"\0" + payload.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def matches(self, expected: str, actual: str) -> bool:
        return hmac.compare_digest(expected, actual)
