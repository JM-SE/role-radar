"""Strict JSON decoding with deterministic depth and node limits."""

import json
from collections.abc import Mapping
from typing import Any


class BoundedJsonError(ValueError):
    """JSON cannot be accepted without exposing provider details."""


class _DuplicateKey(ValueError):
    pass


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise BoundedJsonError("non-finite number")


def validate_tree(value: Any, *, max_depth: int = 32, max_nodes: int = 100_000) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise BoundedJsonError("JSON bounds exceeded")
        if isinstance(item, dict):
            for _key, child in item.items():
                nodes += 1  # object keys are nodes too
                if nodes > max_nodes:
                    raise BoundedJsonError("JSON bounds exceeded")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)

    visit(value, 0)


def loads_bounded(
    payload: bytes,
    *,
    max_depth: int = 32,
    max_nodes: int = 100_000,
) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_nonfinite,
        )
        validate_tree(value, max_depth=max_depth, max_nodes=max_nodes)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, BoundedJsonError) as exc:
        if isinstance(exc, BoundedJsonError):
            raise
        raise BoundedJsonError("invalid JSON") from exc


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BoundedJsonError("value is not canonical JSON") from exc


def ensure_object(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise BoundedJsonError("JSON object required")
    return value
