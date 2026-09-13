"""Propuesta y aplicación explícita de refinamiento de la policy de discovery."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy.orm import Session

from role_radar.acquisition.discovery_policy import LoadedDiscoveryPolicyV1
from role_radar.discovery.policy import DiscoveryPolicyV1
from role_radar.repositories.feedback import FeedbackRepository
from role_radar.services.feedback_service import collect_candidates

MIN_GROUP_DECISIONS: int = 3

_TOP_LEVEL_ORDER: tuple[str, ...] = (
    "schema_version",
    "policy_version",
    "profile_binding",
    "phrase_grammar",
    "groups",
    "target_roles",
    "target_titles",
)


def _plain(value: object) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _term_binding(value: object) -> dict[str, Any]:
    primary = getattr(value, "primary_groups", None)
    coverage = getattr(value, "coverage_groups", None)
    if not isinstance(primary, (list, tuple)) or not isinstance(coverage, (list, tuple)):
        raise ValueError("refinement_policy_invalid")
    return {"primary_groups": list(primary), "coverage_groups": list(coverage)}


def _binding_map(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("refinement_policy_invalid")
    return {str(key): _term_binding(item) for key, item in value.items()}


def policy_payload(
    policy: DiscoveryPolicyV1 | LoadedDiscoveryPolicyV1 | Mapping[str, object],
) -> dict[str, Any]:
    """Return a plain JSON-compatible mapping for one validated policy."""

    if isinstance(policy, LoadedDiscoveryPolicyV1):
        dto = policy.policy
    elif isinstance(policy, DiscoveryPolicyV1):
        dto = policy
    else:
        dto = DiscoveryPolicyV1.model_validate(policy)
    binding = dto.profile_binding
    groups = _plain(dto.groups)
    grammar = dto.phrase_grammar.model_dump(mode="python")
    if not isinstance(groups, dict):
        raise ValueError("refinement_policy_invalid")
    return {
        "schema_version": dto.schema_version,
        "policy_version": dto.policy_version,
        "profile_binding": {
            "profile_id": binding.profile_id,
            "row_version": binding.row_version,
            "schema_version": binding.schema_version,
            "canonical_profile_sha256": binding.canonical_profile_sha256,
        },
        "phrase_grammar": _plain(grammar),
        "groups": groups,
        "target_roles": _binding_map(dto.target_roles),
        "target_titles": _binding_map(dto.target_titles),
    }


def _policy_mapping(
    policy: DiscoveryPolicyV1 | LoadedDiscoveryPolicyV1 | Mapping[str, object],
) -> dict[str, Any]:
    return policy_payload(policy)


def _coverage_groups(payload: Mapping[str, Any]) -> set[str]:
    coverage: set[str] = set()
    for section in ("target_roles", "target_titles"):
        bindings = payload.get(section, {})
        if isinstance(bindings, Mapping):
            for binding in bindings.values():
                if isinstance(binding, Mapping):
                    groups = binding.get("coverage_groups", ())
                    if isinstance(groups, (list, tuple)):
                        coverage.update(str(group) for group in groups)
    return coverage


def _group_hits(groups: Mapping[str, Any], title: str, description: str) -> set[str]:
    folded = f"{title}\n{description}".casefold()
    hits: set[str] = set()
    for group_id, phrases in groups.items():
        if not isinstance(phrases, (list, tuple)):
            continue
        for phrase in phrases:
            if isinstance(phrase, str) and phrase and phrase.casefold() in folded:
                hits.add(str(group_id))
                break
    return hits


def propose_refinement(
    session: Session,
    run_id: str,
    policy: DiscoveryPolicyV1 | LoadedDiscoveryPolicyV1 | Mapping[str, object],
    *,
    min_decisions: int = MIN_GROUP_DECISIONS,
) -> dict[str, Any]:
    """Atribuye decisiones por grupo y propone retirar coberturas sin precisión."""

    payload = _policy_mapping(policy)
    groups = payload.get("groups", {})
    if not isinstance(groups, Mapping):
        raise ValueError("refinement_policy_invalid")
    coverage = _coverage_groups(payload)
    applies: dict[str, int] = {str(group_id): 0 for group_id in groups}
    rejects: dict[str, int] = {str(group_id): 0 for group_id in groups}
    latest = FeedbackRepository(session).latest_for_run(run_id)
    candidates = {item.job_id: item for item in collect_candidates(session, run_id)}
    for job_id, row in latest.items():
        candidate = candidates.get(job_id)
        if candidate is None:
            continue
        hits = _group_hits(groups, candidate.title, candidate.description)
        if row.label == "apply":
            for group_id in hits:
                applies[group_id] += 1
        elif row.label == "reject":
            for group_id in hits:
                rejects[group_id] += 1
    entries: list[dict[str, Any]] = []
    removals: list[str] = []
    for group_id in sorted(applies):
        total = applies[group_id] + rejects[group_id]
        precision = (applies[group_id] / total) if total else None
        primary = group_id not in coverage
        action = "keep"
        if not primary and total >= min_decisions and applies[group_id] == 0:
            action = "remove"
            removals.append(group_id)
        entries.append(
            {
                "group_id": group_id,
                "primary": primary,
                "decisions": total,
                "applies": applies[group_id],
                "rejects": rejects[group_id],
                "precision": precision,
                "action": action,
            }
        )
    validated = DiscoveryPolicyV1.model_validate(payload)
    return {
        "run_id": run_id,
        "policy_version": validated.policy_version,
        "min_decisions": min_decisions,
        "groups": entries,
        "removals": removals,
    }


def _emit_toml_value(value: object) -> str:
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, bool):
        raise ValueError("refinement_toml_unsupported")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_emit_toml_value(item) for item in value) + "]"
    raise ValueError("refinement_toml_unsupported")


def _emit_key(key: str) -> str:
    if key and all(char.isascii() and (char.isalnum() or char in "-_") for char in key):
        return key
    return _emit_toml_value(key)


def _emit_toml_table(lines: list[str], header: str, payload: Mapping[str, Any]) -> None:
    lines.append(f"[{header}]")
    for key in sorted(payload):
        value = payload[key]
        if isinstance(value, Mapping):
            continue
        lines.append(f"{_emit_key(str(key))} = {_emit_toml_value(value)}")
    for key in sorted(payload):
        value = payload[key]
        if isinstance(value, Mapping):
            _emit_toml_table(lines, f"{header}.{_emit_key(str(key))}", value)
    lines.append("")


def emit_policy_toml(payload: Mapping[str, Any]) -> str:
    """Serializa una policy validada a TOML determinista."""

    lines: list[str] = []
    for key in _TOP_LEVEL_ORDER:
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, Mapping):
            _emit_toml_table(lines, key, value)
        else:
            lines.append(f"{key} = {_emit_toml_value(value)}")
    for key in sorted(payload):
        if key in _TOP_LEVEL_ORDER:
            continue
        value = payload[key]
        if isinstance(value, Mapping):
            _emit_toml_table(lines, key, value)
        else:
            lines.append(f"{key} = {_emit_toml_value(value)}")
    return "\n".join(lines).rstrip("\n") + "\n"


def apply_refinement(
    policy: DiscoveryPolicyV1 | LoadedDiscoveryPolicyV1 | Mapping[str, object],
    removals: Sequence[str],
    *,
    new_policy_version: str,
) -> str:
    """Retira grupos de cobertura y emite la policy sucesora validada."""

    payload = _policy_mapping(policy)
    groups = dict(payload.get("groups", {}))
    condemned = set(removals)
    if not condemned:
        raise ValueError("refinement_empty_removals")
    unknown = condemned - set(groups)
    if unknown:
        raise ValueError("refinement_unknown_group")
    coverage = _coverage_groups(payload)
    primary_hit = condemned - coverage
    if primary_hit:
        raise ValueError("refinement_primary_group_protected")
    for group_id in condemned:
        del groups[group_id]
    payload["groups"] = groups
    for section in ("target_roles", "target_titles"):
        bindings = payload.get(section, {})
        if isinstance(bindings, Mapping):
            payload[section] = {
                name: (
                    {
                        **binding,
                        "coverage_groups": [
                            group for group in binding["coverage_groups"] if group not in condemned
                        ],
                    }
                    if isinstance(binding, Mapping)
                    and isinstance(binding.get("coverage_groups"), (list, tuple))
                    else binding
                )
                for name, binding in bindings.items()
            }
    payload["policy_version"] = new_policy_version
    validated = DiscoveryPolicyV1.model_validate(payload)
    return emit_policy_toml(policy_payload(validated))
