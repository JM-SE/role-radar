"""Deterministic, code-owned query planner for CandidateProfileV1."""

from collections.abc import Iterable

from role_radar.discovery.contracts import PlannedQuery, ProviderIntent
from role_radar.domain.profile import CandidateProfileV1

PLANNER_VERSION = "query-planner-v1"
MAX_QUERIES_PER_CYCLE = 24

# These are deliberately closed.  A profile value not in one of these maps is
# useful for matching but is not allowed to become an external search query.
ROLE_VOCABULARY = frozenset({"backend", "full_stack", "platform", "site_reliability", "software"})
REGION_VOCABULARY = frozenset({"argentina", "latam", "latin_america", "spain", "europe", "remote"})
TECHNOLOGY_VOCABULARY = frozenset(
    {"python", "typescript", "javascript", "go", "java", "rust", "kubernetes", "postgres"}
)
EMPLOYMENT_VOCABULARY = frozenset(
    {"full_time", "part_time", "contractor", "temporary", "internship"}
)
LANGUAGE_VOCABULARY = frozenset({"english", "spanish", "french"})


def _safe(values: Iterable[str], vocabulary: frozenset[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value in vocabulary}))


class QueryPlannerV1:
    version = PLANNER_VERSION

    def plan(self, profile: CandidateProfileV1) -> tuple[PlannedQuery, ...]:
        if not isinstance(profile, CandidateProfileV1):
            raise TypeError("QueryPlannerV1 requires CandidateProfileV1")
        roles = _safe(profile.target_roles, ROLE_VOCABULARY)
        regions = _safe(profile.regions, REGION_VOCABULARY)
        technologies = _safe(
            (*profile.core_skills, *profile.secondary_skills), TECHNOLOGY_VOCABULARY
        )
        employment = _safe(profile.employment_preferences, EMPLOYMENT_VOCABULARY)
        languages = _safe(profile.languages, LANGUAGE_VOCABULARY)
        remote = "remote" if profile.remote_only else None
        output: list[PlannedQuery] = []

        # Family order is part of the v1 contract.  First-wins deduplication
        # happens before ordinals are assigned and before the 24 item cut.
        for role in roles:
            for region in regions or (None,):
                suffix = " ".join(
                    item for item in (region, remote, *employment[:1], *languages[:1]) if item
                )
                text = " ".join(item for item in (role.replace("_", " "), suffix) if item)
                for family, host in (
                    ("greenhouse_role_region", "site:boards.greenhouse.io"),
                    ("lever_role_region", "site:jobs.lever.co"),
                ):
                    output.append(PlannedQuery(0, family, ProviderIntent.EXACT, f"{host} {text}"))
        for role in roles:
            for technology in technologies:
                text = f'{role.replace("_", " ")} {technology}'
                for family, host in (
                    ("greenhouse_role_technology", "site:boards.greenhouse.io"),
                    ("lever_role_technology", "site:jobs.lever.co"),
                ):
                    output.append(PlannedQuery(0, family, ProviderIntent.EXACT, f"{host} {text}"))
        unique: list[PlannedQuery] = []
        seen: set[tuple[str, str]] = set()
        for item in output:
            identity = (item.family, item.canonical_query)
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(
                PlannedQuery(len(unique), item.family, item.provider_intent, item.canonical_query)
            )
            if len(unique) == MAX_QUERIES_PER_CYCLE:
                break
        return tuple(unique)
