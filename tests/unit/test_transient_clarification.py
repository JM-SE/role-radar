from role_radar.matching.transient_clarification import (
    MAX_DESCRIPTION_CHARS,
    POLICY_VERSION,
    clarify_description,
)


def test_clarifies_explicit_remote_scope_and_latam_exception() -> None:
    evidence = clarify_description(
        "This is a fully remote position. Work remotely from Latin America, excluding Argentina."
    )
    assert evidence is not None
    assert evidence.policy_version == POLICY_VERSION
    assert evidence.remote_policy == "remote"
    assert evidence.regions == ("latam",)
    assert evidence.excluded_regions == ("argentina",)
    assert not evidence.conflict


def test_ambiguous_negated_and_unscoped_text_abstains() -> None:
    assert clarify_description("Remote work may be available depending on the team.") is None
    assert clarify_description("We are not a remote company.") is None
    assert clarify_description("Remote experience is a plus. Argentina office team.") is None


def test_conflicting_explicit_modalities_are_not_resolved_by_voting() -> None:
    evidence = clarify_description("Fully remote role. Hybrid work required twice weekly.")
    assert evidence is not None
    assert evidence.remote_policy is None
    assert evidence.conflict


def test_unknown_modality_with_explicit_region_is_transient_evidence() -> None:
    evidence = clarify_description("We are hiring candidates based in Argentina.")
    assert evidence is not None
    assert evidence.remote_policy is None
    assert evidence.regions == ("argentina",)


def test_parser_input_is_bounded() -> None:
    text = "Fully remote position. Work remotely from Argentina." + "x" * MAX_DESCRIPTION_CHARS
    assert clarify_description(text) is None
