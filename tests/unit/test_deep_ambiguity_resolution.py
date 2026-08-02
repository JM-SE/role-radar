from role_radar.deep_evaluation.ambiguity_resolution import resolve_ambiguities_v1


def test_resolves_only_exact_valid_extraction_with_evidence() -> None:
    ambiguity = [{"code": "remote_policy_unknown", "field": "remote_policy"}]
    extraction = {
        "id": "e1",
        "validation_status": "valid",
        "extraction_json": {"remote_policy": {"evidence": "remote"}},
    }
    assert resolve_ambiguities_v1(ambiguity, "e1", extraction)[0].question
    assert resolve_ambiguities_v1(ambiguity, "stale", extraction) == ()
    assert resolve_ambiguities_v1([{"code": "unknown", "field": "x"}], "e1", extraction) == ()


def test_missing_or_invalid_evidence_is_not_resolvable() -> None:
    value = {
        "id": "e1",
        "validation_status": "valid",
        "extraction_json": {"remote_policy": {"evidence": None}},
    }
    assert (
        resolve_ambiguities_v1(
            [{"code": "remote_policy_unknown", "field": "remote_policy"}], "e1", value
        )
        == ()
    )
