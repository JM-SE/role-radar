"""F9.1 URL and redirect policy tests."""

import pytest

from role_radar.mailbox.linkedin_resolution.policy import (
    ResolutionPolicyError,
    classify_location,
    validate_linkedin_url,
)


def test_only_audited_linkedin_hosts_are_accepted() -> None:
    assert validate_linkedin_url("https://ar.linkedin.com/jobs/1").host == "ar.linkedin.com"
    assert validate_linkedin_url("https://www.linkedin.com/jobs/1").host == "www.linkedin.com"
    for url in (
        "https://linkedin.com/jobs/1",
        "https://evil.linkedin.com/jobs/1",
        "https://www.linkedin.com./jobs/1",
        "https://WWW.linkedin.com/jobs/1",
        "http://www.linkedin.com/jobs/1",
        "https://user:pass@www.linkedin.com/jobs/1",
    ):
        with pytest.raises(ResolutionPolicyError):
            validate_linkedin_url(url)


def test_location_can_be_relative_linkedin_or_exact_ats_posting() -> None:
    linked = classify_location(
        "https://www.linkedin.com/jobs/1?trk=redacted", "/jobs/view/2?trk=next"
    )
    assert linked.host == "www.linkedin.com"
    ats = classify_location(
        "https://www.linkedin.com/jobs/1",
        "https://job-boards.greenhouse.io/acme/jobs/eng-1",
    )
    assert ats.final_ats.provider == "greenhouse"  # type: ignore[attr-defined]
    assert ats.final_ats.external_id == "eng-1"  # type: ignore[attr-defined]


def test_location_rejects_unknown_hosts_and_board_only_ats() -> None:
    for location in (
        "https://evil.example/redirect",
        "https://boards.greenhouse.io/acme",
        "https://jobs.lever.co/acme/apply",
        "https://jobs.lever.co/acme/eng-1?x=1",
    ):
        with pytest.raises(ResolutionPolicyError):
            classify_location("https://www.linkedin.com/jobs/1", location)
