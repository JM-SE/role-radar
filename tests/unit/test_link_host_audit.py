"""Pure F9.0 host audit tests."""

from role_radar.mailbox.link_host_audit import audit_link_hosts


def test_audit_is_deterministic_and_counts_url_shapes() -> None:
    result = audit_link_hosts(
        (
            "https://linkedin.com/jobs/view/1?trk=mail#top",
            "https://boards.greenhouse.io/acme/jobs/eng-1",
            "http://unknown.example/jobs",
        )
    )

    assert result.validated
    assert result.total_url_count == 3
    assert [item.host for item in result.host_summaries] == [
        "boards.greenhouse.io",
        "linkedin.com",
        "unknown.example",
    ]
    assert result.host_summaries[0].direct_ats_greenhouse_count == 1
    assert result.host_summaries[1].query_present_count == 1
    assert result.host_summaries[2].unknown


def test_audit_rejects_adversarial_url_without_partial_report() -> None:
    result = audit_link_hosts(("https://user:pass@linkedin.com/jobs/1",))

    assert not result.validated
    assert result.terminal_code == "unsafe_url"
    assert result.host_summaries == ()


def test_audit_fail_closed_at_url_and_host_caps() -> None:
    too_many_urls = audit_link_hosts(tuple(f"https://host.example/{i}" for i in range(101)))
    assert too_many_urls.terminal_code == "url_limit"
    result = audit_link_hosts(tuple(f"https://host{i}.example/job" for i in range(21)))
    assert result.terminal_code == "host_limit"
    assert result.host_summaries == ()


def test_audit_does_not_change_classifier_policy_for_greenhouse_host() -> None:
    result = audit_link_hosts(("https://job-boards.greenhouse.io/acme/jobs/eng-1",))

    assert result.validated
    assert result.host_summaries[0].direct_ats_greenhouse_count == 1
