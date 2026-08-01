"""Pruebas de las transformaciones puras de F2."""

from datetime import UTC, datetime

from role_radar.domain.dto import RawJob
from role_radar.normalization.jobs import normalize_raw_job
from role_radar.normalization.text import description_hash, html_to_text
from role_radar.normalization.urls import clean_url


def test_clean_url_removes_tracking_parameters() -> None:
    assert (
        clean_url(" https://example.test/jobs/1?utm_source=x&lang=en#description")
        == "https://example.test/jobs/1?lang=en"
    )


def test_html_to_text_and_description_hash_are_stable() -> None:
    assert html_to_text("<p>Hello&nbsp; world</p><p>API</p>") == "Hello world API"
    assert description_hash(" Hello\nworld ") == description_hash("Hello world")
    assert len(description_hash("content") or "") == 64


def test_normalize_raw_job_maps_all_text_fields() -> None:
    normalized = normalize_raw_job(
        RawJob(
            source="greenhouse",
            external_id="1",
            source_url="https://example.test/jobs/1?utm_campaign=x",
            title=" Backend   Engineer ",
            company=" Acme ",
            location=" Remote  US ",
            description="<p>Build APIs</p>",
            collected_at=datetime.now(UTC),
        )
    )
    assert normalized.title == "Backend Engineer"
    assert normalized.location == "Remote US"
    assert normalized.normalized_location == "remote us"
    assert normalized.description == "Build APIs"
    assert normalized.source_url == "https://example.test/jobs/1"
