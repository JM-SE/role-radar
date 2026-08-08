"""UTF-8, URL, item and canonical batch bounds."""

from datetime import UTC, datetime

import pytest

from role_radar.collectors.raw_job_bounds import (
    CanonicalBatch,
    RawJobBoundsError,
    validate_raw_job,
    validate_url,
)
from role_radar.domain.dto import RawJob


def _job(description: str = "ok") -> RawJob:
    return RawJob(
        source="greenhouse",
        external_id="1",
        title="Engineer",
        company="Acme",
        description=description,
        source_url="https://boards.greenhouse.io/acme/jobs/1",
        structured_data={"id": "1"},
        collected_at=datetime.now(UTC),
    )


def test_description_and_structured_caps_are_exact_and_never_truncated() -> None:
    exact = "é" * (256 * 1024 // 2)
    validate_raw_job(_job(exact))
    with pytest.raises(RawJobBoundsError) as error:
        validate_raw_job(_job(exact + "é"))
    assert error.value.kind == "oversized"


def test_urls_reject_userinfo_controls_and_invalid_scheme() -> None:
    for value in ("https://user:pass@example.test/x", "javascript:alert(1)", "https://x/\n"):
        with pytest.raises(RawJobBoundsError):
            validate_url(value)


def test_batch_cap_is_exact() -> None:
    batch = CanonicalBatch(limit_bytes=5)
    assert batch.add(b"a") == 3
    assert batch.add(b"a") == 5
    with pytest.raises(RawJobBoundsError) as error:
        batch.add(b"a")
    assert error.value.kind == "batch"
