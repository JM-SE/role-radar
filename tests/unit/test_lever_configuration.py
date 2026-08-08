import pytest
from pydantic import ValidationError

from role_radar.sources.configuration import LeverRegion, LeverSourceConfigV1
from role_radar.sources.contracts import PublicLeverSourceConfiguration
from role_radar.sources.identity import canonical_source_key
from role_radar.sources.public import project_public_configuration


def test_lever_config_normalizes_public_identity_only() -> None:
    config = LeverSourceConfigV1(site="  Acme_Site ", region=LeverRegion.EU, company=" Acme ")
    assert config.region is LeverRegion.EU
    assert config.model_dump(mode="json") == {
        "site": "acme_site",
        "region": "eu",
        "company": "Acme",
    }
    assert canonical_source_key("lever", config.model_dump()) == "lever:eu:acme_site"
    assert canonical_source_key(
        "lever", {"site": "acme_site", "region": "eu", "company": "Other"}
    ) == "lever:eu:acme_site"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a/b",
        "a\\b",
        "a.b",
        "a%b",
        "a@b",
        "a:b",
        "a b",
        "é",
        "a" * 129,
    ],
)
def test_lever_site_is_strict_and_path_safe(value: str) -> None:
    with pytest.raises(ValidationError):
        LeverSourceConfigV1(site=value, region=LeverRegion.GLOBAL)


@pytest.mark.parametrize(
    "configuration",
    [
        {"site": "acme", "region": "global", "url": "https://canary"},
        {"site": "acme", "region": "global", "nested": {"token": "canary"}},
        {"site": "acme", "region": "global", "board_token": "canary"},
        {"site": "acme", "region": "global", "unknown": "canary"},
        {"site": "acme", "region": "global", "company": "   "},
    ],
)
def test_lever_rejects_network_credentials_and_unknown_fields(
    configuration: dict[str, object],
) -> None:
    with pytest.raises((ValidationError, ValueError)):
        LeverSourceConfigV1.model_validate(configuration)


def test_lever_public_projection_is_allowlisted() -> None:
    with pytest.raises((ValidationError, ValueError)):
        project_public_configuration(
            "lever",
            1,
            {"site": "acme", "region": "global", "company": "Acme", "token": "canary"},
        )
    valid = project_public_configuration("lever", 1, {"site": "acme", "region": "global"})
    assert isinstance(valid, PublicLeverSourceConfiguration)
    assert valid.as_dict() == {"site": "acme", "region": "global"}
