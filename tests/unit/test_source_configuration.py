import pytest
from pydantic import ValidationError

from role_radar.sources.configuration import GreenhouseSourceConfig
from role_radar.sources.contracts import PublicSourceConfiguration
from role_radar.sources.identity import canonical_source_key
from role_radar.sources.public import project_public_configuration


def test_greenhouse_config_is_strict_and_canonical() -> None:
    config = GreenhouseSourceConfig(board_token="  Acme_Board ", company=" Acme ")
    assert config.board_token == "acme_board"
    assert config.company == "Acme"
    assert canonical_source_key("greenhouse", config.model_dump()) == "greenhouse:acme_board"


@pytest.mark.parametrize(
    "configuration",
    [
        {"board_token": "acme", "url": "https://example.test"},
        {"board_token": "acme", "nested": {"api_key": "canary"}},
        {"board_token": "éxample"},
        {"board_token": "acme", "company": "   "},
    ],
)
def test_forbidden_and_invalid_configuration_is_rejected(configuration: dict[str, object]) -> None:
    with pytest.raises((ValidationError, ValueError)):
        GreenhouseSourceConfig.model_validate(configuration)


def test_public_projection_is_allowlisted() -> None:
    projection = project_public_configuration(
        "greenhouse", 1, {"board_token": "acme", "company": "Acme"}
    )
    assert isinstance(projection, PublicSourceConfiguration)
    assert projection.as_dict() == {"board_token": "acme", "company": "Acme"}
    assert project_public_configuration("manual", 0, {"secret": "canary"}) == {}
