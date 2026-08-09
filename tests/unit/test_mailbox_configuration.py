"""Strict external descriptor and EMAIL source identity tests."""

import pytest

from role_radar.mailbox.configuration import EmailSourceConfigV1, ExternalMailboxConfig


def test_email_source_config_has_only_non_secret_identity() -> None:
    config = EmailSourceConfigV1(connection_alias=" Role-Radar ", parser_profile="LinkedIn")
    assert config.model_dump() == {"connection_alias": "role-radar", "parser_profile": "linkedin"}


def test_gmail_descriptor_mismatch_fails_closed() -> None:
    with pytest.raises(ValueError):
        ExternalMailboxConfig(
            connection_alias="role-radar",
            protocol="imap",
            host="imap.gmail.com",
            port=993,
            tls=True,
            validate_certificate=True,
            mailbox="INBOX",
            readonly=True,
            auth_mode="xoauth2",
            username_handle="username",
            oauth2_handle="oauth",
        )
