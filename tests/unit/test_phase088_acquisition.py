"""Offline contracts for the F8.8 acquisition boundary."""

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from role_radar.acquisition.activation import ActivationError, parse_xoauth_expiry
from role_radar.acquisition.configuration import (
    DevelopmentAcquisitionFilePolicy,
    load_acquisition_config,
)
from role_radar.acquisition.jobicy_terms_evidence import (
    BUNDLE_FORMAT_VERSION,
    MANIFEST_NAME,
    PAGE_NAMES,
    POLICY_VERSION,
    RSS_URL,
    TERMS_URL,
    EvidenceFilePolicy,
    load_jobicy_terms_evidence,
)
from role_radar.acquisition.readiness import calculate_readiness


def test_development_loader_is_strict_and_path_free(tmp_path: Path) -> None:
    path = tmp_path / "acquisition.toml"
    path.write_text('schema_version = 1\nconfig_version = "test"\n')
    path.chmod(0o600)
    config = load_acquisition_config(path, policy=DevelopmentAcquisitionFilePolicy())
    assert config.config_version == "test"
    with pytest.raises(ValueError):
        load_acquisition_config(
            path.with_name("other.toml"), policy=DevelopmentAcquisitionFilePolicy()
        )


def test_xoauth_expiry_has_five_minute_margin() -> None:
    now = datetime(2026, 8, 9, 12, tzinfo=UTC)
    metadata = json.dumps({"schema_version": 1, "expires_at": "2026-08-09T12:05:00Z"})
    parse_xoauth_expiry(metadata, now=now)
    with pytest.raises(ActivationError) as error:
        parse_xoauth_expiry(
            json.dumps({"schema_version": 1, "expires_at": "2026-08-09T12:04:59Z"}),
            now=now,
        )
    assert error.value.code == "oauth_not_fresh"


def test_jobicy_bundle_is_two_pages_and_terms_sha_is_manifest_hash(tmp_path: Path) -> None:
    root = tmp_path / "jobicy"
    root.mkdir()
    pages = (b"terms", b"fair-use")
    manifest = {
        "bundle_format_version": BUNDLE_FORMAT_VERSION,
        "pages": [
            {
                "retrieved_at": "2026-08-01T00:00:00Z",
                "sha256": hashlib.sha256(pages[0]).hexdigest(),
                "url": TERMS_URL,
            },
            {
                "retrieved_at": "2026-08-01T00:00:00Z",
                "sha256": hashlib.sha256(pages[1]).hexdigest(),
                "url": RSS_URL,
            },
        ],
        "policy_version": POLICY_VERSION,
    }
    encoded = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    bundle = root / digest
    bundle.mkdir()
    (bundle / MANIFEST_NAME).write_bytes(encoded)
    for name, content in zip(PAGE_NAMES, pages, strict=True):
        (bundle / name).write_bytes(content)
    root.chmod(0o550)
    bundle.chmod(0o550)
    for name in (MANIFEST_NAME, *PAGE_NAMES):
        (bundle / name).chmod(0o440)
    evidence = load_jobicy_terms_evidence(
        digest,
        root=root,
        policy=EvidenceFilePolicy(os.getuid(), os.getgid()),
    )
    assert evidence.terms_sha256 == digest
    assert "terms" not in repr(evidence)


def test_readiness_is_sanitized_and_disabled_capabilities_do_not_require_credentials() -> None:
    from role_radar.acquisition.configuration import AcquisitionConfig

    report = calculate_readiness(AcquisitionConfig(config_version="test"))
    assert report.state == "disabled"
    assert all(item.required_credentials == 0 for item in report.capabilities)
    assert "/etc" not in repr(report)


def test_dedicated_account_recommendation_does_not_block_ready_mailbox() -> None:
    from role_radar.acquisition.configuration import AcquisitionConfig
    from role_radar.acquisition.readiness import CapabilityMetadata
    from role_radar.mailbox.configuration import ExternalMailboxConfig

    descriptor = ExternalMailboxConfig(
        connection_alias="role-radar",
        protocol="imap",
        host="imap.gmail.com",
        port=993,
        tls=True,
        validate_certificate=True,
        mailbox="RoleRadar",
        readonly=True,
        auth_mode="app_password",
        username_handle="gmail-username",
        app_password_handle="gmail-app-password",
        app_password_2fa_ack=True,
        app_password_scope_ack=True,
        app_password_revocation_ack=True,
    )
    handles = frozenset(
        {
            "gmail-username",
            "gmail-app-password",
            "mailbox-message-hmac",
            "mailbox-content-hmac",
        }
    )
    report = calculate_readiness(
        AcquisitionConfig(config_version="test", mailboxes={"role-radar": descriptor}),
        metadata={"mailbox:role-radar": CapabilityMetadata(handles)},
    )

    mailbox = next(item for item in report.capabilities if item.capability == "mailbox:role-radar")
    assert mailbox.state == "ready"
    assert "dedicated_account_recommended" in mailbox.codes
    assert "capability_ready" in mailbox.codes


def test_missing_mailbox_credentials_is_blocked_without_readiness_crash() -> None:
    from role_radar.acquisition.configuration import AcquisitionConfig
    from role_radar.mailbox.configuration import ExternalMailboxConfig

    descriptor = ExternalMailboxConfig(
        connection_alias="role-radar",
        protocol="imap",
        host="imap.gmail.com",
        port=993,
        tls=True,
        validate_certificate=True,
        mailbox="RoleRadar",
        readonly=True,
        auth_mode="app_password",
        username_handle="gmail-username",
        app_password_handle="gmail-app-password",
        app_password_2fa_ack=True,
        app_password_scope_ack=True,
        app_password_revocation_ack=True,
    )
    report = calculate_readiness(
        AcquisitionConfig(config_version="test", mailboxes={"role-radar": descriptor})
    )

    mailbox = next(item for item in report.capabilities if item.capability == "mailbox:role-radar")
    assert mailbox.state == "blocked"
    assert "credential_missing" in mailbox.codes
