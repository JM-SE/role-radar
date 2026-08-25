"""Capability-isolated worker composition for acquisition."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from role_radar.acquisition.activation import ActivationError, validate_jobicy_activation
from role_radar.acquisition.configuration import AcquisitionConfig
from role_radar.acquisition.credentials import (
    CredentialError,
    CredentialResolver,
    resolve_mailbox_credentials,
)
from role_radar.acquisition.jobicy_terms_evidence import (
    JobicyEvidenceError,
    load_jobicy_terms_evidence,
)
from role_radar.acquisition.readiness import (
    CapabilityMetadata,
    ReadinessReport,
    calculate_readiness,
)
from role_radar.discovery.providers.brave import BraveSearchProvider
from role_radar.discovery.providers.tavily import TavilySearchProvider
from role_radar.mailbox.contracts import CredentialMaterial, MailboxDescriptor


@dataclass(frozen=True, slots=True)
class AcquisitionCapabilities:
    brave: BraveSearchProvider | None
    tavily: TavilySearchProvider | None
    query_hmac: bytes | None
    jobicy_terms: Any | None
    mailbox_descriptors: dict[str, MailboxDescriptor]
    mailbox_credentials: Callable[[str], CredentialMaterial] | None
    mailbox_hmacs: dict[str, tuple[bytes, bytes]]
    readiness: ReadinessReport


def compose_acquisition_capabilities(
    config: AcquisitionConfig,
    *,
    credential_resolver: CredentialResolver | None = None,
    now: datetime | None = None,
    evidence_loader: Callable[..., Any] = load_jobicy_terms_evidence,
) -> AcquisitionCapabilities:
    """Build enabled capabilities independently and return sanitized readiness."""
    available: dict[str, set[str]] = {}
    resolver = credential_resolver
    brave = tavily = None
    query_hmac: bytes | None = None
    if config.discovery is not None and (
        config.brave_free.enabled or config.tavily_free.enabled or config.brave_paid.enabled
    ):
        try:
            if resolver is None:
                resolver = CredentialResolver()
            query_hmac = resolver.resolve(config.discovery.query_hmac_handle).get_secret_value()
            available["query_hmac"] = {config.discovery.query_hmac_handle}
        except CredentialError:
            pass
    if resolver is None and (
        config.brave_free.enabled or config.tavily_free.enabled or config.mailboxes
    ):
        try:
            resolver = CredentialResolver()
        except CredentialError:
            resolver = None
    if resolver is not None and config.brave_free.enabled and config.brave_free.credential_handle:
        try:
            brave = BraveSearchProvider(resolver.text(config.brave_free.credential_handle))
            available["brave"] = {config.brave_free.credential_handle}
        except CredentialError:
            pass
    if resolver is not None and config.tavily_free.enabled and config.tavily_free.credential_handle:
        try:
            tavily = TavilySearchProvider(resolver.text(config.tavily_free.credential_handle))
            available["tavily"] = {config.tavily_free.credential_handle}
        except CredentialError:
            pass
    terms = None
    terms_meta = CapabilityMetadata()
    if config.jobicy is not None:
        try:
            evidence = evidence_loader(config.jobicy.terms_sha256)
            terms = validate_jobicy_activation(
                evidence,
                terms_sha256=config.jobicy.terms_sha256,
                reviewed_at=config.jobicy.reviewed_at,
                fair_use_ack=config.jobicy.fair_use_ack,
                preserve_destination_ack=config.jobicy.preserve_destination_ack,
                no_redistribution_ack=config.jobicy.no_redistribution_ack,
                now=now or datetime.now(UTC),
            )
        except (JobicyEvidenceError, ActivationError) as exc:
            terms_meta = CapabilityMetadata(terms_code=exc.code)
    descriptors = {alias: value.descriptor() for alias, value in config.mailboxes.items()}
    mailbox_hmacs: dict[str, tuple[bytes, bytes]] = {}
    for alias, descriptor in descriptors.items():
        if resolver is None:
            continue
        try:
            mailbox_hmacs[alias] = (
                resolver.resolve(descriptor.message_hmac_handle).get_secret_value(),
                resolver.resolve(descriptor.content_hmac_handle).get_secret_value(),
            )
            available[f"mailbox:{alias}"] = {
                item
                for item in (
                    descriptor.username_handle,
                    descriptor.oauth2_handle,
                    descriptor.oauth2_expiry_handle,
                    descriptor.app_password_handle,
                    descriptor.message_hmac_handle,
                    descriptor.content_hmac_handle,
                )
                if item is not None
            }
        except CredentialError:
            continue

    def mailbox_credentials(alias: str) -> CredentialMaterial:
        if resolver is None:
            raise CredentialError("credential_directory_unavailable")
        return resolve_mailbox_credentials(descriptors[alias], resolver, now=now)

    metadata = {
        "query_hmac": CapabilityMetadata(frozenset(available.get("query_hmac", set()))),
        "brave": CapabilityMetadata(frozenset(available.get("brave", set()))),
        "tavily": CapabilityMetadata(frozenset(available.get("tavily", set()))),
        "jobicy": terms_meta if terms is None else CapabilityMetadata(),
        **{
            f"mailbox:{alias}": CapabilityMetadata(
                frozenset(available.get(f"mailbox:{alias}", set()))
            )
            for alias in descriptors
        },
    }
    readiness = calculate_readiness(config, metadata=metadata, policy="production", runtime=True)
    return AcquisitionCapabilities(
        brave,
        tavily,
        query_hmac,
        terms,
        descriptors,
        mailbox_credentials if descriptors else None,
        mailbox_hmacs,
        readiness,
    )
