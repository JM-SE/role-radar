from dataclasses import replace

from sqlalchemy.orm import Session

from role_radar.mailbox.contracts import BoundedMailboxMessage, MailboxStateSnapshot, MailboxTask
from role_radar.mailbox.parser_registry import default_registry
from role_radar.services.pipeline_mailbox import PipelineMailboxService


def _message(*, domain: str = "linkedin.com", auth: bool = True) -> BoundedMailboxMessage:
    return BoundedMailboxMessage(
        sender_domain=domain,
        list_id=None,
        auth_evidence="pass" if auth else "ambiguous",
        subject="Job Alert",
        text="LinkedIn job alert",
        html="",
        authserv_id="mx.google.com" if auth else "evil.invalid",
        dmarc_result="pass" if auth else None,
        header_from_domain=domain if auth else None,
    )


def test_auto_v1_requires_google_auth_and_never_falls_back_to_generic() -> None:
    parsed = default_registry().parse("auto", _message())
    assert parsed.parser_name == "linkedin"
    assert parsed.template_code.startswith("auto-v1:")

    unknown = default_registry().parse("auto", _message(auth=False))
    assert unknown.parser_name == "unknown"
    assert unknown.terminal_code == "review"

    generic = default_registry().parse("generic", _message())
    assert generic.parser_name == "generic"
    assert generic.terminal_code is None


def test_auto_v1_rejects_non_google_authserv_and_hmacs_are_alias_scoped() -> None:
    non_google = _message()
    non_google = replace(non_google, authserv_id="mx")
    parsed = default_registry().parse("auto", non_google)
    assert parsed.parser_name == "unknown"

    def session_factory() -> Session:
        raise AssertionError("session factory must not be called")

    service = PipelineMailboxService(
        session_factory,
        mailbox_hmac_keys={
            "one": (b"one-url", b"one-content"),
            "two": (b"two-url", b"two-content"),
        },
    )
    task = MailboxTask(
        "source-two",
        "email:two",
        "two",
        "auto",
        "mailbox:run:source-two",
        MailboxStateSnapshot("source-two", None, 0, 1),
        True,
        None,
        1,
    )
    assert service._keys_for(task) == (b"two-url", b"two-content")
