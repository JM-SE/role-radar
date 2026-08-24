"""Independent literal golden vectors for display-v2 canonical bytes and hashes."""

from __future__ import annotations

import hashlib

from role_radar.evaluation.blind_labeling.contracts import PilotItem
from role_radar.evaluation.blind_labeling.display import _rendered_payload, render_pilot_item
from role_radar.evaluation.blind_labeling.display_policy import (
    DISPLAY_CONTRACT_SHA256,
    DISPLAY_HASH_DOMAIN_CONTRACT,
    DISPLAY_HASH_DOMAIN_RENDERED_EVIDENCE,
    DISPLAY_POLICY_CANONICAL_BYTES,
)

EXPECTED_POLICY_CANONICAL_BYTES = (
    b'{"algorithm_revision":"strict-entity-html-terminal-v1","contract_version":"f10.2-display-v2","de'
    b'rived_normalization":"NFC-after-layout-only-v1","entity":{"canonicalization":"sorted-compact-jso'
    b'n-utf8-ensure-ascii-false-v1","decode_passes":2,"key_policy":"semicolon-terminated-only","source'
    b'":"python:html.entities.html5","table_sha256":"47eca34bf835bd382855775e292362f1088a49a10a66ae45a'
    b'0accb26d58dfff6"},"errors":["display_input_invalid","display_input_too_large","display_unicode_i'
    b'nvalid","display_entity_invalid","display_entity_table_mismatch","display_decode_depth_exceeded"'
    b',"display_html_malformed","display_html_depth_exceeded","display_parse_limit_exceeded","display_'
    b'unsafe_control","display_visible_url_forbidden","display_visible_email_forbidden","display_outpu'
    b't_too_large","display_empty"],"external_reference":{"bare_dotted_tokens":"not_url_without_path_q'
    b'uery_fragment","email_error":"display_visible_email_forbidden","email_pattern":"(?<![a-z0-9.!#$%'
    b"&'*+/=?^_`{|}~-])[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:"
    b'[a-z0-9-]{0,61}[a-z0-9])?\\\\.)+[a-z]{2,63}(?![a-z0-9-])","flags":258,"order":["url","email"],"url'
    b'_error":"display_visible_url_forbidden","url_pattern":"(?:https?://|www\\\\.|mailto:)|(?<![a-z0-9_'
    b'@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\\\.)+[a-z]{2,63}(?::[0-9]{1,5})?(?=[/?#])"},"hash_dom'
    b'ains":{"contract":"f10.2:display-contract-v2","rendered_evidence":"f10.2:rendered-evidence-v1"},'
    b'"html":{"block_tags":["article","div","h1","h2","h3","h4","h5","h6","p","section"],"break_tag":"'
    b'br","comments_and_declarations":"discard","layout":"blocks-blank-line-br-line-li-bullet-two-spac'
    b'e-indent-v1","list_containers":["ol","ul"],"list_item":"li","suppressed_tags":["embed","iframe",'
    b'"noscript","object","script","style"],"unknown_tags":"discard_tags_preserve_text","void_tags":["'
    b'area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"]'
    b'},"limits":{"aggregate_visible_evidence_bytes":1048576,"field_input_bytes":1048576,"field_output'
    b'_bytes":1048576,"html_depth":64,"parse_events":100000},"schema":"f10.2-rendered-evidence-v1","so'
    b'urce_validation":{"attributes":"discard-never-emit","empty_optional_location":"none","empty_requ'
    b'ired":"fail","entity_allowed_controls":[],"input":"str-strict-utf8-unicode-scalars-noncharacters'
    b'","raw_allowed_controls":["LF","TAB"],"rejected_controls":"C0-C1-DEL-ESC-CR-NUL-BIDI-U2028-U2029'
    b'","tabs":"visible-two-character-backslash-t"}}'
)
EXPECTED_POLICY_SHA256 = "2c4da70280514b3c2d862486964eacdea7ca4dbc31b257c89c9cef14bf61ec1a"

EXPECTED_RENDERED_EVIDENCE_CANONICAL_BYTES = (
    b'{"company":"Acme Labs","description":"Build safe systems.","display_contract_sha256":"2c4da70'
    b'2'
    b'80'
    b'514b3c2d862486964eacdea7ca4dbc31b257c89c9cef14bf61ec1a","display_contract_version":"f10.2-displa'
    b'y-v2","display_schema":"f10.2-rendered-evidence-v1","location":"Remote","opaque_id":"0123456789a'
    b'bcdef01234567","title":"Senior Role"}'
)
EXPECTED_RENDERED_EVIDENCE_SHA256 = (
    "239ab1066332efbb7d256c094a2897bb684d23a218dffe0759774e80701105a0"
)


def test_policy_golden_uses_independent_literal_bytes_and_sha() -> None:
    assert hashlib.sha256(
        DISPLAY_HASH_DOMAIN_CONTRACT.encode("ascii") + b"\x00" + EXPECTED_POLICY_CANONICAL_BYTES
    ).hexdigest() == EXPECTED_POLICY_SHA256
    assert DISPLAY_POLICY_CANONICAL_BYTES == EXPECTED_POLICY_CANONICAL_BYTES
    assert DISPLAY_CONTRACT_SHA256 == EXPECTED_POLICY_SHA256


def test_rendered_evidence_golden_uses_independent_literal_bytes_and_sha() -> None:
    result = render_pilot_item(
        PilotItem(
            "0123456789abcdef01234567",
            "Senior Role",
            "Acme Labs",
            "Remote",
            "Build safe systems.",
        )
    )
    assert _rendered_payload(
        opaque_id=result.opaque_id,
        title=result.title,
        company=result.company,
        location=result.location,
        description=result.description,
    ) == EXPECTED_RENDERED_EVIDENCE_CANONICAL_BYTES
    assert hashlib.sha256(
        DISPLAY_HASH_DOMAIN_RENDERED_EVIDENCE.encode("ascii")
        + b"\x00"
        + EXPECTED_RENDERED_EVIDENCE_CANONICAL_BYTES
    ).hexdigest() == EXPECTED_RENDERED_EVIDENCE_SHA256
    assert result.rendered_evidence_sha256 == EXPECTED_RENDERED_EVIDENCE_SHA256
