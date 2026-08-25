"""Independent literal golden vectors for display-v2 canonical bytes and hashes."""

from __future__ import annotations

import hashlib
import html.entities
import json

from role_radar.evaluation.blind_labeling.contracts import PilotItem
from role_radar.evaluation.blind_labeling.display import _rendered_payload, render_pilot_item
from role_radar.evaluation.blind_labeling.display_policy import (
    DISPLAY_CONTRACT_SHA256,
    DISPLAY_POLICY_CANONICAL_BYTES,
)

EXPECTED_POLICY_CANONICAL_BYTES = (
    b'{"algorithm_revision":"strict-entity-html-terminal-v1","contract_version":"f10.2-display'
    b'-v2","derived_normalization":"NFC-after-layout-only-v1","entity":{"canonicalization":"so'
    b'rted-compact-json-utf8-ensure-ascii-false-v1","decode_passes":2,"key_policy":"semicolon-'
    b'terminated-only","source":"python:html.entities.html5","table_sha256":"47eca34bf835bd382'
    b'855775e292362f1088a49a10a66ae45a0accb26d58dfff6"},"errors":["display_input_invalid","dis'
    b'play_input_too_large","display_unicode_invalid","display_entity_invalid","display_entity'
    b'_table_mismatch","display_decode_depth_exceeded","display_html_malformed","display_html_'
    b'depth_exceeded","display_parse_limit_exceeded","display_unsafe_control","display_visible'
    b'_url_forbidden","display_visible_email_forbidden","display_output_too_large","display_em'
    b'pty"],"external_reference":{"bare_dotted_tokens":"not_url_without_path_query_fragment","'
    b'email_error":"display_visible_email_forbidden","email_pattern":"(?<![a-z0-9.!#$%&\'*+/=?^'
    b"_`{|}~-])[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:"
    b'[a-z0-9-]{0,61}[a-z0-9])?\\\\.)+[a-z]{2,63}(?![a-z0-9-])","flags":258,"order":["url","emai'
    b'l"],"url_error":"display_visible_url_forbidden","url_pattern":"(?:https?://|www\\\\.|mailt'
    b"o:)|(?<![a-z0-9_@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\\\.)+[a-z]{2,63}(?::[0-9]{1,5"
    b'})?(?=[/?#])"},"hash_domains":{"contract":"f10.2:display-contract-v2","rendered_evidence'
    b'":"f10.2:rendered-evidence-v1"},"html":{"block_tags":["article","div","h1","h2","h3","h4'
    b'","h5","h6","p","section"],"break_tag":"br","comments_and_declarations":"discard","layou'
    b't":"blocks-blank-line-br-line-li-bullet-two-space-indent-v1","list_containers":["ol","ul'
    b'"],"list_item":"li","literal_ampersands":"control-sentinel-before-html-parser-v1","suppr'
    b'essed_tags":["embed","iframe","noscript","object","script","style"],"unknown_tags":"disc'
    b'ard_tags_preserve_text","void_tags":["area","base","br","col","hr","img","input","link",'
    b'"meta","param","source","track","wbr"]},"limits":{"accounting":{"aggregate":"title-compa'
    b'ny-description-and-non-none-location-only","aggregate_excludes":["opaque_id","schema-ver'
    b'sion-hashes","json-syntax","composer-labels-counters-separators","none-location"],"encod'
    b'ing":"utf-8","enforcement":"before-serialization-hashing-and-constructor","field_input":"'
    b'each-non-none-source-field-before-decoding","field_output":"each-non-none-final-field-a'
    b'fter-nfc-and-tab-rendering","working_output":"after-each-completed-entity-pass"},"aggreg'
    b'ate_visible_evidence_bytes":1048576,"field_input_bytes":1048576,"field_output_bytes":104'
    b'8576,"html_depth":64,"parse_events":100000},"schema":"f10.2-rendered-evidence-v1","sourc'
    b'e_validation":{"attributes":"discard-never-emit","empty_optional_location":"none","empty'
    b'_required":"fail","entity_allowed_controls":[],"input":"str-strict-utf8-unicode-scalars-'
    b'noncharacters","raw_allowed_controls":["LF","TAB"],"rejected_controls":"C0-C1-DEL-ESC-CR'
    b'-NUL-BIDI-U2028-U2029","tabs":"visible-two-character-backslash-t"}}'
)
EXPECTED_POLICY_SHA256 = "88db2bccb53128bfb6850dcd7d340464208f97ddf90202a6407c7882d3d47a5d"
EXPECTED_ENTITY_TABLE_SHA256 = "47eca34bf835bd382855775e292362f1088a49a10a66ae45a0accb26d58dfff6"

EXPECTED_RENDERED_EVIDENCE_CANONICAL_BYTES = (
    b'{"company":"Acme Labs","description":"Build safe systems.","display_contract_sha256":"88'
    b'db2bccb53128bfb6850dcd7d340464208f97ddf90202a6407c7882d3d47a5d","display_contract_versio'
    b'n":"f10.2-display-v2","display_schema":"f10.2-rendered-evidence-v1","location":"Remote",'
    b'"opaque_id":"0123456789abcdef01234567","title":"Senior Role"}'
)
EXPECTED_RENDERED_EVIDENCE_SHA256 = (
    "1f8cb3d8e2ad8a0be9ab8bf333a023d571a531ea56e93b6bebba0ae11f6ba63b"
)


def test_policy_golden_uses_independent_literal_bytes_and_sha() -> None:
    assert (
        hashlib.sha256(
            b"f10.2:display-contract-v2\x00" + EXPECTED_POLICY_CANONICAL_BYTES
        ).hexdigest()
        == EXPECTED_POLICY_SHA256
    )
    assert DISPLAY_POLICY_CANONICAL_BYTES == EXPECTED_POLICY_CANONICAL_BYTES
    assert DISPLAY_CONTRACT_SHA256 == EXPECTED_POLICY_SHA256


def test_selected_html5_entity_table_digest_is_independently_pinned() -> None:
    selected = {
        key: html.entities.html5[key] for key in sorted(html.entities.html5) if key.endswith(";")
    }
    canonical = json.dumps(
        selected,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == EXPECTED_ENTITY_TABLE_SHA256


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
    assert (
        _rendered_payload(
            opaque_id="0123456789abcdef01234567",
            title="Senior Role",
            company="Acme Labs",
            location="Remote",
            description="Build safe systems.",
        )
        == EXPECTED_RENDERED_EVIDENCE_CANONICAL_BYTES
    )
    assert (
        result.display_schema,
        result.display_contract_version,
        result.display_contract_sha256,
    ) == ("f10.2-rendered-evidence-v1", "f10.2-display-v2", EXPECTED_POLICY_SHA256)
    assert (
        hashlib.sha256(
            b"f10.2:rendered-evidence-v1\x00" + EXPECTED_RENDERED_EVIDENCE_CANONICAL_BYTES
        ).hexdigest()
        == EXPECTED_RENDERED_EVIDENCE_SHA256
    )
    assert result.rendered_evidence_sha256 == EXPECTED_RENDERED_EVIDENCE_SHA256
