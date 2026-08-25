"""Gate A policy grammar, identity, and secure-loader checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from role_radar.acquisition.discovery_policy import (
    DiscoveryPolicyFileError,
    load_discovery_policy,
)
from role_radar.acquisition.discovery_policy import (
    test_discovery_policy_file_policy as _test_discovery_policy_file_policy,
)
from role_radar.discovery.policy import (
    DiscoveryPhraseGrammarV1,
    DiscoveryPolicyError,
    DiscoveryPolicyV1,
    canonical_policy_bytes,
    policy_sha256,
)

PROFILE_ID = "00000000-0000-0000-0000-000000000001"
PROFILE_SHA = "a" * 64
GOLDEN_POLICY_SHA256 = "9b323f25e8d20695d01b3789fd480894c04a3eb8072603b56e5beeac1e093fcb"
GOLDEN_POLICY_CANONICAL_BYTES = (
    b'{"groups":{"primary":["Backend Engineer"]},"phrase_grammar":{"allowed_ascii_space":" ",'
    b'"allowed_punctuation":["#","&","\'","+","-",".","/"],"allowed_unicode_categories":["Lu","L'
    b'l","Lt","Lm","Lo","Mn","Mc","Me","Nd","Nl","No"],"ascii_email_marker_pattern":"(?i)(?<!['
    b'A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\\\\.[A-Z]{2,63}(?![A-Z0-9.-])","base64_'
    b'candidate_pattern":"(?:[A-Za-z0-9+/]{40,126}={0,2}|[A-Za-z0-9_-]{43,128})","forbidden_qu'
    b'ery_characters":["!","\\"","$","(",")",":",";","<","=",">","?","@","[","\\\\","]","^","_","'
    b'`","{","|","}","~","*"],"forbidden_query_tokens":["after","allintitle","allinurl","and",'
    b'"before","cache","ext","filetype","intext","intitle","inurl","link","near","not","or","r'
    b'elated","site","source"],"forbidden_secret_token_sequences":[["access","key"],["api","ke'
    b'y"],["client","secret"],["private","key"],["secret","key"]],"forbidden_secret_tokens":["'
    b'apikey","authorization","bearer","credential","credentials","password","passwd","private'
    b'key","secret","secretkey","token"],"forbidden_url_markers":["://","www.","mailto:"],"for'
    b'bidden_url_tokens":["http","https","ftp"],"grammar_version":"discovery-phrase-grammar-v1'
    b'","lexical_token_source":"unicode-category-run-v1","long_hex_candidate_pattern":"[0-9a-f'
    b'A-F]{32,128}","maximum_chars":128,"minimum_chars":1,"normalization":"NFKC"},"policy_vers'
    b'ion":"gate-a-v1","profile_binding":{"canonical_profile_sha256":"aaaaaaaaaaaaaaaaaaaaaaaa'
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id":"00000000-0000-0000-0000-00000000'
    b'0001","row_version":1,"schema_version":1},"schema_version":1,"target_roles":{"backend":{'
    b'"coverage_groups":[],"primary_groups":["primary"]}},"target_titles":{}}'
)


def policy_payload(*, phrases: tuple[str, ...] = ("Backend Engineer",)) -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_version": "gate-a-v1",
        "profile_binding": {
            "profile_id": PROFILE_ID,
            "row_version": 1,
            "schema_version": 1,
            "canonical_profile_sha256": PROFILE_SHA,
        },
        "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
        "groups": {"primary": phrases},
        "target_roles": {"backend": {"primary_groups": ["primary"]}},
        "target_titles": {},
    }


def test_policy_is_strict_and_canonical_hash_is_format_independent() -> None:
    policy = DiscoveryPolicyV1.model_validate(policy_payload())
    reordered = DiscoveryPolicyV1.model_validate(
        {
            **policy_payload(),
            "groups": {"primary": ["Backend Engineer"]},
        }
    )

    assert canonical_policy_bytes(policy) == canonical_policy_bytes(reordered)
    assert policy_sha256(policy) == hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()
    assert canonical_policy_bytes(policy) == GOLDEN_POLICY_CANONICAL_BYTES
    assert hashlib.sha256(GOLDEN_POLICY_CANONICAL_BYTES).hexdigest() == GOLDEN_POLICY_SHA256
    with pytest.raises(ValueError):
        DiscoveryPolicyV1.model_validate({**policy_payload(), "unexpected": True})


@pytest.mark.parametrize("phrase", ["C++", "C#", ".NET", "Node.js", "Data/ML", "R&D"])
def test_admitted_punctuation_is_not_treated_as_query_syntax(phrase: str) -> None:
    policy = DiscoveryPolicyV1.model_validate(policy_payload(phrases=(phrase,)))
    assert policy.groups["primary"] == (phrase,)


@pytest.mark.parametrize(
    "phrase",
    ["site:example.com", "https://example.com", "api key", "password", "a@b.example"],
)
def test_forbidden_phrase_content_fails_closed(phrase: str) -> None:
    with pytest.raises(ValueError):
        DiscoveryPolicyV1.model_validate(policy_payload(phrases=(phrase,)))


def test_secure_loader_uses_bounded_private_test_file(tmp_path: Path) -> None:
    path = tmp_path / "discovery-policy.toml"
    grammar = DiscoveryPhraseGrammarV1().model_dump(mode="json")
    grammar_toml = "\n".join(
        f"{key} = {json.dumps(value, ensure_ascii=False)}" for key, value in grammar.items()
    )
    path.write_text(
        f'''schema_version = 1
policy_version = "gate-a-v1"

[profile_binding]
profile_id = "{PROFILE_ID}"
row_version = 1
schema_version = 1
canonical_profile_sha256 = "{PROFILE_SHA}"

[phrase_grammar]
{grammar_toml}

[groups]
primary = ["Backend Engineer"]

[target_roles.backend]
primary_groups = ["primary"]

[target_titles]
''',
        encoding="utf-8",
    )
    path.chmod(0o600)

    loaded = load_discovery_policy(path, file_policy=_test_discovery_policy_file_policy())

    assert loaded.source_path == path
    assert loaded.policy_sha256 == policy_sha256(loaded.policy)
    assert loaded.raw_bytes == path.read_bytes()


def test_secure_loader_rejects_wrong_mode(tmp_path: Path) -> None:
    path = tmp_path / "discovery-policy.toml"
    path.write_text("schema_version = 1\n", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(DiscoveryPolicyFileError) as error:
        load_discovery_policy(path, file_policy=_test_discovery_policy_file_policy())
    assert error.value.code == "discovery_policy_mode_invalid"


def test_policy_error_does_not_include_phrase_or_path() -> None:
    secret_phrase = "backend-private-phrase"
    with pytest.raises((DiscoveryPolicyError, ValueError)) as error:
        DiscoveryPolicyV1.model_validate(policy_payload(phrases=(secret_phrase, "site:x")))
    assert secret_phrase not in str(error.value)
