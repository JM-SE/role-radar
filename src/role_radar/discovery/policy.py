"""Pure discovery limits and the strict profile-bound v2 policy.

The small :class:`DiscoveryPolicy` dataclass at the top of this module is the
original v1 policy.  It is intentionally left as-is: the pipeline and the
historical discovery consumers still use that API.  The v2 policy types below
are separately named and do not participate in v1 authorization or planning.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from role_radar.domain.profile import normalize_text
from role_radar.matching.policy import canonical_role

DISCOVERY_POLICY_VERSION = "discovery-policy-v1"
MAX_NEW_SOURCES_PER_RUN = 8
MAX_ACTIVE_DISCOVERY_SOURCES = 50
MAX_TRANSIENT_RESULTS_PER_QUERY = 100


@dataclass(frozen=True, slots=True)
class DiscoveryPolicy:
    version: str = DISCOVERY_POLICY_VERSION
    max_new_sources_per_run: int = MAX_NEW_SOURCES_PER_RUN
    max_active_sources: int = MAX_ACTIVE_DISCOVERY_SOURCES
    max_results_per_query: int = MAX_TRANSIENT_RESULTS_PER_QUERY

    def allows_new_source(self, created: int) -> bool:
        return created < self.max_new_sources_per_run


# F10.1D v2 policy grammar.  These are code-owned constants.  A policy file
# repeats them in its DTO so the complete grammar is part of the policy hash;
# the policy validator below rejects any attempted weakening.
DISCOVERY_POLICY_SCHEMA_VERSION = 1
DISCOVERY_PHRASE_GRAMMAR_VERSION = "discovery-phrase-grammar-v1"
DISCOVERY_PHRASE_NORMALIZATION: Literal["NFKC"] = "NFKC"
MIN_APPROVED_PHRASE_CHARS = 1
MAX_APPROVED_PHRASE_CHARS = 128
ALLOWED_UNICODE_CATEGORIES = (
    "Lu",
    "Ll",
    "Lt",
    "Lm",
    "Lo",
    "Mn",
    "Mc",
    "Me",
    "Nd",
    "Nl",
    "No",
)
ALLOWED_ASCII_SPACE = " "
ALLOWED_PUNCTUATION = ("#", "&", "'", "+", "-", ".", "/")
FORBIDDEN_QUERY_CHARACTERS = (
    "!",
    '"',
    "$",
    "(",
    ")",
    ":",
    ";",
    "<",
    "=",
    ">",
    "?",
    "@",
    "[",
    "\\",
    "]",
    "^",
    "_",
    "`",
    "{",
    "|",
    "}",
    "~",
    "*",
)
LEXICAL_TOKEN_SOURCE = "unicode-category-run-v1"
FORBIDDEN_QUERY_TOKENS = (
    "after",
    "allintitle",
    "allinurl",
    "and",
    "before",
    "cache",
    "ext",
    "filetype",
    "intext",
    "intitle",
    "inurl",
    "link",
    "near",
    "not",
    "or",
    "related",
    "site",
    "source",
)
FORBIDDEN_URL_MARKERS = ("://", "www.", "mailto:")
FORBIDDEN_URL_TOKENS = ("http", "https", "ftp")
ASCII_EMAIL_MARKER_PATTERN = (
    r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}"
    r"(?![A-Z0-9.-])"
)
FORBIDDEN_SECRET_TOKENS = (
    "apikey",
    "authorization",
    "bearer",
    "credential",
    "credentials",
    "password",
    "passwd",
    "privatekey",
    "secret",
    "secretkey",
    "token",
)
FORBIDDEN_SECRET_TOKEN_SEQUENCES = (
    ("access", "key"),
    ("api", "key"),
    ("client", "secret"),
    ("private", "key"),
    ("secret", "key"),
)
LONG_HEX_CANDIDATE_PATTERN = r"[0-9a-fA-F]{32,128}"
BASE64_CANDIDATE_PATTERN = r"(?:[A-Za-z0-9+/]{40,126}={0,2}|[A-Za-z0-9_-]{43,128})"

_POLICY_VERSION = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_MARKER = re.compile(ASCII_EMAIL_MARKER_PATTERN)
_LONG_HEX = re.compile(LONG_HEX_CANDIDATE_PATTERN)
_BASE64 = re.compile(BASE64_CANDIDATE_PATTERN)
_ASCII_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=_-]+")


class DiscoveryPolicyError(ValueError):
    """Sanitized, stable error raised by pure v2 policy operations."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _StrictV2Model(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )


def _string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field}_invalid")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field}_invalid")
    return tuple(cast(tuple[str, ...], value))


def _mapping(value: object, *, field: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field}_invalid")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{field}_invalid")
    return dict(value)


class ProfileBindingV1(_StrictV2Model):
    """The exact immutable profile row identity selected by v2."""

    profile_id: str
    row_version: StrictInt = Field(gt=0)
    schema_version: Literal[1]
    canonical_profile_sha256: str

    @field_validator("profile_id")
    @classmethod
    def canonical_uuid(cls, value: str) -> str:
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("profile_binding_invalid") from exc
        if str(parsed) != value or value != value.casefold():
            raise ValueError("profile_binding_invalid")
        return value

    @field_validator("canonical_profile_sha256")
    @classmethod
    def canonical_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("profile_binding_invalid")
        return value

    @property
    def profile_version(self) -> int:
        """Compatibility spelling for authorization/report adapters."""

        return self.row_version

    @property
    def profile_schema_version(self) -> int:
        """Compatibility spelling for authorization/report adapters."""

        return self.schema_version

    @property
    def profile_sha256(self) -> str:
        """Compatibility spelling for authorization/report adapters."""

        return self.canonical_profile_sha256

    def as_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "row_version": self.row_version,
            "schema_version": self.schema_version,
            "canonical_profile_sha256": self.canonical_profile_sha256,
        }


class DiscoveryPhraseGrammarV1(_StrictV2Model):
    """The complete, non-weakenable v1 phrase grammar source."""

    grammar_version: str = DISCOVERY_PHRASE_GRAMMAR_VERSION
    normalization: str = DISCOVERY_PHRASE_NORMALIZATION
    minimum_chars: StrictInt = MIN_APPROVED_PHRASE_CHARS
    maximum_chars: StrictInt = MAX_APPROVED_PHRASE_CHARS
    allowed_unicode_categories: tuple[str, ...] = ALLOWED_UNICODE_CATEGORIES
    allowed_ascii_space: str = ALLOWED_ASCII_SPACE
    allowed_punctuation: tuple[str, ...] = ALLOWED_PUNCTUATION
    forbidden_query_characters: tuple[str, ...] = FORBIDDEN_QUERY_CHARACTERS
    lexical_token_source: str = LEXICAL_TOKEN_SOURCE
    forbidden_query_tokens: tuple[str, ...] = FORBIDDEN_QUERY_TOKENS
    forbidden_url_markers: tuple[str, ...] = FORBIDDEN_URL_MARKERS
    forbidden_url_tokens: tuple[str, ...] = FORBIDDEN_URL_TOKENS
    ascii_email_marker_pattern: str = ASCII_EMAIL_MARKER_PATTERN
    forbidden_secret_tokens: tuple[str, ...] = FORBIDDEN_SECRET_TOKENS
    forbidden_secret_token_sequences: tuple[tuple[str, str], ...] = FORBIDDEN_SECRET_TOKEN_SEQUENCES
    long_hex_candidate_pattern: str = LONG_HEX_CANDIDATE_PATTERN
    base64_candidate_pattern: str = BASE64_CANDIDATE_PATTERN

    @field_validator(
        "allowed_unicode_categories",
        "allowed_punctuation",
        "forbidden_query_characters",
        "forbidden_query_tokens",
        "forbidden_url_markers",
        "forbidden_url_tokens",
        "forbidden_secret_tokens",
        mode="before",
    )
    @classmethod
    def tuple_fields(cls, value: object, info: Any) -> tuple[str, ...]:
        return _string_tuple(value, field=info.field_name)

    @field_validator("forbidden_secret_token_sequences", mode="before")
    @classmethod
    def sequence_fields(cls, value: object) -> tuple[tuple[str, str], ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("forbidden_secret_token_sequences_invalid")
        result: list[tuple[str, str]] = []
        for item in value:
            if (
                not isinstance(item, (list, tuple))
                or len(item) != 2
                or any(not isinstance(part, str) for part in item)
            ):
                raise ValueError("forbidden_secret_token_sequences_invalid")
            result.append((item[0], item[1]))
        return tuple(result)

    @model_validator(mode="after")
    def is_fixed_contract(self) -> DiscoveryPhraseGrammarV1:
        expected = _fixed_grammar_payload()
        actual = _jsonable(self.model_dump(mode="python"))
        if actual != expected:
            raise ValueError("phrase_grammar_invalid")
        return self


class DiscoveryTermBindingV1(_StrictV2Model):
    """Ordered policy groups used by one canonical role/title key."""

    primary_groups: tuple[str, ...]
    coverage_groups: tuple[str, ...] = ()

    @field_validator("primary_groups", "coverage_groups", mode="before")
    @classmethod
    def group_tuple(cls, value: object, info: Any) -> tuple[str, ...]:
        result = _string_tuple(value, field=info.field_name)
        if info.field_name == "primary_groups" and not result:
            raise ValueError("term_binding_invalid")
        if len(set(result)) != len(result):
            raise ValueError("term_binding_invalid")
        return result

    @model_validator(mode="after")
    def no_duplicate_references(self) -> DiscoveryTermBindingV1:
        combined = self.primary_groups + self.coverage_groups
        if len(set(combined)) != len(combined):
            raise ValueError("term_binding_invalid")
        return self


def _validate_phrase(value: str, grammar: DiscoveryPhraseGrammarV1) -> str:
    """Validate one policy phrase in the contract's specified order."""

    if not isinstance(value, str):
        raise ValueError("phrase_invalid")
    if not MIN_APPROVED_PHRASE_CHARS <= len(value) <= MAX_APPROVED_PHRASE_CHARS:
        raise ValueError("phrase_invalid")
    if value != unicodedata.normalize(DISCOVERY_PHRASE_NORMALIZATION, value):
        raise ValueError("phrase_invalid")
    if value != value.strip() or "  " in value:
        raise ValueError("phrase_invalid")
    folded = value.casefold()
    if any(marker in folded for marker in FORBIDDEN_URL_MARKERS):
        raise ValueError("phrase_invalid")
    if _EMAIL_MARKER.search(value) is not None:
        raise ValueError("phrase_invalid")
    if any(_LONG_HEX.fullmatch(match.group(0)) for match in _ASCII_ALNUM_RUN.finditer(value)):
        raise ValueError("phrase_invalid")
    if any(_BASE64.fullmatch(match.group(0)) for match in _BASE64_RUN.finditer(value)):
        raise ValueError("phrase_invalid")

    for char in value:
        if char == ALLOWED_ASCII_SPACE:
            continue
        category = unicodedata.category(char)
        if category in ALLOWED_UNICODE_CATEGORIES or char in ALLOWED_PUNCTUATION:
            continue
        raise ValueError("phrase_invalid")

    if any(char in value for char in FORBIDDEN_QUERY_CHARACTERS):
        raise ValueError("phrase_invalid")

    lexical_tokens: list[str] = []
    run: list[str] = []
    for char in value:
        if unicodedata.category(char) in ALLOWED_UNICODE_CATEGORIES:
            run.append(char)
        elif run:
            lexical_tokens.append("".join(run).casefold())
            run = []
    if run:
        lexical_tokens.append("".join(run).casefold())
    if any(
        token in FORBIDDEN_QUERY_TOKENS or token in FORBIDDEN_URL_TOKENS for token in lexical_tokens
    ):
        raise ValueError("phrase_invalid")
    if any(token in FORBIDDEN_SECRET_TOKENS for token in lexical_tokens):
        raise ValueError("phrase_invalid")
    if any(
        tuple(lexical_tokens[index : index + len(sequence)]) == sequence
        for sequence in FORBIDDEN_SECRET_TOKEN_SEQUENCES
        for index in range(len(lexical_tokens) - len(sequence) + 1)
    ):
        raise ValueError("phrase_invalid")
    return value


class DiscoveryPolicyV1(_StrictV2Model):
    """Strict immutable, non-secret profile-driven discovery policy."""

    schema_version: Literal[1]
    policy_version: str
    profile_binding: ProfileBindingV1
    phrase_grammar: DiscoveryPhraseGrammarV1
    groups: Mapping[str, tuple[str, ...]]
    target_roles: Mapping[str, DiscoveryTermBindingV1]
    target_titles: Mapping[str, DiscoveryTermBindingV1]

    @field_validator("policy_version")
    @classmethod
    def valid_policy_version(cls, value: str) -> str:
        if _POLICY_VERSION.fullmatch(value) is None:
            raise ValueError("policy_invalid")
        return value

    @field_validator("groups", "target_roles", "target_titles", mode="before")
    @classmethod
    def mapping_fields(cls, value: object, info: Any) -> dict[str, object]:
        return _mapping(value, field=info.field_name)

    @field_validator("groups", mode="before")
    @classmethod
    def group_values(cls, value: object) -> dict[str, tuple[str, ...]]:
        raw = _mapping(value, field="groups")
        groups: dict[str, tuple[str, ...]] = {}
        for group_id, phrases in raw.items():
            if _IDENTIFIER.fullmatch(group_id) is None:
                raise ValueError("policy_invalid")
            group = _string_tuple(phrases, field="group")
            if not group:
                raise ValueError("policy_invalid")
            groups[group_id] = group
        return groups

    @field_validator("target_roles", mode="before")
    @classmethod
    def role_keys(cls, value: object) -> dict[str, object]:
        raw = _mapping(value, field="target_roles")
        if any(canonical_role(key) != key for key in raw):
            raise ValueError("policy_invalid")
        return raw

    @field_validator("target_titles", mode="before")
    @classmethod
    def title_keys(cls, value: object) -> dict[str, object]:
        raw = _mapping(value, field="target_titles")
        try:
            valid = all(normalize_text(key) == key for key in raw)
        except ValueError as exc:
            raise ValueError("policy_invalid") from exc
        if not valid:
            raise ValueError("policy_invalid")
        return raw

    @model_validator(mode="after")
    def validate_references_and_phrases(self) -> DiscoveryPolicyV1:
        if self.phrase_grammar != DiscoveryPhraseGrammarV1():
            raise ValueError("policy_invalid")
        for phrases in self.groups.values():
            for phrase in phrases:
                _validate_phrase(phrase, self.phrase_grammar)

        referenced: list[str] = []
        for binding in (*self.target_roles.values(), *self.target_titles.values()):
            combined = binding.primary_groups + binding.coverage_groups
            if len(set(combined)) != len(combined) or any(
                group_id not in self.groups for group_id in combined
            ):
                raise ValueError("policy_invalid")
            referenced.extend(combined)
        if set(referenced) != set(self.groups):
            raise ValueError("policy_invalid")

        # Pydantic's frozen flag protects assignment to the model, while these
        # proxies protect the nested mappings from mutation as well.
        object.__setattr__(self, "groups", MappingProxyType(dict(self.groups)))
        object.__setattr__(self, "target_roles", MappingProxyType(dict(self.target_roles)))
        object.__setattr__(self, "target_titles", MappingProxyType(dict(self.target_titles)))
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_policy_bytes(self)

    @property
    def sha256(self) -> str:
        return policy_sha256(self)


def _fixed_grammar_payload() -> dict[str, object]:
    return {
        "grammar_version": DISCOVERY_PHRASE_GRAMMAR_VERSION,
        "normalization": DISCOVERY_PHRASE_NORMALIZATION,
        "minimum_chars": MIN_APPROVED_PHRASE_CHARS,
        "maximum_chars": MAX_APPROVED_PHRASE_CHARS,
        "allowed_unicode_categories": list(ALLOWED_UNICODE_CATEGORIES),
        "allowed_ascii_space": ALLOWED_ASCII_SPACE,
        "allowed_punctuation": list(ALLOWED_PUNCTUATION),
        "forbidden_query_characters": list(FORBIDDEN_QUERY_CHARACTERS),
        "lexical_token_source": LEXICAL_TOKEN_SOURCE,
        "forbidden_query_tokens": list(FORBIDDEN_QUERY_TOKENS),
        "forbidden_url_markers": list(FORBIDDEN_URL_MARKERS),
        "forbidden_url_tokens": list(FORBIDDEN_URL_TOKENS),
        "ascii_email_marker_pattern": ASCII_EMAIL_MARKER_PATTERN,
        "forbidden_secret_tokens": list(FORBIDDEN_SECRET_TOKENS),
        "forbidden_secret_token_sequences": [
            list(item) for item in FORBIDDEN_SECRET_TOKEN_SEQUENCES
        ],
        "long_hex_candidate_pattern": LONG_HEX_CANDIDATE_PATTERN,
        "base64_candidate_pattern": BASE64_CANDIDATE_PATTERN,
    }


def _jsonable(value: object) -> Any:
    if isinstance(value, BaseModel):
        return _jsonable(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def canonical_policy_payload(policy: DiscoveryPolicyV1) -> dict[str, object]:
    """Return the complete JSON-compatible policy hash payload."""

    if not isinstance(policy, DiscoveryPolicyV1):
        raise TypeError("canonical_policy_payload requires DiscoveryPolicyV1")
    # Build this explicitly rather than serializing the nested mapping proxies;
    # this also keeps canonical hashing warning-free under Pydantic's serializer.
    return {
        "schema_version": policy.schema_version,
        "policy_version": policy.policy_version,
        "profile_binding": _jsonable(policy.profile_binding.model_dump(mode="python")),
        "phrase_grammar": _jsonable(policy.phrase_grammar.model_dump(mode="python")),
        "groups": {key: list(value) for key, value in policy.groups.items()},
        "target_roles": {
            key: _jsonable(value.model_dump(mode="python"))
            for key, value in policy.target_roles.items()
        },
        "target_titles": {
            key: _jsonable(value.model_dump(mode="python"))
            for key, value in policy.target_titles.items()
        },
    }


def canonical_policy_bytes(policy: DiscoveryPolicyV1) -> bytes:
    """Serialize policy content using the shared canonical JSON contract."""

    return json.dumps(
        canonical_policy_payload(policy),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def policy_sha256(policy: DiscoveryPolicyV1) -> str:
    return sha256(canonical_policy_bytes(policy)).hexdigest()


def canonical_policy_sha256(policy: DiscoveryPolicyV1) -> str:
    """Compatibility spelling for callers that name the canonical hash."""

    return policy_sha256(policy)
