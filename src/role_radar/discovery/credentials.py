"""Worker-only credential resolver; no application settings or persistence."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr


class CredentialError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WorkerCredentials:
    brave_api_key: SecretStr
    tavily_api_key: SecretStr
    query_hmac_key: bytes


def read_worker_secret(path: str | os.PathLike[str]) -> bytes:
    candidate = Path(path)
    try:
        if candidate.is_symlink() or not candidate.is_file():
            raise CredentialError("credential path is not a regular file")
        metadata = candidate.stat()
        if stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}:
            raise CredentialError("credential file must be private")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise CredentialError("credential owner is invalid")
        value = candidate.read_bytes().strip()
    except OSError as exc:
        raise CredentialError("credential is unavailable") from exc
    if not value or len(value) > 4096:
        raise CredentialError("credential is invalid")
    return value


def resolve_worker_credentials(
    *, brave_path: str, tavily_path: str, hmac_path: str
) -> WorkerCredentials:
    return WorkerCredentials(
        brave_api_key=SecretStr(read_worker_secret(brave_path).decode("utf-8")),
        tavily_api_key=SecretStr(read_worker_secret(tavily_path).decode("utf-8")),
        query_hmac_key=read_worker_secret(hmac_path),
    )
