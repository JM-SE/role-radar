"""Credential filesystem policy tests."""

import stat
from dataclasses import dataclass

from role_radar.acquisition.credentials import _credential_mode_allowed


@dataclass(frozen=True)
class Metadata:
    st_mode: int
    st_uid: int
    st_gid: int


def _metadata(*, mode: int, uid: int, gid: int) -> Metadata:
    return Metadata(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid)


def test_accepts_systemd_root_owned_0440_projection() -> None:
    assert _credential_mode_allowed(_metadata(mode=0o440, uid=0, gid=0))


def test_rejects_group_readable_credential_from_non_root_owner() -> None:
    assert not _credential_mode_allowed(_metadata(mode=0o440, uid=1000, gid=1000))


def test_retains_strict_private_credential_modes() -> None:
    assert _credential_mode_allowed(_metadata(mode=0o400, uid=0, gid=0))
    assert _credential_mode_allowed(_metadata(mode=0o600, uid=1000, gid=1000))
