"""Where results go, and who owns them afterwards.

rastro runs as root, so everything it writes is root-owned by default. That makes
the report unreadable-without-sudo for the human who ran it, so ownership is
handed back to the invoking user during teardown.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_UNSAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]+")


def _safe_target_name(target: str) -> str:
    """A target becomes part of a directory name; it must not contain path parts."""
    cleaned = _UNSAFE_NAME.sub("-", target).strip("-.")
    return cleaned or "target"


def resolve_output_dir(target: str, explicit: str | None, now: str) -> Path:
    """--output wins; otherwise ./rastro-<target>-<timestamp>, falling back to the
    platform data dir when the working directory is not writable."""
    if explicit:
        return Path(explicit).expanduser()
    name = f"rastro-{_safe_target_name(target)}-{now}"
    cwd = Path.cwd()
    if os.access(cwd, os.W_OK):
        return cwd / name
    return invoking_user_home() / ".local" / "share" / "rastro" / name


def create_output_dir(path: Path) -> Path:
    """Create the output directory 0700. Refuses to reuse a pre-existing directory:
    we later chown this tree, and chowning a directory we did not create is unsafe."""
    if path.exists():
        raise FileExistsError(f"output directory already exists: {path}")
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    return path


def invoking_user_home() -> Path:
    """Home of the human who ran sudo, not /root — otherwise their config silently
    stops applying the moment they elevate."""
    user = os.environ.get("SUDO_USER")
    if user:
        return Path(os.path.expanduser(f"~{user}"))
    return Path.home()


def drop_ownership(path: Path) -> None:
    """Hand the output tree back to the human who ran sudo.

    follow_symlinks=False is load-bearing: a recursive chown that follows symlinks
    is a privilege-escalation primitive (a link to /etc/shadow would be handed to
    an unprivileged user).
    """
    raw_uid = os.environ.get("SUDO_UID")
    if raw_uid is None:
        return  # real root login — nobody to hand back to
    uid = int(raw_uid)
    gid = int(os.environ.get("SUDO_GID", raw_uid))
    if not path.exists():
        return
    os.chown(path, uid, gid, follow_symlinks=False)
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)
