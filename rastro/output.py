"""Where results go, and who owns them afterwards.

rastro runs as root, so everything it writes is root-owned by default. That makes
the report unreadable-without-sudo for the human who ran it, so ownership is
handed back to the invoking user during teardown.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

_UNSAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]+")


def _safe_target_name(target: str) -> str:
    """A target becomes part of a directory name; it must not contain path parts."""
    cleaned = _UNSAFE_NAME.sub("-", target).strip("-.")
    return cleaned or "target"


def resolve_output_dir(target: str, explicit: str | None, now: str) -> Path:
    """--output wins; otherwise ./rastro-<target>-<timestamp>.

    There is no not-writable fallback. rastro only ever runs as root, so a
    writability check on the working directory is always true — the fallback
    branch was unreachable, and the platform data dir it pointed at would have
    left a root-owned ~/.local/share/rastro/ behind. If the directory genuinely
    cannot be created, cli reports the OSError and exits.
    """
    if explicit:
        return Path(explicit).expanduser()
    return Path.cwd() / f"rastro-{_safe_target_name(target)}-{now}"


def create_output_dir(path: Path) -> Path:
    """Create the output directory 0700. Refuses to reuse a pre-existing directory:
    we later chown this tree, and chowning a directory we did not create is unsafe."""
    if path.exists():
        raise FileExistsError(f"output directory already exists: {path}")
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    return path


def drop_ownership(path: Path) -> None:
    """Hand the output tree back to the human who ran sudo.

    follow_symlinks=False is load-bearing: a recursive chown that follows symlinks
    is a privilege-escalation primitive (a link to /etc/shadow would be handed to
    an unprivileged user).

    This runs from cli.main's `finally`, so it must never raise: a chown failure
    here would discard the real return code and replace it with a traceback,
    losing results that were already written. Failures are reported to stderr and
    otherwise ignored.
    """
    raw_uid = os.environ.get("SUDO_UID")
    if raw_uid is None:
        return  # real root login — nobody to hand back to
    try:
        uid = int(raw_uid)
        gid = int(os.environ.get("SUDO_GID", raw_uid))
    except ValueError:
        print(f"cannot hand back ownership: bad SUDO_UID/SUDO_GID: {raw_uid!r}",
              file=sys.stderr)
        return
    if not path.exists():
        return
    try:
        os.chown(path, uid, gid, follow_symlinks=False)
        for root, dirs, files in os.walk(path):
            for name in dirs + files:
                os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)
    except OSError as error:
        print(
            f"could not hand back ownership of {path} to {uid}:{gid}: {error}\n"
            f"results are intact but may still be root-owned",
            file=sys.stderr,
        )
