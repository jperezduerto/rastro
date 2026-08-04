import os
from pathlib import Path

import pytest

from rastro.output import create_output_dir, drop_ownership, resolve_output_dir


def test_explicit_output_wins(tmp_path: Path):
    got = resolve_output_dir("10.0.0.1", str(tmp_path / "mine"), now="20260804-120000")
    assert got == tmp_path / "mine"


def test_default_name_includes_target_and_timestamp(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    got = resolve_output_dir("10.0.0.1", None, now="20260804-120000")
    assert got.name == "rastro-10.0.0.1-20260804-120000"


def test_target_with_slashes_does_not_escape_into_parent(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    got = resolve_output_dir("../../etc", None, now="20260804-120000")
    assert ".." not in got.name


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode bits not meaningful on Windows")
def test_created_dir_is_0700(tmp_path: Path):
    created = create_output_dir(tmp_path / "out")
    assert (created.stat().st_mode & 0o777) == 0o700


def test_drop_ownership_is_noop_without_sudo_uid(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SUDO_UID", raising=False)
    (tmp_path / "f.txt").write_text("x")
    drop_ownership(tmp_path)  # must not raise
    assert (tmp_path / "f.txt").read_text() == "x"


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0, reason="chown requires root"
)
def test_drop_ownership_does_not_follow_symlinks(tmp_path: Path, monkeypatch):
    outside = tmp_path / "outside.txt"
    outside.write_text("sensitive")
    original_uid = outside.stat().st_uid

    out = tmp_path / "out"
    out.mkdir()
    (out / "link").symlink_to(outside)

    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    drop_ownership(out)

    assert outside.stat().st_uid == original_uid


def test_default_output_dir_is_always_under_cwd(tmp_path: Path, monkeypatch):
    # There is no not-writable fallback: rastro only runs as root, so the old
    # os.access(cwd, W_OK) check was always true and its ~/.local/share branch was
    # dead code that would have left a root-owned directory in the user's home.
    monkeypatch.chdir(tmp_path)
    got = resolve_output_dir("10.0.0.1", None, now="20260804-120000")
    assert got.parent == tmp_path


def test_create_output_dir_refuses_a_pre_existing_directory(tmp_path: Path):
    # This guard is what makes the later recursive root chown safe: we must never
    # chown a tree we did not create ourselves.
    existing = tmp_path / "out"
    existing.mkdir()
    with pytest.raises(FileExistsError):
        create_output_dir(existing)


def test_drop_ownership_reports_chown_failure_without_raising(tmp_path, monkeypatch, capsys):
    # It runs in main's finally; raising there would replace the real return code
    # with a traceback and lose results that are already on disk.
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    def boom(*args, **kwargs):
        raise PermissionError("read-only file system")

    monkeypatch.setattr("rastro.output.os.chown", boom, raising=False)
    (tmp_path / "f.txt").write_text("x")

    drop_ownership(tmp_path)  # must not raise

    err = capsys.readouterr().err
    assert "could not hand back ownership" in err
    assert "results are intact" in err
