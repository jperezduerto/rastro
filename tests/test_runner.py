# tests/test_runner.py
import os
from pathlib import Path

from rastro import runner
from rastro.runner import CommandSpec, run_command, run_many


def test_successful_command_records_exit_code_and_writes_stdout(tmp_path: Path):
    art = run_command(
        "echo hello-rastro", tool="echo", timeout=10, output_dir=tmp_path, slug="greet"
    )
    assert art.exit_code == 0
    assert art.timed_out is False
    assert "hello-rastro" in (tmp_path / art.stdout_path).read_text()


def test_stdout_path_is_relative_to_output_dir(tmp_path: Path):
    art = run_command("echo x", tool="echo", timeout=10, output_dir=tmp_path, slug="rel")
    assert not Path(art.stdout_path).is_absolute()
    assert art.stdout_path.startswith("raw/")


def test_timeout_is_recorded_not_raised(tmp_path: Path):
    art = run_command(
        "sleep 5", tool="sleep", timeout=1, output_dir=tmp_path, slug="slow"
    )
    assert art.timed_out is True
    assert art.exit_code != 0


def test_failing_command_records_nonzero_exit(tmp_path: Path):
    art = run_command("exit 3", tool="sh", timeout=10, output_dir=tmp_path, slug="fail")
    assert art.exit_code == 3
    assert art.timed_out is False


def test_run_many_returns_one_artifact_per_spec(tmp_path: Path):
    specs = [
        CommandSpec(command=f"echo {i}", tool="echo", timeout=5, slug=f"n{i}")
        for i in range(5)
    ]
    arts = run_many(specs, max_parallel=3, output_dir=tmp_path)
    assert len(arts) == 5
    assert {a.slug_source for a in arts} == {f"n{i}" for i in range(5)}


def test_run_many_isolates_failures(tmp_path: Path):
    specs = [
        CommandSpec(command="echo ok", tool="echo", timeout=5, slug="good"),
        CommandSpec(command="exit 9", tool="sh", timeout=5, slug="bad"),
    ]
    arts = {a.slug_source: a for a in run_many(specs, max_parallel=2, output_dir=tmp_path)}
    assert arts["good"].exit_code == 0
    assert arts["bad"].exit_code == 9


def test_run_command_write_failure_returns_artifact_not_raise(tmp_path: Path, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("simulated disk full")

    monkeypatch.setattr(runner.os, "open", boom)
    art = run_command("echo hi", tool="echo", timeout=5, output_dir=tmp_path, slug="x")
    assert art.exit_code != 0
    assert art.timed_out is False
    assert art.stdout_path == ""


def test_run_many_isolates_write_failure(tmp_path: Path, monkeypatch):
    real_open = os.open

    def flaky_open(path, *args, **kwargs):
        if "bad" in str(path):
            raise OSError("simulated write failure")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(runner.os, "open", flaky_open)
    specs = [
        CommandSpec(command="echo ok", tool="echo", timeout=5, slug="good"),
        CommandSpec(command="echo bad", tool="echo", timeout=5, slug="bad"),
    ]
    arts = {a.slug_source: a for a in run_many(specs, max_parallel=2, output_dir=tmp_path)}
    assert arts["good"].exit_code == 0
    assert arts["bad"].exit_code != 0
