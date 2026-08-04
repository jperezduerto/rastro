from rastro.cli import main


def test_version_flag_prints_and_exits_zero(capsys):
    code = main(["--version"])
    assert code == 0
    assert "rastro" in capsys.readouterr().out
