import base64
import io
import json
import time

import jwtpeek.cli as cli


def _seg(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _token(header, payload) -> str:
    return f"{_seg(header)}.{_seg(payload)}.sig"


def test_reads_token_from_stdin(monkeypatch, capsys):
    tok = _token({"alg": "none"}, {"sub": "admin"})
    monkeypatch.setattr("sys.stdin", io.StringIO(tok + "\n"))

    rc = cli.main(["-"])

    out = capsys.readouterr().out
    assert "alg-none" in out
    assert rc == 1  # CRITICAL finding -> non-zero exit


def test_empty_stdin_errors(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("   \n"))

    rc = cli.main(["-"])

    assert rc == 2
    assert "no token" in capsys.readouterr().err


def test_token_argument_still_works(capsys):
    tok = _token({"alg": "RS256"}, {"sub": "1", "exp": int(time.time()) + 3600})

    rc = cli.main([tok])

    assert "Findings:" in capsys.readouterr().out
    assert rc == 0  # clean token, no critical/high


def test_min_severity_filters_below_threshold(capsys):
    # alg=none -> alg-none (CRITICAL); no exp -> no-exp (MEDIUM)
    tok = _token({"alg": "none"}, {"sub": "1"})
    rc = cli.main([tok, "--min-severity", "CRITICAL"])
    out = capsys.readouterr().out
    assert "alg-none" in out
    assert "no-exp" not in out   # MEDIUM finding filtered out
    assert rc == 1              # a CRITICAL is still shown -> gate fails


def test_min_severity_hides_everything_below_high(capsys):
    # HS256 + valid exp -> only an INFO finding; --min-severity HIGH hides it
    tok = _token({"alg": "HS256"}, {"sub": "1", "exp": int(time.time()) + 3600})
    rc = cli.main([tok, "--min-severity", "HIGH"])
    out = capsys.readouterr().out
    assert "Findings:\n  none" in out
    assert rc == 0


def test_batch_inspects_file_of_tokens(tmp_path, capsys):
    f = tmp_path / "tokens.txt"
    f.write_text(
        _token({"alg": "none"}, {"sub": "1"}) + "\n"          # CRITICAL
        + _token({"alg": "RS256"}, {"sub": "1", "exp": int(time.time()) + 3600}) + "\n"  # clean
        + "not-a-jwt\n"                                         # error line
    )
    rc = cli.main(["--batch", str(f)])
    out = capsys.readouterr().out
    assert "[1]" in out and "CRITICAL" in out
    assert "[2]" in out
    assert "[3] error" in out
    assert rc == 1  # line 1 has a CRITICAL -> gate fails


def test_batch_json_outputs_array(tmp_path, capsys):
    f = tmp_path / "tokens.txt"
    f.write_text(_token({"alg": "none"}, {"sub": "1"}) + "\n")
    rc = cli.main(["--batch", str(f), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list) and data[0]["line"] == 1
    assert any(x["code"] == "alg-none" for x in data[0]["findings"])
    assert rc == 1


def test_batch_empty_file_errors(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("\n  \n")
    assert cli.main(["--batch", str(f)]) == 2


def test_no_token_and_no_batch_errors():
    import pytest
    with pytest.raises(SystemExit):
        cli.main([])


def test_version_flag_prints_version(capsys):
    import pytest
    from jwtpeek import __version__
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out
