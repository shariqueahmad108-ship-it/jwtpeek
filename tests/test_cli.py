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
