import base64
import json
import time

import pytest

from jwtpeek.core import decode_segment, inspect


def _seg(obj) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(header, payload) -> str:
    return f"{_seg(header)}.{_seg(payload)}.sig"


def test_decodes_header_and_payload():
    tok = _token({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": int(time.time()) + 3600})
    result = inspect(tok)
    assert result.header["alg"] == "HS256"
    assert result.payload["sub"] == "1"


def test_flags_alg_none_as_critical():
    # 'None', 'none', 'NONE' should all trip the unsigned-token finding.
    for alg in ("none", "None", "NONE"):
        tok = _token({"alg": alg}, {"sub": "1", "exp": int(time.time()) + 3600})
        codes = {f.code: f.severity for f in inspect(tok).findings}
        assert codes.get("alg-none") == "CRITICAL", alg


def test_flags_missing_exp():
    tok = _token({"alg": "HS256"}, {"sub": "1"})
    codes = {f.code for f in inspect(tok).findings}
    assert "no-exp" in codes


def test_flags_expired():
    tok = _token({"alg": "RS256"}, {"exp": 1000})
    findings = inspect(tok, now=2000).findings
    assert any(f.code == "expired" for f in findings)


def test_flags_long_lived():
    now = 1_000_000
    tok = _token({"alg": "RS256"}, {"exp": now + 400 * 86400})
    findings = inspect(tok, now=now).findings
    assert any(f.code == "long-lived" for f in findings)


def test_symmetric_alg_is_info():
    tok = _token({"alg": "HS512"}, {"exp": int(time.time()) + 3600})
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("alg-symmetric") == "INFO"


def test_valid_rs256_token_has_no_findings():
    tok = _token({"alg": "RS256"}, {"sub": "1", "exp": int(time.time()) + 3600})
    assert inspect(tok).findings == []


def test_rejects_wrong_segment_count():
    with pytest.raises(ValueError, match="3 dot-separated"):
        inspect("only.two")


def test_rejects_non_base64_segment():
    with pytest.raises(ValueError):
        inspect("@@@.@@@.sig")


def test_decode_segment_restores_padding():
    assert decode_segment(_seg({"a": 1})) == {"a": 1}
