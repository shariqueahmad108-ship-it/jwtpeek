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


def test_flags_empty_signature():
    tok = f"{_seg({'alg': 'HS256'})}.{_seg({'sub': '1', 'exp': int(time.time()) + 3600})}."
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("empty-signature") == "HIGH"


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


def test_flags_key_source_headers_as_high():
    valid_exp = int(time.time()) + 3600
    for param in ("jku", "x5u", "jwk"):
        tok = _token({"alg": "RS256", param: "x"}, {"exp": valid_exp})
        codes = {f.code: f.severity for f in inspect(tok).findings}
        assert codes.get(f"header-{param}") == "HIGH", param


def test_flags_x5c_as_medium():
    tok = _token({"alg": "RS256", "x5c": ["cert"]}, {"exp": int(time.time()) + 3600})
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("header-x5c") == "MEDIUM"


def test_flags_kid_header():
    tok = _token({"alg": "RS256", "kid": "../../key"}, {"exp": int(time.time()) + 3600})
    codes = {f.code for f in inspect(tok).findings}
    assert "header-kid" in codes


def test_flags_valid_crit_as_medium():
    # A well-formed crit naming a present extension param is reported at MEDIUM.
    tok = _token({"alg": "RS256", "b64": False, "crit": ["b64"]}, {"exp": int(time.time()) + 3600})
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("header-crit") == "MEDIUM"
    assert "header-crit-invalid" not in codes


def test_flags_crit_not_a_list_as_invalid():
    tok = _token({"alg": "RS256", "crit": "b64"}, {"exp": int(time.time()) + 3600})
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("header-crit-invalid") == "HIGH"
    assert "header-crit" not in codes


def test_flags_empty_crit_as_invalid():
    tok = _token({"alg": "RS256", "crit": []}, {"exp": int(time.time()) + 3600})
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("header-crit-invalid") == "HIGH"


def test_flags_crit_naming_registered_header_as_invalid():
    tok = _token({"alg": "RS256", "crit": ["alg"]}, {"exp": int(time.time()) + 3600})
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("header-crit-invalid") == "HIGH"


def test_flags_crit_naming_absent_param_as_invalid():
    # crit names an extension param that is not present in the header — an RFC 7515 violation.
    tok = _token({"alg": "RS256", "crit": ["dpop+ext"]}, {"exp": int(time.time()) + 3600})
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("header-crit-invalid") == "HIGH"


def test_flags_not_yet_valid_nbf():
    now = 1_000_000
    tok = _token({"alg": "RS256"}, {"exp": now + 3600, "nbf": now + 600})
    codes = {f.code for f in inspect(tok, now=now).findings}
    assert "not-yet-valid" in codes


def test_flags_iat_in_future():
    now = 1_000_000
    tok = _token({"alg": "RS256"}, {"exp": now + 3600, "iat": now + 600})
    codes = {f.code for f in inspect(tok, now=now).findings}
    assert "iat-future" in codes


def test_valid_rs256_token_has_no_findings():
    tok = _token({"alg": "RS256"}, {"sub": "1", "exp": int(time.time()) + 3600})
    assert inspect(tok).findings == []


def test_rejects_wrong_segment_count():
    with pytest.raises(ValueError, match="3-segment JWS or 5-segment JWE"):
        inspect("only.two")


def test_jwe_five_segments_reported_as_encrypted():
    # A 5-segment JWE: header . encrypted_key . iv . ciphertext . tag
    header = _seg({"alg": "RSA-OAEP", "enc": "A256GCM"})
    tok = f"{header}.encrypted_key.iv.ciphertext.tag"
    result = inspect(tok)
    codes = {f.code: f.severity for f in result.findings}
    assert codes.get("jwe-encrypted") == "INFO"
    assert result.header["enc"] == "A256GCM"
    assert result.payload == {}  # claims are ciphertext, not inspectable


def test_jwe_rsa1_5_key_management_flagged():
    header = _seg({"alg": "RSA1_5", "enc": "A128CBC-HS256"})
    tok = f"{header}.ek.iv.ct.tag"
    codes = {f.code: f.severity for f in inspect(tok).findings}
    assert codes.get("jwe-weak-alg") == "HIGH"
    assert codes.get("jwe-encrypted") == "INFO"


def test_rejects_non_base64_segment():
    with pytest.raises(ValueError):
        inspect("@@@.@@@.sig")


def test_decode_segment_restores_padding():
    assert decode_segment(_seg({"a": 1})) == {"a": 1}


def test_severity_rank_orders_levels():
    from jwtpeek.core import severity_rank
    assert severity_rank("INFO") < severity_rank("MEDIUM") < severity_rank("HIGH") < severity_rank("CRITICAL")
    assert severity_rank("bogus") == -1
