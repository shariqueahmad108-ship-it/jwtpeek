"""Decode and security-inspect JSON Web Tokens without verifying signatures.

This is a *triage* aid: it never validates a signature, so treat every field as
attacker-controlled. It exists to answer "what does this token claim, and what
looks risky about how it's built?" quickly during a review or a pentest.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass, field
from typing import Any

# alg values that mean the token carries no real signature.
_NONE_ALGS = {"none"}
# HMAC family — symmetric, relevant to RS/HS key-confusion attacks.
_SYMMETRIC_PREFIX = "HS"
# A token valid for longer than this (seconds) is flagged as long-lived.
LONG_LIVED_SECONDS = 365 * 24 * 3600  # 1 year

# Header parameters that let a token influence which key verifies it. If the
# server honours them, the token can often be forged (or coerced into an SSRF).
_KEY_SOURCE_HEADERS = {
    "jku": ("HIGH", "points to a URL the server may fetch a JWK Set from — key injection / SSRF if trusted."),
    "x5u": ("HIGH", "points to a URL the server may fetch an X.509 cert from — key injection / SSRF if trusted."),
    "jwk": ("HIGH", "embeds a public key the server may verify against — forgeable if trusted."),
    "x5c": ("MEDIUM", "embeds an X.509 cert chain the server may verify against — review whether it is trusted."),
}

# Header parameters registered by RFC 7515 / JWA. A 'crit' list must name only
# *extension* params (and each must actually be present in the header), so any of
# these appearing in 'crit' is a spec violation and a tampering signal.
_RESERVED_CRIT_NAMES = {
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
}

# JWE (encrypted token) key-management algorithms with known weaknesses.
_RSA1_5_DETAIL = (
    "key management is RSAES-PKCS1-v1_5 (RSA1_5), vulnerable to Bleichenbacher / "
    "million-message padding-oracle attacks; RSA-OAEP should be used instead."
)
_JWE_RISKY_ALGS = {
    "RSA1_5": ("HIGH", _RSA1_5_DETAIL),
}


@dataclass
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    code: str
    message: str


@dataclass
class Inspection:
    header: dict[str, Any]
    payload: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)


# Severity levels, ordered least to most severe.
SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def severity_rank(severity: str) -> int:
    """Rank of a severity (0 = INFO … 4 = CRITICAL); -1 if unknown."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, restoring any stripped ``=`` padding."""
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"segment is not valid base64url: {exc}") from exc


def decode_segment(segment: str) -> dict[str, Any]:
    """Decode one JWT segment (header or payload) into a JSON object."""
    data = _b64url_decode(segment)
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"segment is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("segment does not decode to a JSON object")
    return obj


def _inspect_jwe(parts: list[str]) -> Inspection:
    """Inspect a 5-segment JWE (encrypted token).

    A JWE's payload is ciphertext, so its claims cannot be read without the
    decryption key. We still decode the (cleartext) JOSE header and surface the
    key-management (``alg``) and content-encryption (``enc``) algorithms, which
    are the useful triage signals for an encrypted token.
    """
    header = decode_segment(parts[0])
    alg = str(header.get("alg", "")).strip()
    enc = str(header.get("enc", "")).strip()
    findings: list[Finding] = [
        Finding(
            "INFO",
            "jwe-encrypted",
            f"This is a JWE (encrypted, 5 segments), not a signed JWS: the payload is ciphertext and its "
            f"claims cannot be inspected without the decryption key (alg={alg or '?'}, enc={enc or '?'}).",
        )
    ]
    risky = _JWE_RISKY_ALGS.get(alg)
    if risky:
        severity, detail = risky
        findings.append(Finding(severity, "jwe-weak-alg", f"JWE {detail}"))
    return Inspection(header=header, payload={}, findings=findings)


def inspect(token: str, now: int | None = None) -> Inspection:
    """Decode a JWT (without verifying its signature) and flag security issues.

    Args:
        token: the compact JWT string — a 3-segment JWS (``header.payload.signature``)
            or a 5-segment JWE (encrypted; only its header is inspectable).
        now: unix timestamp used for expiry checks; defaults to the current time
            (injectable so tests are deterministic).

    Raises:
        ValueError: if the token is not a 3-segment JWS or a 5-segment JWE.
    """
    now = int(time.time()) if now is None else now
    parts = token.strip().split(".")
    if len(parts) == 5:
        return _inspect_jwe(parts)
    if len(parts) != 3:
        raise ValueError(f"expected a 3-segment JWS or 5-segment JWE, got {len(parts)} segments")

    header = decode_segment(parts[0])
    payload = decode_segment(parts[1])
    findings: list[Finding] = []

    if parts[2] == "":
        findings.append(
            Finding(
                "HIGH",
                "empty-signature",
                "The signature segment is empty: the token is effectively unsigned and forgeable if "
                "the server does not enforce a signature.",
            )
        )

    alg = str(header.get("alg", "")).strip()
    if alg.lower() in _NONE_ALGS:
        findings.append(
            Finding(
                "CRITICAL",
                "alg-none",
                "Header alg is 'none': the token is unsigned and can be forged if the server accepts it.",
            )
        )
    elif alg == "":
        findings.append(
            Finding(
                "MEDIUM",
                "alg-missing",
                "Header has no 'alg' — non-standard; verify how the server selects the algorithm.",
            )
        )
    elif alg.upper().startswith(_SYMMETRIC_PREFIX):
        findings.append(
            Finding(
                "INFO",
                "alg-symmetric",
                f"Symmetric algorithm ({alg}): if the server also accepts RS*, it may be vulnerable to key-confusion.",
            )
        )

    for param, (severity, detail) in _KEY_SOURCE_HEADERS.items():
        if param in header:
            findings.append(Finding(severity, f"header-{param}", f"Header '{param}' present: {detail}"))

    if "kid" in header:
        findings.append(
            Finding(
                "LOW",
                "header-kid",
                "Header 'kid' is attacker-controlled; if used to look up a key unsafely it can enable "
                "path traversal or SQL injection.",
            )
        )

    if "crit" in header:
        crit = header.get("crit")
        problems: list[str] = []
        if not isinstance(crit, list) or not crit:
            problems.append("must be a non-empty array of strings")
        elif not all(isinstance(name, str) for name in crit):
            problems.append("every entry must be a string")
        else:
            for name in crit:
                if name in _RESERVED_CRIT_NAMES:
                    problems.append(f"names the registered header '{name}'")
                elif name not in header:
                    problems.append(f"names '{name}', which is absent from the header")
        if problems:
            findings.append(
                Finding(
                    "HIGH",
                    "header-crit-invalid",
                    "Header 'crit' violates RFC 7515 (" + "; ".join(problems) + "): a verifier that "
                    "does not reject this can be bypassed, and a malformed crit list is a tampering signal.",
                )
            )
        else:
            findings.append(
                Finding(
                    "MEDIUM",
                    "header-crit",
                    "Header 'crit' marks extension params the verifier MUST understand and process; "
                    "confirm the server enforces every listed param — ignored 'crit' extensions are a "
                    "known validation-bypass vector.",
                )
            )

    if "exp" not in payload:
        findings.append(
            Finding("MEDIUM", "no-exp", "Payload has no 'exp' claim: the token never expires.")
        )
    else:
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            if exp < now:
                findings.append(
                    Finding("LOW", "expired", f"Token is expired (exp={int(exp)}, now={now}).")
                )
            elif exp - now > LONG_LIVED_SECONDS:
                days = int((exp - now) / 86400)
                findings.append(
                    Finding("LOW", "long-lived", f"Token is long-lived (~{days} days until exp).")
                )
        else:
            findings.append(
                Finding("LOW", "exp-not-numeric", "'exp' is present but not a numeric timestamp.")
            )

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and not isinstance(nbf, bool) and nbf > now:
        minutes = int((nbf - now) / 60)
        findings.append(
            Finding("LOW", "not-yet-valid", f"Token is not valid yet (nbf is ~{minutes} min in the future).")
        )

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and not isinstance(iat, bool) and iat > now:
        findings.append(
            Finding("LOW", "iat-future", "'iat' (issued-at) is in the future — clock skew or a tampered timestamp.")
        )

    return Inspection(header=header, payload=payload, findings=findings)
