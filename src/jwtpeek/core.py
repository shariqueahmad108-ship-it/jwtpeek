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


def inspect(token: str, now: int | None = None) -> Inspection:
    """Decode a JWT (without verifying its signature) and flag security issues.

    Args:
        token: the compact JWT string (``header.payload.signature``).
        now: unix timestamp used for expiry checks; defaults to the current time
            (injectable so tests are deterministic).

    Raises:
        ValueError: if the token is not three base64url/JSON segments.
    """
    now = int(time.time()) if now is None else now
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"expected 3 dot-separated segments, got {len(parts)}")

    header = decode_segment(parts[0])
    payload = decode_segment(parts[1])
    findings: list[Finding] = []

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

    return Inspection(header=header, payload=payload, findings=findings)
