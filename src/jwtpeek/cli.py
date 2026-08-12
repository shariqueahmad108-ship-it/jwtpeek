"""Command-line entry point for jwtpeek."""

from __future__ import annotations

import argparse
import json
import sys

from jwtpeek.core import SEVERITY_ORDER, inspect, severity_rank


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jwtpeek",
        description="Decode and security-inspect a JWT without verifying its signature.",
    )
    parser.add_argument(
        "token", help="the JWT to inspect (header.payload.signature), or '-' to read it from stdin"
    )
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="INFO",
        help="only report findings at or above this severity (default: INFO — all)",
    )
    args = parser.parse_args(argv)

    token = args.token
    if token == "-":
        token = sys.stdin.read().strip()
        if not token:
            print("error: no token provided on stdin", file=sys.stderr)
            return 2

    try:
        result = inspect(token)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    threshold = severity_rank(args.min_severity)
    findings = [f for f in result.findings if severity_rank(f.severity) >= threshold]

    if args.json:
        print(
            json.dumps(
                {
                    "header": result.header,
                    "payload": result.payload,
                    "findings": [f.__dict__ for f in findings],
                },
                indent=2,
            )
        )
    else:
        print("Header:")
        print(json.dumps(result.header, indent=2))
        print("\nPayload:")
        print(json.dumps(result.payload, indent=2))
        print("\nFindings:")
        if not findings:
            print("  none")
        for finding in findings:
            print(f"  [{finding.severity}] {finding.code}: {finding.message}")

    # Non-zero exit when something serious is shown, so jwtpeek is usable as a gate
    # in scripts/CI (honouring --min-severity).
    if any(f.severity in ("CRITICAL", "HIGH") for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
