"""Command-line entry point for jwtpeek."""

from __future__ import annotations

import argparse
import json
import sys

from jwtpeek.core import inspect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jwtpeek",
        description="Decode and security-inspect a JWT without verifying its signature.",
    )
    parser.add_argument("token", help="the JWT to inspect (header.payload.signature)")
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    args = parser.parse_args(argv)

    try:
        result = inspect(args.token)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "header": result.header,
                    "payload": result.payload,
                    "findings": [f.__dict__ for f in result.findings],
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
        if not result.findings:
            print("  none")
        for finding in result.findings:
            print(f"  [{finding.severity}] {finding.code}: {finding.message}")

    # Non-zero exit when something serious is found, so jwtpeek is usable as a gate
    # in scripts/CI.
    if any(f.severity in ("CRITICAL", "HIGH") for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
