"""Command-line entry point for jwtpeek."""

from __future__ import annotations

import argparse
import json
import sys

from jwtpeek import __version__
from jwtpeek.core import SEVERITY_ORDER, Inspection, inspect, severity_rank


def _filtered(findings, threshold):
    return [f for f in findings if severity_rank(f.severity) >= threshold]


def _has_serious(findings) -> bool:
    return any(f.severity in ("CRITICAL", "HIGH") for f in findings)


def _print_single(result: Inspection, findings, as_json: bool) -> None:
    if as_json:
        print(json.dumps({
            "header": result.header,
            "payload": result.payload,
            "findings": [f.__dict__ for f in findings],
        }, indent=2))
        return
    print("Header:")
    print(json.dumps(result.header, indent=2))
    print("\nPayload:")
    print(json.dumps(result.payload, indent=2))
    print("\nFindings:")
    if not findings:
        print("  none")
    for finding in findings:
        print(f"  [{finding.severity}] {finding.code}: {finding.message}")


def _run_batch(path: str, threshold: int, as_json: bool) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            tokens = [(i, line.strip()) for i, line in enumerate(fh, 1) if line.strip()]
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    if not tokens:
        print(f"error: no tokens found in {path}", file=sys.stderr)
        return 2

    results: list[dict] = []
    gate_failed = False
    for lineno, tok in tokens:
        try:
            result = inspect(tok)
        except ValueError as exc:
            results.append({"line": lineno, "error": str(exc)})
            continue
        findings = _filtered(result.findings, threshold)
        gate_failed = gate_failed or _has_serious(findings)
        results.append({"line": lineno, "findings": [f.__dict__ for f in findings]})

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if "error" in r:
                print(f"[{r['line']}] error: {r['error']}")
                continue
            fs = r["findings"]
            top = max((f["severity"] for f in fs), key=severity_rank, default="clean")
            codes = ", ".join(f["code"] for f in fs) or "-"
            print(f"[{r['line']}] {top:<8} {len(fs)} finding(s): {codes}")

    return 1 if gate_failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jwtpeek",
        description="Decode and security-inspect a JWT without verifying its signature.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "token",
        nargs="?",
        help="the JWT to inspect (header.payload.signature), or '-' to read it from stdin",
    )
    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="inspect a file of tokens, one per line, printing a summary per token",
    )
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="INFO",
        help="only report findings at or above this severity (default: INFO — all)",
    )
    args = parser.parse_args(argv)

    threshold = severity_rank(args.min_severity)

    if args.batch:
        return _run_batch(args.batch, threshold, args.json)

    token = args.token
    if token is None:
        parser.error("provide a token, '-' to read from stdin, or --batch FILE")
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

    findings = _filtered(result.findings, threshold)
    _print_single(result, findings, args.json)

    return 1 if _has_serious(findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
