# jwtpeek

Decode and **security-inspect** a JSON Web Token without verifying its signature.

`jwtpeek` is a small triage tool for reviews and pentests: paste a token, get its
decoded header and claims plus a list of things that look risky about *how the
token is built* — before you ever trust its contents.

> It never validates signatures. Treat every field it prints as attacker-controlled.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
jwtpeek <token>
jwtpeek <token> --json     # machine-readable output
```

Example:

```
$ jwtpeek eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
Header:
{ "alg": "none" }

Payload:
{ "sub": "admin" }

Findings:
  [CRITICAL] alg-none: Header alg is 'none': the token is unsigned and can be forged if the server accepts it.
  [MEDIUM] no-exp: Payload has no 'exp' claim: the token never expires.
```

The CLI exits `1` when a **CRITICAL/HIGH** finding is present (usable as a gate in
scripts/CI), `2` on a malformed token, and `0` otherwise.

## What it flags

| Code | Severity | Meaning |
|---|---|---|
| `alg-none` | CRITICAL | `alg` is `none` — token is unsigned and forgeable if accepted |
| `alg-missing` | MEDIUM | header has no `alg` |
| `alg-symmetric` | INFO | HMAC (`HS*`) alg — watch for RS/HS key-confusion |
| `no-exp` | MEDIUM | no `exp` claim — token never expires |
| `expired` | LOW | `exp` is in the past |
| `long-lived` | LOW | `exp` is more than a year out |
| `exp-not-numeric` | LOW | `exp` present but not a numeric timestamp |

## Library use

```python
from jwtpeek import inspect

result = inspect(token)
for f in result.findings:
    print(f.severity, f.code, f.message)
```

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT
