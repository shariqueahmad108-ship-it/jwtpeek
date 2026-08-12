# jwtpeek

Decode and **security-inspect** a JSON Web Token without verifying its signature.

`jwtpeek` is a small triage tool for reviews and pentests: paste a token, get its
decoded header and claims plus a list of things that look risky about *how the
token is built* — before you ever trust its contents.

> It never validates signatures. Treat every field it prints as attacker-controlled.

[![CI](https://github.com/shariqueahmad108-ship-it/jwtpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/shariqueahmad108-ship-it/jwtpeek/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
jwtpeek <token>
jwtpeek <token> --json                 # machine-readable output
echo "<token>" | jwtpeek -             # read the token from stdin
jwtpeek <token> --min-severity HIGH    # only show HIGH/CRITICAL (CI gate)
jwtpeek --batch tokens.txt             # inspect a file of tokens, one per line
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
| `empty-signature` | HIGH | signature segment is empty — token is effectively unsigned |
| `alg-missing` | MEDIUM | header has no `alg` |
| `alg-symmetric` | INFO | HMAC (`HS*`) alg — watch for RS/HS key-confusion |
| `header-jku` / `header-x5u` | HIGH | header points to a URL for the verification key — key injection / SSRF if trusted |
| `header-jwk` | HIGH | header embeds a public key — forgeable if the server verifies against it |
| `header-x5c` | MEDIUM | header embeds an X.509 cert chain — review whether it's trusted |
| `header-kid` | LOW | `kid` is attacker-controlled — path-traversal / SQLi if used unsafely for key lookup |
| `no-exp` | MEDIUM | no `exp` claim — token never expires |
| `expired` | LOW | `exp` is in the past |
| `long-lived` | LOW | `exp` is more than a year out |
| `exp-not-numeric` | LOW | `exp` present but not a numeric timestamp |
| `not-yet-valid` | LOW | `nbf` is in the future — token not valid yet |
| `iat-future` | LOW | `iat` (issued-at) is in the future — clock skew or tampering |

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
