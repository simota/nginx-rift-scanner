---
name: nginx-rift-scanner
description: "Scans for CVE-2026-42945 (NGINX Rift): runs version detection against the NGINX binary, package managers, and Dockerfile image tags, then parses nginx.conf and all included files for the heap-overflow trigger pattern (unnamed PCRE captures plus a query string in rewrite/if/set, followed by a second rewrite/if/set in the same scope). Use when auditing NGINX configurations for CVE-2026-42945, checking an NGINX version for the Rift vulnerability, or reviewing rewrite-module directives for the Rift exploit pattern."
---

# nginx-rift-scanner

Detect CVE-2026-42945 ("NGINX Rift") — a CVSS v4.0 9.2 CRITICAL heap-based
buffer overflow (CWE-122) in `ngx_http_rewrite_module`. This skill drives
`scripts/scan_nginx_rift.py`, a Python 3 stdlib-only scanner. Detect-only: no
auto-fix, no network calls, no external dependencies.

## Trigger Guidance

Use this skill when the user needs:
- an NGINX configuration audited for CVE-2026-42945 (NGINX Rift)
- an installed NGINX version checked against the Rift affected-version table
- `rewrite`/`if`/`set` directives reviewed for the Rift heap-overflow pattern
- a CI/SIEM-friendly JSON vulnerability report for NGINX Rift

Route elsewhere when the task is primarily:
- writing or fixing application/config code: `Builder`
- a general security audit beyond this CVE: `Sentinel`
- threat modeling or exploit development: `Breach` / `Probe`

## Workflow

Two-pronged detection runs on every invocation:

1. **Version check** — `nginx -V`, `dpkg`/`rpm`/`apk`, and
   `Dockerfile`/`docker-compose` image tags; each source classified
   `VULNERABLE` / `POTENTIALLY_VULNERABLE` (1.30.1 only) / `FIXED` / `UNKNOWN`.
2. **Config pattern scan** — a brace-aware tokenizer parses `nginx.conf` and all
   `include`d files, flagging a scope block only when all three trigger
   conditions hold in order. Full condition spec, include-splicing, and
   `--prefix` resolution semantics → `references/detection-spec.md`.

### Usage

```bash
# Basic scan (nginx in PATH, config at /etc/nginx/nginx.conf)
python3 scripts/scan_nginx_rift.py

# Custom binary, config, prefix, and Docker scan dir
python3 scripts/scan_nginx_rift.py \
  --nginx-binary /usr/sbin/nginx \
  --config /etc/nginx/nginx.conf \
  --prefix /etc/nginx \
  --scan-dir .

# JSON output for CI / SIEM integration
python3 scripts/scan_nginx_rift.py --json

# Scan fixtures
python3 scripts/scan_nginx_rift.py --config fixtures/vulnerable.nginx.conf
python3 scripts/scan_nginx_rift.py --config fixtures/safe.nginx.conf
```

Flags: `--nginx-binary` (default `nginx`), `--config` (default
`/etc/nginx/nginx.conf`), `--prefix` (default: directory of `--config`),
`--scan-dir` (default `.`), `--json`. Exit codes: `0` = no findings, `1` =
VULNERABLE / POTENTIALLY_VULNERABLE version or config pattern found.

### Tests

```bash
python3 -m unittest discover -s tests
```

27 tests. Fixture contract: `fixtures/vulnerable.nginx.conf` → 3 config
findings, exit 1; `fixtures/safe.nginx.conf` → 0 findings, exit 0.

## Boundaries

### Always
- Run `scripts/scan_nginx_rift.py` to produce findings — never assert
  vulnerability status from manual inspection alone.
- Treat every config finding as a heuristic requiring human review
  (`references/false-positives.md`) before concluding a config is exploitable.
- Report 1.30.1 as `POTENTIALLY_VULNERABLE` (exit 1, conservative).
- Honor exit codes: `0` = no findings, `1` = VULNERABLE / POTENTIALLY_VULNERABLE.

### Ask First
- Before treating a config finding as confirmed-exploitable (it is a
  conservative heuristic, not proof).
- Before recommending a workaround over the preferred upgrade path.

### Never
- Auto-fix or rewrite NGINX configurations — the scanner is detect-only.
- Make network calls or add external (non-stdlib) Python dependencies.
- Suppress or downgrade a finding to make the exit code green.

## Output Requirements

Every deliverable must include:
- Version-check verdict per source (binary / package manager / Docker tag),
  each classified `VULNERABLE` / `POTENTIALLY_VULNERABLE` / `FIXED` / `UNKNOWN`.
- Config findings with file, scope, and the triggering directive pair, each
  labeled as a heuristic requiring human review.
- The final exit code (`0` / `1`) and overall verdict.
- Remediation guidance — upgrade preferred; named-capture workaround otherwise
  (`references/false-positives.md`).

## Reference Map

| Reference | Read this when |
|-----------|----------------|
| `references/detection-spec.md` | You need the root cause (`is_args` length-vs-copy mismatch), the full affected-versions table incl. the 1.30.1 `POTENTIALLY_VULNERABLE` note, the three trigger conditions in detail (`${1}`–`${9}` brace form, value/replacement-arg scoping, `if`-conservative handling), include-splicing, or `--prefix` resolution semantics. |
| `references/false-positives.md` | You are reviewing a config finding — full false-positive caveat list, human-review guidance, and the named-capture remediation example. |

## AUTORUN Support

When invoked with `_AGENT_CONTEXT`:
- Parse `Role / Task / Task_Type / Mode / Chain / Input / Constraints / Expected_Output`.
- Resolve scan inputs from `Input` (binary path, config path, prefix, scan dir,
  json flag); default any unset value to the flag defaults above.
- Run `scripts/scan_nginx_rift.py` (prefer `--json` when a structured report is
  expected), capture findings and exit code.
- Skip verbose narration; produce the final report only, then emit the
  completion block below.

```yaml
_STEP_COMPLETE:
  Agent: nginx-rift-scanner
  Status: SUCCESS | PARTIAL | BLOCKED | FAILED
  Output:
    cve: CVE-2026-42945
    version_verdict: VULNERABLE | POTENTIALLY_VULNERABLE | FIXED | UNKNOWN
    config_findings: <count>
    exit_code: 0 | 1
    sources_checked: [binary, package_manager, docker_tag, config]
    human_review_required: <bool>   # true whenever config_findings > 0
  Next: <agent name> | DONE
  Reason: <terse cause for non-SUCCESS, or "scan complete, exit 0, no findings" for clean SUCCESS>
```
