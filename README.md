# nginx-rift-scanner

Dependency-free Python 3 scanner for **CVE-2026-42945 ("NGINX Rift")** —
a CVSS v4.0 **9.2 CRITICAL** heap-based buffer overflow (CWE-122) in
`ngx_http_rewrite_module`.

## What it detects

Two independent checks are run on every invocation:

| Check | How |
|-------|-----|
| **Version** | `nginx -V`, `dpkg`/`rpm`/`apk`, Dockerfile/compose image tags |
| **Config pattern** | Brace-aware parse of `nginx.conf` + all `include`d files |

### Affected versions

| Edition    | Vulnerable                      | Fixed                        |
|------------|---------------------------------|------------------------------|
| NGINX OSS  | 0.6.27 – 1.30.1                 | 1.31.0+ (or 1.30.1 patched)  |
| NGINX Plus | R32 before R32P6                | R32P6+                       |
| NGINX Plus | R36 before R36P4                | R36P4+                       |
| NGINX Plus | R37+                            | Unaffected                   |

> **Note on 1.30.1**: the patched 1.30.1 stable build reports the same
> version string as the vulnerable one, so the scanner classifies any
> 1.30.1 as `POTENTIALLY_VULNERABLE` (exit 1, conservative). Verify the
> package changelog / advisory backport to confirm the patch is applied.

### Config trigger pattern

A scope block is flagged when **all three conditions hold**:

1. A `rewrite`, `if`, or `set` directive uses an **unnamed PCRE capture**
   reference (`$1`–`$9`, including the brace form `${1}`–`${9}`).
2. That directive's **value/replacement argument** contains a `?` character
   (for `rewrite`/`set` the regex-pattern argument is excluded — a `?` there
   is a PCRE quantifier; `if` conditions are scanned conservatively).
3. Another `rewrite`/`if`/`set` directive **follows in the same scope**
   (includes are spliced into the including scope, so pairs spanning an
   `include` boundary are detected).

## Quick start

```bash
# Clone and run
git clone https://github.com/simota/nginx-rift-scanner.git
cd nginx-rift-scanner

# Scan local nginx (binary in PATH, config at /etc/nginx/nginx.conf)
python3 scripts/scan_nginx_rift.py

# Custom paths
python3 scripts/scan_nginx_rift.py \
  --nginx-binary /usr/sbin/nginx \
  --config /etc/nginx/nginx.conf \
  --prefix /etc/nginx \
  --scan-dir /app

# JSON output (CI / SIEM)
python3 scripts/scan_nginx_rift.py --json

# Validate with included fixtures
python3 scripts/scan_nginx_rift.py --config fixtures/vulnerable.nginx.conf
python3 scripts/scan_nginx_rift.py --config fixtures/safe.nginx.conf
```

Exit codes: `0` = clean, `1` = VULNERABLE / POTENTIALLY_VULNERABLE version
or config pattern flagged.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--nginx-binary PATH` | `nginx` | Path to nginx executable |
| `--config PATH` | `/etc/nginx/nginx.conf` | Root nginx config to scan |
| `--prefix PATH` | directory of `--config` | nginx configuration prefix used to resolve relative `include` paths (nginx resolves them against the prefix, not the including file's directory) |
| `--scan-dir PATH` | `.` | Directory to search for Dockerfiles/compose files |
| `--json` | — | Emit JSON report to stdout |

## Remediation

**Upgrade** (preferred):
- OSS → NGINX ≥ 1.31.0 (or apply the 1.30.1 stable patch)
- Plus → R32P6+, R36P4+, or R37+

**Workaround** — replace unnamed captures with named captures in every
`rewrite`/`if`/`set` directive that also contains `?`:

```nginx
# Vulnerable
rewrite ^/api/(\w+)$ /new-api?path=$1 last;

# Safe
rewrite ^/api/(?<action>\w+)$ /new-api?path=$action last;
```

## False-positive note

Config findings are **heuristic**. A flagged directive does not guarantee
exploitability — the `?` may not be in the URI-construction path, or the
capture reference may not interact with the allocation that overflows. Every
finding should be reviewed by a human before remediation is prioritised.

## Requirements

- Python 3.6+ (stdlib only — no pip installs)
- `nginx` binary (optional — version check skipped if absent)

## Fixtures

| File | Expected result |
|------|----------------|
| `fixtures/vulnerable.nginx.conf` | 3 config findings, exit 1 |
| `fixtures/safe.nginx.conf` | 0 config findings, exit 0 |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-42945>
- F5 Advisory K000161019: <https://my.f5.com/manage/s/article/K000161019>
