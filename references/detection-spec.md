# Detection Specification — CVE-2026-42945 (NGINX Rift)

CVE-2026-42945 ("NGINX Rift") is a CVSS v4.0 9.2 CRITICAL heap-based buffer
overflow (CWE-122) in `ngx_http_rewrite_module`.

## Root cause

The length-calculation pass runs with `is_args=0` while the copy pass runs with
`is_args=1`. URI-escaping logic activated by the query-string delimiter then
overflows the heap buffer allocated for the rewrite result, because the buffer
was sized in the earlier pass without accounting for the escaping that the copy
pass performs.

## Trigger conditions

The bug is triggered when ALL THREE conditions hold in order, in the same scope
block:

1. A `rewrite`, `if`, or `set` directive references an **unnamed PCRE capture**
   (`$1`–`$9`, including the brace form `${1}`–`${9}`).
2. The replacement / value argument contains a **`?` character** (the
   query-string delimiter that activates URI-escaping logic). For `rewrite` and
   `set` the regex-pattern argument is **excluded** — a `?` there is a PCRE
   quantifier, not a query-string delimiter. `if` conditions are scanned
   **conservatively** because the condition mixes regex and value operands and
   the two cannot be reliably separated.
3. **Another** `rewrite`/`if`/`set` directive **follows in the same scope**.

## Scope and include semantics

- The config-pattern scan uses a **brace-aware tokenizer** that parses
  `nginx.conf` and all `include`d files.
- Included files are **spliced into the including scope** (nginx textual-include
  semantics), so a triggering directive pair that spans an `include` boundary is
  still detected.
- Relative `include` masks resolve against the **configuration prefix**
  (`--prefix`, default: the directory of `--config`) — nginx resolves them
  against the prefix, not against the including file's own directory.

## Version classification

Each version source (`nginx -V`, `dpkg`/`rpm`/`apk`, Dockerfile/compose image
tags) is classified as `VULNERABLE`, `POTENTIALLY_VULNERABLE` (1.30.1 only),
`FIXED`, or `UNKNOWN`.

### Affected versions

| Edition    | Vulnerable          | Fixed                       |
|------------|---------------------|-----------------------------|
| NGINX OSS  | 0.6.27 – 1.30.1     | 1.31.0+ (or 1.30.1 patched) |
| NGINX Plus | R32 before R32P6    | R32P6+                      |
| NGINX Plus | R36 before R36P4    | R36P4+                      |
| NGINX Plus | R37+                | Unaffected                  |

> **1.30.1 note**: the patched 1.30.1 build cannot be distinguished from the
> vulnerable one by version string, so the scanner reports any 1.30.1 as
> `POTENTIALLY_VULNERABLE` (conservative, exit 1). Verify the package changelog
> / advisory backport to confirm the patch is applied.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-42945>
- F5 K000161019: <https://my.f5.com/manage/s/article/K000161019>
