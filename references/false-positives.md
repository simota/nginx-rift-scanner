# False-Positive Caveats and Remediation

## The config-pattern check is a conservative heuristic

For `rewrite`/`set` the `?` check is limited to value/replacement arguments, so
PCRE quantifiers in the regex-pattern argument no longer false-positive. The
check may still flag configurations that are not exploitable in practice, for
example:

- `?` appearing inside a PCRE character class (e.g., `[^?]`) within a
  replacement/value string.
- `?` quantifiers inside `if` conditions (scanned conservatively because the
  condition mixes regex and value operands).
- `?` used in a value that does not participate in URI construction.
- Directives where `$1` is not actually derived from a regex on the same
  request URI path.

## Human review is mandatory

Every finding must be reviewed by a human before concluding that a configuration
is exploitable. The scanner deliberately errs on the side of caution — false
positives are preferable to missed detections for a CRITICAL-severity CVE. The
scanner does **not** auto-fix configurations.

## Remediation

**Upgrade** (preferred):
- OSS: upgrade to NGINX 1.31.0+ or apply the 1.30.1 stable patch.
- Plus: upgrade to R32P6+, R36P4+, or R37+.

**Workaround** (if upgrade is not immediately possible): replace unnamed
captures with **named captures** in every `rewrite`/`if`/`set` directive that
also contains `?`:

```nginx
# Before (vulnerable pattern)
rewrite ^/api/(\w+)$ /new-api?path=$1 last;

# After (safe: named capture)
rewrite ^/api/(?<action>\w+)$ /new-api?path=$action last;
```
