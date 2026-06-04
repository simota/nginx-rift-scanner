#!/usr/bin/env python3
"""
scan_nginx_rift.py — CVE-2026-42945 ("NGINX Rift") scanner
Heap-based buffer overflow in ngx_http_rewrite_module.

Usage:
    python3 scan_nginx_rift.py [OPTIONS]

    --nginx-binary PATH   Path to nginx binary (default: nginx, searched in PATH)
    --config PATH         Path to nginx.conf (default: /etc/nginx/nginx.conf)
    --prefix PATH         nginx config prefix for resolving relative includes
                          (default: directory of --config)
    --scan-dir PATH       Directory to scan for Dockerfiles/compose files
                          (default: current directory)
    --json                Output findings as JSON

Detection spec sourced from:
  - NVD:  https://nvd.nist.gov/vuln/detail/CVE-2026-42945
  - F5:   https://my.f5.com/manage/s/article/K000161019
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Version range constants (verified from NVD/F5/Ubuntu advisories)
# ---------------------------------------------------------------------------
# OSS: vulnerable 0.6.27 – 1.30.1, fixed in 1.31.0+ (and 1.30.1 stable patch)
# The 1.30.1 that is "fixed" is the *stable* branch patch; the vuln was
# introduced in 0.6.27.  Version 1.31.0 is the mainline fixed release.
OSS_VULN_MIN = (0, 6, 27)
OSS_VULN_MAX = (1, 30, 1)   # inclusive upper bound per advisory
OSS_FIXED    = (1, 31, 0)   # first fully unambiguous fix in mainline

# NGINX Plus: R32 < R32P6 and R36 < R36P4 are vulnerable; R37+ unaffected
PLUS_VULN_RANGES = [
    # (release, first_fix_patch)   — patches below first_fix_patch are vuln
    (32, 6),
    (36, 4),
]
PLUS_FIXED_RELEASE = 37  # R37 and above are unaffected

# ---------------------------------------------------------------------------
# Rewrite-module directive keywords
# ---------------------------------------------------------------------------
REWRITE_DIRECTIVES = {"rewrite", "if", "set"}

# Unnamed capture reference: $1 … $9, including the brace form ${1} … ${9}
# that nginx accepts to delimit the reference from following text.
RE_UNNAMED_CAP = re.compile(r'\$(?:[1-9]|\{[1-9]\})')
# Question mark in a string value (triggers URI-escaping logic)
RE_HAS_QMARK   = re.compile(r'\?')
# Named capture group in PCRE: (?<name>...) or (?P<name>...)
RE_NAMED_CAP   = re.compile(r'\(\?(?:<[^>]+>|P<[^>]+>)')


# ===========================================================================
# VERSION DETECTION
# ===========================================================================

def _parse_oss_version(ver_str: str) -> Optional[tuple]:
    """Parse 'nginx/1.25.3' or '1.25.3' -> (1, 25, 3) or None."""
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', ver_str)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def _parse_plus_version(ver_str: str) -> Optional[dict]:
    """
    Parse NGINX Plus version strings like:
      nginx-plus-r36, nginx-plus-r36p2, nginx/1.27.x (nginx-plus-r36)
    An explicit 'plus' marker is required: bare 'r<digit>' substrings also
    appear in OSS strings (Alpine '-rN' package revisions, gcc banners in
    `nginx -V` output) and must not shadow OSS classification.
    Returns dict with keys 'release' (int) and 'patch' (int, 0 if unspecified).
    """
    if 'plus' not in ver_str.lower():
        return None
    # Prefer the r/p pair anchored to the 'plus' marker; fall back to a
    # bare r/p pair anywhere in the (already plus-marked) string.
    m = re.search(r'plus[-_ ]?[Rr](\d+)(?:[-_.]?[Pp](\d+))?', ver_str,
                  re.IGNORECASE)
    if not m:
        m = re.search(r'[Rr](\d+)(?:[Pp](\d+))?', ver_str)
    if m:
        return {"release": int(m.group(1)), "patch": int(m.group(2) or 0)}
    return None


def _classify_oss(ver: tuple) -> str:
    """Returns 'VULNERABLE', 'POTENTIALLY_VULNERABLE', 'FIXED', or 'UNKNOWN'."""
    if ver == OSS_VULN_MAX:
        # 1.30.1 exists both as the last vulnerable build and as the patched
        # stable release; the version string alone cannot distinguish them.
        return "POTENTIALLY_VULNERABLE"
    if OSS_VULN_MIN <= ver <= OSS_VULN_MAX:
        return "VULNERABLE"
    if ver >= OSS_FIXED:
        return "FIXED"
    # Versions below OSS_VULN_MIN pre-date the module; classify conservatively.
    return "UNKNOWN"


OSS_AMBIGUOUS_NOTE = ("cannot distinguish patched 1.30.1 by version string — "
                      "verify package changelog/advisory backport")


def _oss_status_and_detail(ver: tuple) -> tuple:
    """Classify an OSS version tuple and build its human-readable detail."""
    status = _classify_oss(ver)
    detail = ".".join(map(str, ver))
    if status == "POTENTIALLY_VULNERABLE":
        detail += f" ({OSS_AMBIGUOUS_NOTE})"
    return status, detail


def _classify_plus(plus: dict) -> str:
    release = plus["release"]
    patch   = plus["patch"]
    if release >= PLUS_FIXED_RELEASE:
        return "FIXED"
    for (vuln_rel, first_fix_patch) in PLUS_VULN_RANGES:
        if release == vuln_rel and patch < first_fix_patch:
            return "VULNERABLE"
        if release == vuln_rel and patch >= first_fix_patch:
            return "FIXED"
    # Other releases not explicitly listed — conservatively UNKNOWN
    return "UNKNOWN"


def check_version_binary(nginx_binary: str) -> dict:
    """Run nginx -V and extract version info."""
    result = {"source": "binary", "raw": None, "status": "UNKNOWN", "detail": ""}
    try:
        proc = subprocess.run(
            [nginx_binary, "-V"],
            capture_output=True, text=True, timeout=10
        )
        # nginx -V writes to stderr
        output = proc.stderr + proc.stdout
        result["raw"] = output.strip().split("\n")[0]

        plus_info = _parse_plus_version(output)
        if plus_info:
            result["edition"]  = "NGINX Plus"
            result["plus"]     = plus_info
            result["status"]   = _classify_plus(plus_info)
            result["detail"]   = (
                f"R{plus_info['release']}P{plus_info['patch']}"
                if plus_info["patch"] else f"R{plus_info['release']}"
            )
        else:
            oss_ver = _parse_oss_version(output)
            if oss_ver:
                result["edition"] = "NGINX OSS"
                result["version"] = oss_ver
                result["status"], result["detail"] = _oss_status_and_detail(oss_ver)
            else:
                result["status"] = "UNKNOWN"
                result["detail"] = "Could not parse version from binary output"
    except FileNotFoundError:
        result["status"] = "UNKNOWN"
        result["detail"] = f"Binary not found: {nginx_binary}"
    except subprocess.TimeoutExpired:
        result["status"] = "UNKNOWN"
        result["detail"] = "nginx -V timed out"
    return result


def check_version_pkg_managers() -> list:
    """Probe dpkg, rpm, apk for installed nginx packages."""
    findings = []

    # dpkg (Debian/Ubuntu)
    try:
        proc = subprocess.run(
            ["dpkg", "-l", "nginx*"],
            capture_output=True, text=True, timeout=10
        )
        for line in proc.stdout.splitlines():
            if line.startswith("ii"):
                parts = line.split()
                pkg, ver_raw = parts[1], parts[2]
                # Include the package name so 'nginx-plus' packages carry
                # the required Plus marker into version parsing.
                plus = _parse_plus_version(f"{pkg} {ver_raw}")
                if plus:
                    findings.append({
                        "source": "dpkg", "package": pkg, "raw": ver_raw,
                        "edition": "NGINX Plus", "plus": plus,
                        "status": _classify_plus(plus),
                        "detail": f"R{plus['release']}P{plus['patch']}"
                    })
                else:
                    oss = _parse_oss_version(ver_raw)
                    if oss:
                        status, detail = _oss_status_and_detail(oss)
                        findings.append({
                            "source": "dpkg", "package": pkg, "raw": ver_raw,
                            "edition": "NGINX OSS", "version": oss,
                            "status": status,
                            "detail": detail
                        })
    except FileNotFoundError:
        pass

    # rpm (RHEL/CentOS/Fedora)
    try:
        proc = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n", "nginx*"],
            capture_output=True, text=True, timeout=10
        )
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                pkg, ver_raw = parts[0], parts[1]
                # Include the package name so 'nginx-plus' packages carry
                # the required Plus marker into version parsing.
                plus = _parse_plus_version(f"{pkg} {ver_raw}")
                if plus:
                    findings.append({
                        "source": "rpm", "package": pkg, "raw": ver_raw,
                        "edition": "NGINX Plus",
                        "status": _classify_plus(plus), "plus": plus,
                        "detail": f"R{plus['release']}P{plus['patch']}"
                    })
                else:
                    oss = _parse_oss_version(ver_raw)
                    if oss:
                        status, detail = _oss_status_and_detail(oss)
                        findings.append({
                            "source": "rpm", "package": pkg, "raw": ver_raw,
                            "edition": "NGINX OSS", "version": oss,
                            "status": status,
                            "detail": detail
                        })
    except FileNotFoundError:
        pass

    # apk (Alpine)
    try:
        proc = subprocess.run(
            ["apk", "info", "-v", "nginx"],
            capture_output=True, text=True, timeout=10
        )
        for line in proc.stdout.splitlines():
            if line.startswith("nginx"):
                ver_raw = line.strip()
                oss = _parse_oss_version(ver_raw)
                if oss:
                    status, detail = _oss_status_and_detail(oss)
                    findings.append({
                        "source": "apk", "package": "nginx", "raw": ver_raw,
                        "edition": "NGINX OSS", "version": oss,
                        "status": status,
                        "detail": detail
                    })
    except FileNotFoundError:
        pass

    return findings


def check_version_dockerfiles(start_dir: str) -> list:
    """
    Walk the directory tree looking for Dockerfile* and docker-compose*.
    Extract nginx image tags and classify version.
    """
    findings = []
    start = Path(start_dir)
    patterns = ["Dockerfile", "Dockerfile.*", "docker-compose.yml",
                 "docker-compose.yaml", "compose.yml", "compose.yaml"]

    candidate_files = []
    for pat in patterns:
        candidate_files.extend(start.rglob(pat))

    # Match official nginx image references including registry-qualified
    # paths (docker.io/library/nginx:…), quoted compose values, and FROM
    # lines with flags (--platform=…). The final path component must be
    # exactly 'nginx'; the tag follows ':' (or '@' for digests).
    re_image = re.compile(
        r'(?:FROM(?:\s+--\S+)*|image:)\s+["\']?'
        r'(?:[\w.\-]+(?::\d+)?/)?(?:[\w.\-]+/)*nginx[:@]([^\s"\']+)',
        re.IGNORECASE)

    for fpath in candidate_files:
        try:
            text = fpath.read_text(errors="replace")
        except OSError:
            continue
        for m in re_image.finditer(text):
            tag = m.group(1).strip()
            lineno = text[:m.start()].count("\n") + 1
            plus = _parse_plus_version(tag)
            if plus:
                findings.append({
                    "source": "dockerfile", "file": str(fpath),
                    "line": lineno, "image_tag": tag,
                    "edition": "NGINX Plus", "plus": plus,
                    "status": _classify_plus(plus),
                    "detail": f"R{plus['release']}P{plus['patch']}"
                })
            else:
                oss = _parse_oss_version(tag)
                if oss:
                    status, detail = _oss_status_and_detail(oss)
                    findings.append({
                        "source": "dockerfile", "file": str(fpath),
                        "line": lineno, "image_tag": tag,
                        "edition": "NGINX OSS", "version": oss,
                        "status": status,
                        "detail": detail
                    })
                else:
                    # "latest", "stable", "alpine" — cannot classify
                    findings.append({
                        "source": "dockerfile", "file": str(fpath),
                        "line": lineno, "image_tag": tag,
                        "edition": "NGINX OSS", "status": "UNKNOWN",
                        "detail": f"Tag '{tag}' — pin to a specific version"
                    })
    return findings


# ===========================================================================
# CONFIG PATTERN SCAN
# ===========================================================================

def _tokenize_nginx_config(text: str) -> list:
    """
    Minimal nginx config tokenizer.
    Returns list of dicts: {type, value, lineno}
    Types: DIRECTIVE, LBRACE, RBRACE, SEMICOLON, STRING
    Strips comments (#...) and handles quoted strings.
    """
    tokens = []
    i = 0
    lineno = 1
    n = len(text)

    while i < n:
        c = text[i]

        if c == '\n':
            lineno += 1
            i += 1
            continue

        if c in ' \t\r':
            i += 1
            continue

        # Comment
        if c == '#':
            while i < n and text[i] != '\n':
                i += 1
            continue

        if c == '{':
            tokens.append({'type': 'LBRACE', 'value': '{', 'lineno': lineno})
            i += 1
            continue

        if c == '}':
            tokens.append({'type': 'RBRACE', 'value': '}', 'lineno': lineno})
            i += 1
            continue

        if c == ';':
            tokens.append({'type': 'SEMICOLON', 'value': ';', 'lineno': lineno})
            i += 1
            continue

        # Quoted string
        if c in ('"', "'"):
            quote = c
            i += 1
            buf = []
            start_line = lineno
            while i < n and text[i] != quote:
                if text[i] == '\n':
                    lineno += 1
                if text[i] == '\\' and i + 1 < n:
                    i += 1  # skip escape
                buf.append(text[i])
                i += 1
            i += 1  # closing quote
            tokens.append({'type': 'STRING', 'value': ''.join(buf), 'lineno': start_line})
            continue

        # Bare word / directive name / value
        buf = []
        start_line = lineno
        while i < n and text[i] not in ' \t\r\n{};"\'#':
            buf.append(text[i])
            i += 1
        if buf:
            tokens.append({'type': 'WORD', 'value': ''.join(buf), 'lineno': start_line})

    return tokens


def _collect_include_paths(include_pattern: str, prefix: Path) -> list:
    """
    Expand an include directive glob the way nginx does: relative masks
    resolve against the configuration prefix directory, not the directory
    of the including file.
    """
    import glob as _glob
    if not os.path.isabs(include_pattern):
        include_pattern = str(prefix / include_pattern)
    return _glob.glob(include_pattern)


def parse_config_tree(config_path: Path, visited: set = None,
                      prefix: Path = None) -> list:
    """
    Recursively parse nginx.conf and all included files.
    Returns a flat list of {file, lineno, directive, args[]} records.
    Relative include masks resolve against `prefix` (default: the root
    config file's directory), matching nginx's prefix-based resolution.
    """
    if visited is None:
        visited = set()
    if prefix is None:
        prefix = config_path.parent
    real = str(config_path.resolve()) if config_path.exists() else str(config_path)
    if real in visited:
        return []
    visited.add(real)

    try:
        text = config_path.read_text(errors="replace")
    except OSError:
        return []

    tokens = _tokenize_nginx_config(text)
    directives = []
    i = 0
    n = len(tokens)

    while i < n:
        tok = tokens[i]
        if tok['type'] == 'WORD':
            # Collect directive name + args until SEMICOLON or LBRACE
            directive_name = tok['value']
            args = []
            lineno = tok['lineno']
            i += 1
            while i < n and tokens[i]['type'] not in ('SEMICOLON', 'LBRACE', 'RBRACE'):
                args.append(tokens[i]['value'])
                i += 1
            directives.append({
                'file': str(config_path),
                'lineno': lineno,
                'directive': directive_name,
                'args': args
            })
            # Handle includes
            if directive_name == 'include' and args:
                included = _collect_include_paths(args[0], prefix)
                for inc_path in sorted(included):
                    directives.extend(
                        parse_config_tree(Path(inc_path), visited, prefix))
        elif tok['type'] in ('LBRACE', 'RBRACE', 'SEMICOLON'):
            i += 1
        else:
            i += 1

    return directives


def _directive_uses_unnamed_capture(directive: str, args: list) -> bool:
    """
    Returns True if any arg contains $1..$9 (unnamed PCRE capture reference).
    For 'if' directives the condition itself may carry them; for 'rewrite'
    the replacement (arg[1]) is the primary risk surface; for 'set' it's arg[1].
    We check all args conservatively.
    """
    for arg in args:
        if RE_UNNAMED_CAP.search(arg):
            return True
    return False


def _directive_has_qmark(directive: str, args: list) -> bool:
    """
    Returns True if a '?' appears in an argument that can reach URI
    construction.  For 'rewrite' and 'set' the first argument (regex
    pattern / variable name) is excluded — a '?' there is a PCRE
    quantifier (or never present), not a query-string delimiter.
    'if' keeps the conservative all-args scan because its condition
    mixes regex and value operands.
    """
    if directive.lower() in ('rewrite', 'set'):
        check_args = args[1:]
    else:
        check_args = args
    for arg in check_args:
        if RE_HAS_QMARK.search(arg):
            return True
    return False


def _suggest_named_capture_rewrite(args: list) -> str:
    """
    Produce a best-effort suggestion replacing $1..$9 with named capture
    placeholders.  This is a heuristic hint, not a guaranteed correct fix.
    """
    suggestion_args = []
    counter = [0]

    def _replace_unnamed(s):
        def _sub(m):
            counter[0] += 1
            idx = m.group(0).strip('${}')  # '1'..'9' from both $N and ${N}
            return f"${{group{idx}}}"
        return RE_UNNAMED_CAP.sub(_sub, s)

    for arg in args:
        suggestion_args.append(_replace_unnamed(arg))

    hint = " ".join(suggestion_args)
    note = ("  # TODO: replace (?...) capture groups with (?<groupN>...) "
            "named captures and update references above")
    return hint + note


def scan_config_patterns(config_path: Path, prefix: Path = None) -> list:
    """
    Two-pass heuristic scan for CVE-2026-42945 trigger pattern:
      Within a single scope block, find a rewrite/if/set directive that:
        (a) uses unnamed PCRE capture reference ($1..$9 or ${1}..${9}), AND
        (b) contains '?' in a value/replacement argument,
      FOLLOWED BY another rewrite/if/set directive in the same scope.

    Included files are spliced into the including file's current scope
    (matching nginx's textual include semantics), so a trigger pair that
    spans an include boundary is still detected.  Relative include masks
    resolve against `prefix` (default: the root config file's directory).

    NOTE: This is a CONSERVATIVE HEURISTIC. Findings require human review
    to confirm exploitability. For 'rewrite'/'set' the '?' check is limited
    to value/replacement arguments (a '?' in the regex-pattern argument is
    a PCRE quantifier, not a query-string delimiter). For 'if' all args
    are scanned conservatively, so quantifiers there may still produce
    false positives, as may '?' inside a regex character class.
    """
    findings = []

    if not config_path.exists():
        return findings
    if prefix is None:
        prefix = config_path.parent

    # Brace-aware scope tracking shared across the whole include tree:
    # scope ids must stay continuous across include boundaries.
    visited = set()
    scope_stack = [0]
    scope_counter = [0]
    directive_stream = []

    def _collect_file(fpath: Path):
        """Splice this file's directives into the CURRENT scope."""
        real = str(fpath.resolve()) if fpath.exists() else str(fpath)
        if real in visited:
            return
        visited.add(real)

        try:
            text = fpath.read_text(errors="replace")
        except OSError:
            return

        tokens = _tokenize_nginx_config(text)
        i = 0
        n = len(tokens)

        while i < n:
            tok = tokens[i]
            if tok['type'] == 'LBRACE':
                scope_counter[0] += 1
                scope_stack.append(scope_counter[0])
                i += 1
                continue
            if tok['type'] == 'RBRACE':
                if len(scope_stack) > 1:
                    scope_stack.pop()
                i += 1
                continue
            if tok['type'] == 'SEMICOLON':
                i += 1
                continue
            if tok['type'] in ('WORD', 'STRING'):
                directive_name = tok['value']
                args = []
                lineno = tok['lineno']
                i += 1
                while i < n and tokens[i]['type'] not in ('SEMICOLON', 'LBRACE', 'RBRACE'):
                    args.append(tokens[i]['value'])
                    i += 1
                # Don't advance past LBRACE/RBRACE here — let next iteration handle
                directive_stream.append({
                    'scope': scope_stack[-1],
                    'directive': directive_name,
                    'args': args,
                    'lineno': lineno,
                    'file': str(fpath)
                })

                # Handle include: recurse with the shared scope state so the
                # included directives land in the including scope.
                if directive_name == 'include' and args:
                    included = _collect_include_paths(args[0], prefix)
                    for inc_path in sorted(included):
                        _collect_file(Path(inc_path))
            else:
                i += 1

    _collect_file(config_path)

    # Group directives by scope
    from collections import defaultdict
    by_scope = defaultdict(list)
    for d in directive_stream:
        by_scope[d['scope']].append(d)

    # Within each scope, look for the trigger pattern
    for scope_id, scope_directives in by_scope.items():
        rewrite_directives = [
            d for d in scope_directives
            if d['directive'].lower() in REWRITE_DIRECTIVES
        ]

        for idx, d in enumerate(rewrite_directives):
            uses_unnamed = _directive_uses_unnamed_capture(d['directive'], d['args'])
            has_qmark    = _directive_has_qmark(d['directive'], d['args'])

            if uses_unnamed and has_qmark:
                # Check if a subsequent rewrite/if/set directive exists in same scope
                if idx + 1 < len(rewrite_directives):
                    next_d = rewrite_directives[idx + 1]
                    findings.append({
                        'file': d['file'],
                        'lineno': d['lineno'],
                        'directive': d['directive'],
                        'args': d['args'],
                        'next_directive': next_d['directive'],
                        'next_lineno': next_d['lineno'],
                        'next_args': next_d['args'],
                        'scope': scope_id,
                        'severity': 'HIGH',
                        'cve': 'CVE-2026-42945',
                        'confidence': 'HEURISTIC — needs human confirmation',
                        'remediation_hint': _suggest_named_capture_rewrite(d['args'])
                    })

    return findings


# ===========================================================================
# REPORTING
# ===========================================================================

SEPARATOR = "-" * 72


def _status_label(status: str) -> str:
    labels = {
        "VULNERABLE":             "[VULNERABLE]",
        "POTENTIALLY_VULNERABLE": "[POTENTIAL] ",
        "FIXED":                  "[FIXED]     ",
        "UNKNOWN":                "[UNKNOWN]   ",
    }
    return labels.get(status, f"[{status}]")


def print_text_report(version_results: list, config_findings: list, config_path: str):
    print()
    print("=" * 72)
    print("  CVE-2026-42945 (NGINX Rift) — Scanner Report")
    print("  CVSS v4.0: 9.2 CRITICAL / v3.1: 8.1 HIGH")
    print("  CWE-122: Heap-based Buffer Overflow (ngx_http_rewrite_module)")
    print("=" * 72)
    print()

    # --- VERSION SECTION ---
    print("VERSION CHECK")
    print(SEPARATOR)
    if not version_results:
        print("  No version information detected.")
    else:
        for vr in version_results:
            src    = vr.get("source", "?")
            status = vr.get("status", "UNKNOWN")
            detail = vr.get("detail", "")
            edition = vr.get("edition", "NGINX")
            label  = _status_label(status)

            if src == "binary":
                print(f"  {label}  binary ({edition} {detail})")
            elif src in ("dpkg", "rpm", "apk"):
                pkg = vr.get("package", "nginx")
                print(f"  {label}  {src}: {pkg} {detail}")
            elif src == "dockerfile":
                fpath = vr.get("file", "")
                tag   = vr.get("image_tag", "")
                lineno = vr.get("line", "?")
                print(f"  {label}  {fpath}:{lineno}  image tag={tag}  ({edition} {detail})")

    print()

    # --- CONFIG SECTION ---
    print(f"CONFIG PATTERN SCAN  (config: {config_path})")
    print(SEPARATOR)
    if not config_findings:
        print("  No suspicious rewrite patterns detected.")
    else:
        print(f"  {len(config_findings)} potential trigger pattern(s) found.")
        print("  NOTE: These are HEURISTIC findings — human review required.")
        print("        A finding here does NOT confirm exploitability.")
        print()
        for i, f in enumerate(config_findings, 1):
            args_str  = " ".join(f['args'])
            nargs_str = " ".join(f['next_args'])
            print(f"  [{i}] {f['file']}:{f['lineno']}")
            print(f"      Directive : {f['directive']} {args_str}")
            print(f"      Reason    : unnamed capture ($1-$9) + '?' in args")
            print(f"      Next dir. : {f['next_directive']} {nargs_str}  (line {f['next_lineno']})")
            print(f"      Severity  : {f['severity']} ({f['confidence']})")
            print(f"      Remediate : Convert unnamed captures to named captures.")
            print(f"                  Hint: {f['remediation_hint']}")
            print()

    # --- SUMMARY ---
    print(SEPARATOR)
    vuln_ver  = sum(1 for v in version_results if v.get("status") == "VULNERABLE")
    maybe_ver = sum(1 for v in version_results
                    if v.get("status") == "POTENTIALLY_VULNERABLE")
    summary = f"  Version findings  : {len(version_results)} checked, {vuln_ver} VULNERABLE"
    if maybe_ver:
        summary += f", {maybe_ver} POTENTIALLY_VULNERABLE"
    print(summary)
    print(f"  Config findings   : {len(config_findings)} pattern(s) flagged for review")
    print()
    print("  References:")
    print("    NVD : https://nvd.nist.gov/vuln/detail/CVE-2026-42945")
    print("    F5  : https://my.f5.com/manage/s/article/K000161019")
    print()
    print("  Mitigation:")
    print("    1. Upgrade NGINX OSS to >= 1.31.0 (or 1.30.1 stable patch;")
    print("       note: a 1.30.1 version string is reported POTENTIALLY_VULNERABLE")
    print("       because the patched build cannot be distinguished by version alone)")
    print("    2. NGINX Plus: upgrade to R32P6+, R36P4+, or R37+")
    print("    3. Workaround: replace unnamed PCRE captures with named captures")
    print("       in all rewrite/if/set directives that contain '?'.")
    print("=" * 72)
    print()


def print_json_report(version_results: list, config_findings: list, config_path: str):
    report = {
        "cve": "CVE-2026-42945",
        "name": "NGINX Rift",
        "cvss_v4": "9.2 CRITICAL",
        "cvss_v31": "8.1 HIGH",
        "version_checks": version_results,
        "config_scan": {
            "config_path": config_path,
            "findings": config_findings,
            "note": (
                "Config findings are HEURISTIC only. "
                "Human review required to confirm exploitability."
            )
        },
        "references": {
            "nvd": "https://nvd.nist.gov/vuln/detail/CVE-2026-42945",
            "f5":  "https://my.f5.com/manage/s/article/K000161019"
        }
    }
    # Convert tuple version numbers to lists for JSON serialisation
    def _serialise(obj):
        if isinstance(obj, tuple):
            return list(obj)
        raise TypeError(f"Not serialisable: {type(obj)}")

    print(json.dumps(report, indent=2, default=_serialise))


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Scan for CVE-2026-42945 (NGINX Rift) — heap buffer overflow "
                    "in ngx_http_rewrite_module."
    )
    parser.add_argument("--nginx-binary", default="nginx",
                        help="Path to nginx binary (default: 'nginx' in PATH)")
    parser.add_argument("--config", default="/etc/nginx/nginx.conf",
                        help="Path to nginx.conf (default: /etc/nginx/nginx.conf)")
    parser.add_argument("--prefix", default=None,
                        help="nginx configuration prefix used to resolve "
                             "relative include paths, matching nginx's "
                             "prefix-based resolution "
                             "(default: directory of --config)")
    parser.add_argument("--scan-dir", default=".",
                        help="Directory to scan for Dockerfiles/compose files "
                             "(default: current directory)")
    parser.add_argument("--json", action="store_true",
                        help="Output findings as JSON")
    args = parser.parse_args()

    version_results = []

    # 1. Binary check
    bin_result = check_version_binary(args.nginx_binary)
    version_results.append(bin_result)

    # 2. Package manager checks
    version_results.extend(check_version_pkg_managers())

    # 3. Dockerfile/compose checks
    version_results.extend(check_version_dockerfiles(args.scan_dir))

    # 4. Config pattern scan
    config_path = Path(args.config)
    prefix = Path(args.prefix) if args.prefix else config_path.parent
    config_findings = scan_config_patterns(config_path, prefix)

    if args.json:
        print_json_report(version_results, config_findings, str(config_path))
    else:
        print_text_report(version_results, config_findings, str(config_path))

    # Exit 1 if any VULNERABLE / POTENTIALLY_VULNERABLE or config findings
    # found (1.30.1 is treated conservatively — see _classify_oss).
    has_vuln_ver = any(
        v.get("status") in ("VULNERABLE", "POTENTIALLY_VULNERABLE")
        for v in version_results
    )
    if has_vuln_ver or config_findings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
