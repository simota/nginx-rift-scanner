#!/usr/bin/env python3
"""
Regression tests for scan_nginx_rift.py — one test class per Judge finding
(RIFT-001 … RIFT-007) plus fixture end-to-end checks.

Run:  python3 -m unittest discover -s tests -v
Stdlib only (unittest) — no pip installs, matching the project requirement.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import scan_nginx_rift as s  # noqa: E402


class TestPlusVersionParsing(unittest.TestCase):
    """RIFT-001: bare 'r<digit>' substrings must not shadow OSS detection."""

    def test_alpine_gcc_banner_is_not_plus(self):
        out = ("nginx version: nginx/1.28.0\n"
               "built by gcc 12.2.1 20220924 (Alpine 12.2.1_git20220924-r4)")
        self.assertIsNone(s._parse_plus_version(out))
        # ...and the OSS path classifies it as VULNERABLE.
        ver = s._parse_oss_version(out)
        self.assertEqual(ver, (1, 28, 0))
        self.assertEqual(s._classify_oss(ver), "VULNERABLE")

    def test_alpine_pkg_revision_is_not_plus(self):
        self.assertIsNone(s._parse_plus_version("1.28.0-r3"))

    def test_plus_string_still_parses(self):
        self.assertEqual(s._parse_plus_version("nginx-plus-r36p2"),
                         {"release": 36, "patch": 2})
        self.assertEqual(s._parse_plus_version("nginx-plus-r36"),
                         {"release": 36, "patch": 0})
        self.assertEqual(
            s._parse_plus_version("nginx/1.27.4 (nginx-plus-r32p6)"),
            {"release": 32, "patch": 6})

    def test_pkg_name_provides_plus_marker(self):
        # dpkg/rpm call sites pass "pkg ver" so nginx-plus packages keep
        # the marker even when the version field alone lacks it.
        self.assertEqual(s._parse_plus_version("nginx-plus R36P4"),
                         {"release": 36, "patch": 4})


class TestIncludeScopeSplicing(unittest.TestCase):
    """RIFT-002: trigger pairs spanning an include boundary are detected."""

    def test_pair_across_include_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "child.conf").write_text("set $a 1;\n")
            parent = tmp / "nginx.conf"
            parent.write_text(
                "http { server { location / {\n"
                "    rewrite ^/(.*)$ /x?p=$1 last;\n"
                "    include child.conf;\n"
                "} } }\n")
            findings = s.scan_config_patterns(parent)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["directive"], "rewrite")
            self.assertEqual(findings[0]["next_directive"], "set")

    def test_include_cycle_is_guarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "a.conf").write_text("include b.conf;\n")
            (tmp / "b.conf").write_text("include a.conf;\n")
            # Must terminate without RecursionError and return no findings.
            self.assertEqual(s.scan_config_patterns(tmp / "a.conf"), [])


class TestDockerImageRegex(unittest.TestCase):
    """RIFT-003: registry-qualified / quoted / flagged image refs match."""

    def _findings_for(self, dockerfile_text):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Dockerfile").write_text(dockerfile_text)
            return s.check_version_dockerfiles(tmp)

    def test_registry_qualified(self):
        f = self._findings_for("FROM docker.io/library/nginx:1.29.0\n")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["image_tag"], "1.29.0")
        self.assertEqual(f[0]["status"], "VULNERABLE")

    def test_quoted_compose_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "compose.yml").write_text(
                'services:\n  web:\n    image: "nginx:1.28.0"\n')
            f = s.check_version_dockerfiles(tmp)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["image_tag"], "1.28.0")

    def test_from_with_platform_flag(self):
        f = self._findings_for("FROM --platform=linux/amd64 nginx:1.28.0\n")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["image_tag"], "1.28.0")

    def test_plain_form_still_matches(self):
        f = self._findings_for("FROM nginx:1.27.4\n")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["image_tag"], "1.27.4")

    def test_non_nginx_final_component_does_not_match(self):
        self.assertEqual(
            self._findings_for("FROM nginxinc-fake/other:1\n"), [])
        self.assertEqual(
            self._findings_for("FROM mynginx:1.2.3\n"), [])
        # nginx/nginx-ingress is a different product, not the nginx server.
        self.assertEqual(
            self._findings_for("FROM nginx/nginx-ingress:1.0\n"), [])


class TestIncludePrefixResolution(unittest.TestCase):
    """RIFT-004: relative includes resolve against the nginx prefix."""

    VULN_SNIPPET = ("location / {\n"
                    "    rewrite ^/(.*)$ /x?p=$1 last;\n"
                    "    rewrite ^/old$ /new last;\n"
                    "}\n")

    def test_resolves_against_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "conf.d").mkdir()
            (tmp / "snippets").mkdir()
            (tmp / "snippets" / "x.conf").write_text(self.VULN_SNIPPET)
            app = tmp / "conf.d" / "app.conf"
            app.write_text("include snippets/x.conf;\n")
            findings = s.scan_config_patterns(app, prefix=tmp)
            self.assertEqual(len(findings), 1)
            self.assertTrue(findings[0]["file"].endswith("x.conf"))

    def test_default_prefix_is_config_dir(self):
        # Without an explicit prefix, masks resolve against the root
        # config's own directory (documented default).
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "snippets").mkdir()
            (tmp / "snippets" / "x.conf").write_text(self.VULN_SNIPPET)
            root = tmp / "nginx.conf"
            root.write_text("include snippets/x.conf;\n")
            self.assertEqual(len(s.scan_config_patterns(root)), 1)


class TestUnnamedCaptureForms(unittest.TestCase):
    """RIFT-005: brace form ${1}..${9} is detected."""

    def test_brace_form_detected(self):
        self.assertTrue(s.RE_UNNAMED_CAP.search("/x?p=${1}"))

    def test_plain_form_detected(self):
        self.assertTrue(s.RE_UNNAMED_CAP.search("/x?p=$1"))

    def test_named_reference_not_detected(self):
        self.assertFalse(s.RE_UNNAMED_CAP.search("/x?p=$action"))
        self.assertFalse(s.RE_UNNAMED_CAP.search("/x?p=${name}"))

    def test_suggestion_handles_brace_form(self):
        hint = s._suggest_named_capture_rewrite(["/x?p=${1}"])
        self.assertIn("${group1}", hint)
        hint = s._suggest_named_capture_rewrite(["/x?p=$2"])
        self.assertIn("${group2}", hint)


class TestQmarkArgumentScoping(unittest.TestCase):
    """RIFT-006: '?' quantifier in the regex-pattern arg does not fire."""

    def test_quantifier_in_rewrite_pattern_ignored(self):
        args = [r"^/a/(\w+)?$", "/target/$1", "last"]
        self.assertFalse(s._directive_has_qmark("rewrite", args))

    def test_qmark_in_replacement_fires(self):
        args = [r"^/api/(\w+)$", "/new-api?path=$1", "last"]
        self.assertTrue(s._directive_has_qmark("rewrite", args))

    def test_set_value_fires_but_not_varname(self):
        self.assertTrue(s._directive_has_qmark("set", ["$t", "/r?q=$1"]))
        self.assertFalse(s._directive_has_qmark("set", ["$t", "/plain"]))

    def test_if_remains_conservative(self):
        self.assertTrue(
            s._directive_has_qmark("if", ["($uri", "~", r"^/x/(\w+)?)"]))

    def test_full_scan_quantifier_no_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "nginx.conf"
            conf.write_text(
                "location / {\n"
                r"    rewrite ^/a/(\w+)?$ /target/$1 last;" "\n"
                "    rewrite ^/old$ /new last;\n"
                "}\n")
            self.assertEqual(s.scan_config_patterns(conf), [])


class TestOssClassification(unittest.TestCase):
    """RIFT-007: 1.30.1 is POTENTIALLY_VULNERABLE, not flatly VULNERABLE."""

    def test_1_30_1_potentially_vulnerable(self):
        self.assertEqual(s._classify_oss((1, 30, 1)), "POTENTIALLY_VULNERABLE")

    def test_detail_carries_ambiguity_note(self):
        status, detail = s._oss_status_and_detail((1, 30, 1))
        self.assertEqual(status, "POTENTIALLY_VULNERABLE")
        self.assertIn("1.30.1", detail)
        self.assertIn("verify package changelog", detail)

    def test_range_classification_unchanged(self):
        self.assertEqual(s._classify_oss((0, 6, 27)), "VULNERABLE")
        self.assertEqual(s._classify_oss((1, 28, 0)), "VULNERABLE")
        self.assertEqual(s._classify_oss((1, 30, 0)), "VULNERABLE")
        self.assertEqual(s._classify_oss((1, 31, 0)), "FIXED")
        self.assertEqual(s._classify_oss((0, 6, 26)), "UNKNOWN")


class TestFixturesEndToEnd(unittest.TestCase):
    """README contract: vulnerable -> 3 findings / exit 1, safe -> 0 / exit 0."""

    SCRIPT = REPO_ROOT / "scripts" / "scan_nginx_rift.py"

    def _run(self, config):
        with tempfile.TemporaryDirectory() as empty:
            return subprocess.run(
                [sys.executable, str(self.SCRIPT),
                 "--config", str(config),
                 "--nginx-binary", "/nonexistent-nginx-binary",
                 "--scan-dir", empty, "--json"],
                capture_output=True, text=True, timeout=60)

    def test_vulnerable_fixture(self):
        findings = s.scan_config_patterns(
            REPO_ROOT / "fixtures" / "vulnerable.nginx.conf")
        self.assertEqual(len(findings), 3)
        proc = self._run(REPO_ROOT / "fixtures" / "vulnerable.nginx.conf")
        self.assertEqual(proc.returncode, 1)

    def test_safe_fixture(self):
        findings = s.scan_config_patterns(
            REPO_ROOT / "fixtures" / "safe.nginx.conf")
        self.assertEqual(findings, [])
        proc = self._run(REPO_ROOT / "fixtures" / "safe.nginx.conf")
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
