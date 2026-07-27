"""Offline unit tests for the pure (no-network) logic."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from websectools import clickjack, csp, disclosure, headers  # noqa: E402


# ---- CSP evaluator ----
def test_csp_flags_unsafe_inline():
    findings = csp.evaluate("default-src 'self'; script-src 'self' 'unsafe-inline'")
    assert any(sev == "high" and "unsafe-inline" in msg for sev, msg in findings)


def test_csp_flags_wildcard_script():
    findings = csp.evaluate("script-src *")
    assert any(sev == "high" and "*" in msg for sev, msg in findings)


def test_csp_missing_policy_is_high():
    assert csp.evaluate("")[0][0] == "high"
    assert csp.evaluate("   ")[0][0] == "high"


def test_csp_reasonable_policy_has_no_high():
    findings = csp.evaluate(
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'")
    assert not any(sev == "high" for sev, _ in findings)


def test_csp_parse():
    d = csp.parse("default-src 'self'; img-src * data:")
    assert d["default-src"] == ["'self'"]
    assert d["img-src"] == ["*", "data:"]


# ---- header grading ----
def test_headers_full_set_scores_A():
    hdrs = {h: "x" for h in headers.GRADED}
    r = headers.analyze(hdrs)
    assert r["grade"] == "A" and r["score"] == 100 and not r["missing"]


def test_headers_empty_is_F():
    r = headers.analyze({})
    assert r["grade"] == "F" and len(r["missing"]) == len(headers.GRADED)


# ---- clickjacking ----
def test_clickjack_xfo_protects():
    assert clickjack.analyze({"x-frame-options": "DENY"})["clickjacking_protected"]


def test_clickjack_csp_frame_ancestors_protects():
    r = clickjack.analyze({"content-security-policy": "frame-ancestors 'none'"})
    assert r["csp_frame_ancestors"] and r["clickjacking_protected"]


def test_clickjack_unprotected():
    assert not clickjack.analyze({})["clickjacking_protected"]


# ---- disclosure ----
def test_disclosure_base_of():
    assert disclosure.base_of("example.com/a/b?x=1") == "https://example.com"
    assert disclosure.base_of("http://x.test") == "http://x.test"
