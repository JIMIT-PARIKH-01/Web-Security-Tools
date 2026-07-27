"""Clickjacking protection + HTTP-methods checks."""
from __future__ import annotations

from .http_util import fetch, fetch_site

RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def analyze(headers: dict) -> dict:
    """Pure: is the page protected against being framed?"""
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    frame_ancestors = "frame-ancestors" in csp.lower()
    return {
        "x_frame_options": xfo or None,
        "csp_frame_ancestors": frame_ancestors,
        "clickjacking_protected": bool(xfo) or frame_ancestors,
    }


def methods(target: str, timeout: int = 10) -> dict:
    """Send OPTIONS and report the advertised (and risky) methods."""
    url = target if target.startswith("http") else "https://" + target
    r = fetch(url, method="OPTIONS", timeout=timeout)
    allow = r.headers.get("allow", "") if r.ok else ""
    allowed = [m.strip().upper() for m in allow.split(",") if m.strip()]
    return {"allow": allowed,
            "risky": [m for m in allowed if m in RISKY_METHODS],
            "ok": r.ok, "error": r.error}


def scan_url(target: str, timeout: int = 10) -> dict:
    r = fetch_site(target, timeout=timeout)
    if not r.ok:
        return {"target": target, "reachable": False, "error": r.error}
    out = analyze(r.headers)
    out.update({"target": target, "reachable": True,
                "methods": methods(target, timeout)})
    return out
