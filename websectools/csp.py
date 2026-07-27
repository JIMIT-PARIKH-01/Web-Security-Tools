"""Content-Security-Policy evaluator - parses a CSP and flags weaknesses."""
from __future__ import annotations

from .http_util import fetch_site

DANGEROUS = {"'unsafe-inline'", "'unsafe-eval'"}


def parse(csp: str) -> dict:
    """CSP string -> {directive: [sources]} (directive names lower-cased)."""
    directives = {}
    for part in csp.split(";"):
        toks = part.split()
        if toks:
            directives[toks[0].lower()] = toks[1:]
    return directives


def evaluate(csp: str) -> list:
    """Return a list of (severity, message) findings."""
    if not csp or not csp.strip():
        return [("high", "No Content-Security-Policy present.")]
    d = parse(csp)
    out = []

    def add(sev, msg):
        out.append((sev, msg))

    script = d.get("script-src", d.get("default-src"))
    if script is None:
        add("high", "No script-src or default-src - scripts are unrestricted.")
    else:
        for tok in script:
            if tok in DANGEROUS:
                add("high", f"script-src allows {tok} - weakens XSS protection.")
            if tok == "*":
                add("high", "script-src allows '*' (any host).")
            if tok.startswith("http:"):
                add("medium", "script-src allows an insecure http: source.")

    if "default-src" not in d:
        add("medium", "No default-src fallback directive.")
    if "frame-ancestors" not in d:
        add("medium", "No frame-ancestors - clickjacking not blocked via CSP.")
    if "object-src" not in d:
        add("low", "No object-src 'none' - legacy plugin vector left open.")
    if "base-uri" not in d:
        add("low", "No base-uri - <base> tag injection is possible.")
    for name, srcs in d.items():
        if name != "script-src" and "'unsafe-inline'" in srcs:
            add("low", f"{name} allows 'unsafe-inline'.")

    return out or [("info", "No obvious weaknesses found.")]


def scan_url(target: str, timeout: int = 10) -> dict:
    r = fetch_site(target, timeout=timeout)
    if not r.ok:
        return {"target": target, "reachable": False, "error": r.error}
    policy = r.headers.get("content-security-policy", "")
    return {"target": target, "reachable": True,
            "csp": policy, "findings": evaluate(policy)}
