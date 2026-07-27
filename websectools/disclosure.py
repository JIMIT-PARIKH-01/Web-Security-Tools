"""Responsible-disclosure & info-file checker (security.txt, robots, sitemap)."""
from __future__ import annotations

from urllib.parse import urlsplit

from .http_util import fetch

PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/humans.txt",
]


def base_of(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    p = urlsplit(target)
    return f"{p.scheme}://{p.netloc}"


def scan_url(target: str, timeout: int = 10) -> dict:
    base = base_of(target)
    results = []
    for path in PATHS:
        r = fetch(base + path, timeout=timeout)
        found = r.ok and r.status == 200 and bool(r.body.strip())
        results.append({"path": path, "found": found,
                        "status": r.status if r.ok else None})
    return {"target": base, "results": results}
