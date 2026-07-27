"""Tiny standard-library HTTP helper — no third-party dependencies."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

UA = ("websectools/1.0 (+https://github.com/JIMIT-PARIKH-01/Web-Security-Tools)")


@dataclass
class Resp:
    ok: bool
    status: int = 0
    url: str = ""
    headers: dict = field(default_factory=dict)   # lower-cased keys
    body: str = ""
    error: str = ""


def _norm(hdrs) -> dict:
    return {str(k).lower(): v for k, v in dict(hdrs).items()}


def fetch(url: str, method: str = "GET", timeout: int = 10,
          max_body: int = 200_000) -> Resp:
    """Fetch a single URL. HTTP error responses (4xx/5xx) still return ok=True
    with their headers/status, because header auditing needs them."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = (r.read(max_body).decode("utf-8", "replace")
                    if method == "GET" else "")
            return Resp(True, getattr(r, "status", 200), r.geturl(),
                        _norm(r.headers), body)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(max_body).decode("utf-8", "replace")
        except Exception:
            pass
        return Resp(True, e.code, url, _norm(e.headers or {}), body)
    except Exception as e:                       # URLError, timeout, ssl, dns…
        return Resp(False, 0, url, {}, "", str(e))


def fetch_site(target: str, timeout: int = 10) -> Resp:
    """Try HTTPS first, fall back to HTTP (mirrors the original HeaderGuard)."""
    if target.startswith(("http://", "https://")):
        return fetch(target, timeout=timeout)
    https = fetch("https://" + target, timeout=timeout)
    return https if https.ok else fetch("http://" + target, timeout=timeout)
