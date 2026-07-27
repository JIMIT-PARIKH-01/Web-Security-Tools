"""Security-header analyzer — a dependency-free refactor of the original
HeaderGuard, with grading and the same domains.txt -> CSV batch mode."""
from __future__ import annotations

import csv

from .http_util import fetch_site

# header (lower-case) -> why it matters
GRADED = {
    "content-security-policy": "Controls resource loading; mitigates XSS/injection.",
    "strict-transport-security": "Forces HTTPS (HSTS).",
    "x-frame-options": "Legacy clickjacking protection.",
    "x-content-type-options": "Stops MIME sniffing (nosniff).",
    "referrer-policy": "Limits referrer leakage.",
    "permissions-policy": "Restricts powerful browser features.",
    "cross-origin-opener-policy": "Process isolation (COOP).",
    "cross-origin-resource-policy": "Restricts cross-origin embedding (CORP).",
}


def _grade(score: int) -> str:
    return ("A" if score >= 90 else "B" if score >= 75 else
            "C" if score >= 60 else "D" if score >= 40 else "F")


def analyze(headers: dict) -> dict:
    """Pure: given response headers (lower-cased keys), grade the posture."""
    present = {h: headers[h] for h in GRADED if h in headers}
    missing = [h for h in GRADED if h not in headers]
    score = round(100 * len(present) / len(GRADED))
    return {"present": present, "missing": missing,
            "score": score, "grade": _grade(score)}


def scan_url(target: str, timeout: int = 10) -> dict:
    r = fetch_site(target, timeout=timeout)
    if not r.ok:
        return {"target": target, "reachable": False, "error": r.error}
    out = analyze(r.headers)
    out.update({"target": target, "reachable": True,
                "final_url": r.url, "status": r.status})
    return out


def scan_file(path: str, csv_out: str | None = None, timeout: int = 10) -> list:
    """Batch mode: one domain per line (comments with '#' allowed)."""
    with open(path, encoding="utf-8") as f:
        domains = [ln.strip() for ln in f
                   if ln.strip() and not ln.lstrip().startswith("#")]
    rows = []
    for d in domains:
        res = scan_url(d, timeout)
        rows.append({
            "Domain": d,
            "Reachable": "Yes" if res.get("reachable") else "No",
            "Final URL": res.get("final_url", ""),
            "Status": res.get("status", ""),
            "Grade": res.get("grade", ""),
            "Missing Headers": (", ".join(res["missing"])
                                if res.get("reachable") else "N/A"),
            "Error": res.get("error", ""),
        })
    if csv_out and rows:
        with open(csv_out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    return rows
