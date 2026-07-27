"""Unified CLI for Web-Security-Tools.

    python -m websectools headers example.com
    python -m websectools headers --file domains.txt --csv out.csv
    python -m websectools csp example.com
    python -m websectools clickjack example.com
    python -m websectools disclosure example.com
    python -m websectools audit example.com        # run all checks
"""
from __future__ import annotations

import argparse

from . import clickjack, csp, disclosure, headers


def _hdr(title: str) -> None:
    print("\n=== " + title + " ===")


def cmd_headers(a) -> None:
    if getattr(a, "file", None):
        rows = headers.scan_file(a.file, getattr(a, "csv", None))
        _hdr("Security headers (batch)")
        for r in rows:
            print(f"{r['Domain']:28} {r['Reachable']:4} "
                  f"grade={r['Grade'] or '-':2} missing={r['Missing Headers']}")
        if getattr(a, "csv", None):
            print(f"\nCSV written -> {a.csv}")
        return
    if not a.target:
        raise SystemExit("provide a target, or --file for batch mode")
    res = headers.scan_url(a.target)
    _hdr(f"Security headers: {a.target}")
    if not res.get("reachable"):
        print("unreachable:", res.get("error"))
        return
    print(f"final: {res['final_url']}  status {res['status']}")
    print(f"grade {res['grade']} ({res['score']}/100)")
    print("present:", ", ".join(res["present"]) or "none")
    print("missing:", ", ".join(res["missing"]) or "none")


def cmd_csp(a) -> None:
    res = csp.scan_url(a.target)
    _hdr(f"Content-Security-Policy: {a.target}")
    if not res.get("reachable"):
        print("unreachable:", res.get("error"))
        return
    print("policy:", res["csp"] or "(none)")
    for sev, msg in res["findings"]:
        print(f"[{sev.upper():6}] {msg}")


def cmd_clickjack(a) -> None:
    res = clickjack.scan_url(a.target)
    _hdr(f"Clickjacking + methods: {a.target}")
    if not res.get("reachable"):
        print("unreachable:", res.get("error"))
        return
    print("X-Frame-Options    :", res["x_frame_options"] or "MISSING")
    print("CSP frame-ancestors:", "yes" if res["csp_frame_ancestors"] else "no")
    print("clickjacking       :",
          "protected" if res["clickjacking_protected"] else "VULNERABLE")
    m = res["methods"]
    print("allowed methods    :", ", ".join(m["allow"]) or "unknown")
    if m["risky"]:
        print("risky methods      :", ", ".join(m["risky"]))


def cmd_disclosure(a) -> None:
    res = disclosure.scan_url(a.target)
    _hdr(f"Disclosure files: {res['target']}")
    for r in res["results"]:
        mark = "FOUND " if r["found"] else "absent"
        print(f"{mark} {r['path']}  (status {r['status']})")


def cmd_audit(a) -> None:
    for fn in (cmd_headers, cmd_csp, cmd_clickjack, cmd_disclosure):
        try:
            fn(a)
        except Exception as e:                    # keep going through the audit
            print("error:", e)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="websectools",
        description="Dependency-free web-security auditor.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("headers", help="security-header grading (+batch)")
    h.add_argument("target", nargs="?")
    h.add_argument("--file", help="batch mode: a file of domains")
    h.add_argument("--csv", help="write batch results to this CSV")
    h.set_defaults(fn=cmd_headers)

    for name, fn, helptext in (
        ("csp", cmd_csp, "evaluate the Content-Security-Policy"),
        ("clickjack", cmd_clickjack, "clickjacking + HTTP methods"),
        ("disclosure", cmd_disclosure, "security.txt / robots / sitemap"),
    ):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("target")
        p.set_defaults(fn=fn)

    au = sub.add_parser("audit", help="run every check on one target")
    au.add_argument("target")
    au.add_argument("--file", default=None)
    au.add_argument("--csv", default=None)
    au.set_defaults(fn=cmd_audit)

    args = ap.parse_args(argv)
    args.fn(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
