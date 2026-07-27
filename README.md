# Web-Security-Tools

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org)
![License](https://img.shields.io/badge/license-MIT-green)

A **dependency-free** web-security auditor. Point it at a site and it grades the
HTTP security headers, evaluates the Content-Security-Policy, checks clickjacking
protection and exposed HTTP methods, and looks for responsible-disclosure files.

Started as a single header-scanner (`HeaderGuard.py`) and grew into a small
toolkit — pure Python standard library, **GUI + CLI**, tests + CI.

> ⚠️ **Authorized targets only.** Run this against sites you own or are permitted
> to test.

---

## What's inside
| Check | What it does |
|---|---|
| **headers** | Grades 8 security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP) — with a batch `domains.txt → CSV` mode. |
| **csp** | Parses the Content-Security-Policy and flags weaknesses (`unsafe-inline`, wildcard/`http:` sources, missing `frame-ancestors`/`object-src`/`base-uri`). |
| **clickjack** | Checks framing protection (X-Frame-Options / CSP `frame-ancestors`) and lists advertised + risky HTTP methods (via `OPTIONS`). |
| **disclosure** | Looks for `security.txt`, `robots.txt`, `sitemap.xml`, `humans.txt`. |

## Usage
```bash
python -m websectools headers example.com
python -m websectools headers --file domains.txt --csv report.csv   # batch
python -m websectools csp example.com
python -m websectools clickjack example.com
python -m websectools disclosure example.com
python -m websectools audit example.com          # run every check

# GUI
python -m websectools.gui       # or double-click run.bat

# install the `websectools` command
pip install -e .
```

The original `HeaderGuard.py` still works (`python HeaderGuard.py`) — it now runs
on this package, so it no longer needs `requests`.

## ⬇️ Download & Install

**Public tool — download and use it on your device for free.**

```bash
# 1) Clone it
git clone https://github.com/JIMIT-PARIKH-01/Web-Security-Tools.git
cd Web-Security-Tools

# 2) ...or download a ZIP (no git needed)
#    https://github.com/JIMIT-PARIKH-01/Web-Security-Tools/archive/refs/heads/main.zip

# 3) ...or install the command straight from GitHub
pip install git+https://github.com/JIMIT-PARIKH-01/Web-Security-Tools.git
```

## Responsible use
These checks send ordinary HTTP requests, but only run them against systems you
own or are explicitly authorized to assess.

## License
MIT — see [LICENSE](./LICENSE).
