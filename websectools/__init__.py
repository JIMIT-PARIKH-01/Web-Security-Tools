"""Web-Security-Tools — a dependency-free web-security auditor.

Modules: headers (security-header grader), csp (CSP evaluator),
clickjack (framing + HTTP methods), disclosure (security.txt/robots/sitemap).
"""
from . import clickjack, csp, disclosure, headers, http_util

__version__ = "1.0.0"
__all__ = ["headers", "csp", "clickjack", "disclosure", "http_util"]
