"""
Module: remediation_generator.py
Description: Maps identified structural vulnerabilities and missing headers
             to copy-pasteable, production-ready server configs and framework patches.
"""

from typing import Dict


def generate_remediation_payload(vulnerability_title: str) -> Dict[str, str]:
    """
    Returns deployment-ready defensive configuration blocks and code adjustments
    based on the vulnerability or misconfiguration title.
    """
    title_lower = vulnerability_title.lower()

    # 1. Content Security Policy (CSP)
    if "content security policy" in title_lower or "csp" in title_lower:
        return {
            "type": "HTTP Header",
            "nginx": (
                "# Enforce restrictive CSP\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\" always;\n"
            ),
            "apache": (
                "# Enforce restrictive CSP\n"
                "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\"\n"
            ),
            "cloudflare_transform_rules": (
                "Header Name: Content-Security-Policy\n"
                "Value: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\n"
            )
        }

    # 2. HTTP Strict Transport Security (HSTS)
    if "strict-transport-security" in title_lower or "hsts" in title_lower:
        return {
            "type": "HTTP Header",
            "nginx": (
                "# Enforce HSTS (1 year max-age with subdomains and preload submission)\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
            ),
            "apache": (
                "# Enforce HSTS\n"
                "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
            ),
            "cloudflare_transform_rules": (
                "Header Name: Strict-Transport-Security\n"
                "Value: max-age=31536000; includeSubDomains; preload\n"
            )
        }

    # 3. Clickjacking / X-Frame-Options
    if "frame-options" in title_lower or "clickjacking" in title_lower:
        return {
            "type": "HTTP Header",
            "nginx": "add_header X-Frame-Options \"DENY\" always;\n",
            "apache": "Header always set X-Frame-Options \"DENY\"\n",
            "cloudflare_transform_rules": "Header Name: X-Frame-Options\nValue: DENY\n"
        }

    # 4. Insecure Cookie Flags (Secure, HttpOnly, SameSite)
    if "cookie" in title_lower or "samesite" in title_lower:
        return {
            "type": "Application Code Patch",
            "django_settings": (
                "# Django settings.py\n"
                "SESSION_COOKIE_SECURE = True\n"
                "SESSION_COOKIE_HTTPONLY = True\n"
                "SESSION_COOKIE_SAMESITE = 'Lax'\n"
                "CSRF_COOKIE_SECURE = True\n"
                "CSRF_COOKIE_HTTPONLY = True\n"
                "CSRF_COOKIE_SAMESITE = 'Lax'\n"
            ),
            "express_js": (
                "// Express.js session config\n"
                "app.use(session({\n"
                "  secret: process.env.SESSION_SECRET,\n"
                "  cookie: {\n"
                "    secure: true,\n"
                "    httpOnly: true,\n"
                "    sameSite: 'lax',\n"
                "    maxAge: 3600000\n"
                "  }\n"
                "}));\n"
            ),
            "flask": (
                "# Flask app.py\n"
                "app.config.update(\n"
                "    SESSION_COOKIE_SECURE=True,\n"
                "    SESSION_COOKIE_HTTPONLY=True,\n"
                "    SESSION_COOKIE_SAMESITE='Lax'\n"
                ")\n"
            )
        }

    # 5. Fallback Default Defense Recommendation
    return {
        "type": "General Hardening",
        "nginx": (
            "# Base Security Headers Baseline\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "server_tokens off;\n"
        ),
        "apache": (
            "# Base Security Headers Baseline\n"
            "Header always set X-Content-Type-Options \"nosniff\"\n"
            "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
            "ServerSignature Off\n"
        )
    }
