import re
from utils.helpers import make_web_request


class HeaderScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout

    # ------------------------------------------------------------------
    # CSP quality analysis helpers
    # ------------------------------------------------------------------

    def _parse_csp(self, csp_value: str) -> dict:
        """Parse a Content-Security-Policy header value into a dict of
        directive -> list-of-source-expressions."""
        directives = {}
        # Directives are separated by semicolons
        for part in csp_value.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directive_name = tokens[0].lower()
                sources = [s.lower() for s in tokens[1:]]
                directives[directive_name] = sources
        return directives

    def _check_csp_quality(self, findings: list, csp_value: str):
        """When a CSP header is present, inspect it for common weaknesses."""
        directives = self._parse_csp(csp_value)
        issues = []

        # Determine effective script-src (falls back to default-src per spec)
        script_sources = directives.get("script-src", directives.get("default-src", []))
        default_sources = directives.get("default-src", [])

        # 1. 'unsafe-inline' in script-src or default-src
        if "'unsafe-inline'" in script_sources:
            issues.append("'unsafe-inline' present in script-src — allows inline <script> execution, largely defeating XSS protection")
        elif "'unsafe-inline'" in default_sources:
            issues.append("'unsafe-inline' present in default-src — allows inline scripts as a fallback")

        # 2. 'unsafe-eval' in script-src or default-src
        if "'unsafe-eval'" in script_sources:
            issues.append("'unsafe-eval' present in script-src — allows eval(), Function(), and similar dynamic code execution")
        elif "'unsafe-eval'" in default_sources:
            issues.append("'unsafe-eval' present in default-src — allows eval() as a fallback")

        # 3. Wildcard '*' in any directive
        for directive_name, sources in directives.items():
            if "*" in sources:
                issues.append(f"Wildcard '*' source in '{directive_name}' — allows loading resources from any origin")
                break  # One finding is enough to flag the issue

        # 4. data: URIs in script-src
        if "data:" in script_sources:
            issues.append("'data:' URI scheme in script-src — attackers can execute scripts via data: URIs")

        # 5. Missing frame-ancestors directive (clickjacking protection via CSP)
        if "frame-ancestors" not in directives:
            issues.append("Missing 'frame-ancestors' directive — page can be framed by any origin (clickjacking risk)")

        if issues:
            findings.append({
                "module": "Header Scanner",
                "target": self.url,
                "severity": "MEDIUM",
                "title": "Content Security Policy (CSP) Weaknesses Detected",
                "description": (
                    "The CSP header is present but contains configuration weaknesses that "
                    "reduce its effectiveness against XSS and data injection attacks."
                ),
                "evidence": f"CSP: {csp_value[:300]}\nIssues:\n- " + "\n- ".join(issues),
                "remediation": (
                    "Remove 'unsafe-inline' and 'unsafe-eval' from script-src (use nonces or hashes instead). "
                    "Replace wildcard '*' sources with explicit origins. Remove 'data:' from script-src. "
                    "Add a 'frame-ancestors' directive to prevent clickjacking."
                )
            })

    # ------------------------------------------------------------------
    # HSTS preload readiness
    # ------------------------------------------------------------------

    def _check_hsts_preload(self, findings: list, hsts_value: str):
        """Check HSTS header for preload-readiness: includeSubDomains,
        preload flag, and max-age >= 31536000 (1 year)."""
        hsts_lower = hsts_value.lower()
        issues = []

        # Extract max-age value
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                issues.append(
                    f"max-age is {max_age} seconds ({max_age // 86400} days), "
                    f"which is below the recommended minimum of 31536000 (1 year)"
                )
        else:
            issues.append("max-age directive is missing or malformed")

        if "includesubdomains" not in hsts_lower:
            issues.append("Missing 'includeSubDomains' — subdomains are not covered by HSTS")

        if "preload" not in hsts_lower:
            issues.append("Missing 'preload' — domain is not eligible for browser HSTS preload lists")

        if issues:
            findings.append({
                "module": "Header Scanner",
                "target": self.url,
                "severity": "LOW",
                "title": "HSTS Header Not Preload-Ready",
                "description": (
                    "The Strict-Transport-Security header is present but does not meet "
                    "the requirements for inclusion in browser HSTS preload lists."
                ),
                "evidence": f"Strict-Transport-Security: {hsts_value}\nIssues:\n- " + "\n- ".join(issues),
                "remediation": (
                    "Set HSTS to: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. "
                    "Then submit your domain to hstspreload.org for inclusion in browser preload lists."
                )
            })

    # ------------------------------------------------------------------
    # Deprecated header detection
    # ------------------------------------------------------------------

    def _check_deprecated_headers(self, findings: list, headers_found: dict):
        """Flag deprecated or harmful security header configurations."""
        # 1. X-XSS-Protection: 1  — deprecated; can actually introduce
        #    vulnerabilities in some browsers (information leakage via
        #    selective script blocking in IE/Edge legacy).
        xxss = headers_found.get("x-xss-protection", "")
        if xxss:
            # Flag if enabled (starts with '1')
            xxss_stripped = xxss.strip()
            if xxss_stripped.startswith("1"):
                findings.append({
                    "module": "Header Scanner",
                    "target": self.url,
                    "severity": "LOW",
                    "title": "Deprecated X-XSS-Protection Header Enabled",
                    "description": (
                        "The X-XSS-Protection header is set to '1' (enabled). This header is "
                        "deprecated and removed from modern browsers. In legacy browsers (IE, "
                        "old Edge) it can paradoxically introduce XSS vulnerabilities through "
                        "selective script blocking side-channels."
                    ),
                    "evidence": f"X-XSS-Protection: {xxss}",
                    "remediation": (
                        "Remove the X-XSS-Protection header entirely, or set it to '0' to "
                        "explicitly disable the filter. Rely on Content-Security-Policy for "
                        "XSS mitigation instead."
                    )
                })

        # 2. X-Frame-Options: ALLOW-FROM — deprecated; not supported by
        #    modern browsers. Use CSP frame-ancestors instead.
        xfo = headers_found.get("x-frame-options", "")
        if "allow-from" in xfo.lower():
            findings.append({
                "module": "Header Scanner",
                "target": self.url,
                "severity": "MEDIUM",
                "title": "Deprecated X-Frame-Options ALLOW-FROM Directive",
                "description": (
                    "The X-Frame-Options header uses the 'ALLOW-FROM' directive, which is "
                    "deprecated and not supported by modern browsers (Chrome, Firefox, Edge). "
                    "This means clickjacking protection is effectively absent for most users."
                ),
                "evidence": f"X-Frame-Options: {xfo}",
                "remediation": (
                    "Replace 'X-Frame-Options: ALLOW-FROM' with the CSP 'frame-ancestors' "
                    "directive, which is widely supported: "
                    "Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com;"
                )
            })

    # ------------------------------------------------------------------
    # Cache-Control audit
    # ------------------------------------------------------------------

    def _check_cache_control(self, findings: list, headers_found: dict):
        """Check for Cache-Control header and flag if no-store is missing,
        which may allow sensitive responses to be cached by browsers or
        intermediate proxies."""
        cache_control = headers_found.get("cache-control", "")

        if not cache_control:
            # Header entirely missing
            findings.append({
                "module": "Header Scanner",
                "target": self.url,
                "severity": "LOW",
                "title": "Missing Cache-Control Header",
                "description": (
                    "The response does not include a Cache-Control header. Without explicit "
                    "caching directives, browsers and proxies may cache the response, "
                    "potentially storing sensitive data on disk or in shared caches."
                ),
                "evidence": "Cache-Control header was not found in the response.",
                "remediation": (
                    "Add 'Cache-Control: no-store, no-cache, must-revalidate' to responses "
                    "containing sensitive or user-specific data."
                )
            })
        elif "no-store" not in cache_control.lower():
            # Header present but no-store not set
            findings.append({
                "module": "Header Scanner",
                "target": self.url,
                "severity": "LOW",
                "title": "Cache-Control Missing 'no-store' Directive",
                "description": (
                    "The Cache-Control header is present but does not include the 'no-store' "
                    "directive. Without 'no-store', browsers and proxies are permitted to "
                    "cache the response, which may expose sensitive data."
                ),
                "evidence": f"Cache-Control: {cache_control}",
                "remediation": (
                    "Add the 'no-store' directive to your Cache-Control header for responses "
                    "that contain sensitive data: Cache-Control: no-store, no-cache, must-revalidate."
                )
            })

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    def scan(self) -> dict:
        findings = []
        headers_found = {}

        # Test HTTP headers by requesting the target URL
        try:
            # First try HTTPS, fallback to HTTP if it fails
            try:
                response = make_web_request(self.url, timeout=self.timeout)
            except Exception:
                if self.url.startswith("https://"):
                    self.url = self.url.replace("https://", "http://")
                    response = make_web_request(self.url, timeout=self.timeout)
                else:
                    raise

            headers_found = {k.lower(): v for k, v in response.headers.items()}
        except Exception as e:
            return {
                "error": f"Failed to connect to web server for header scan: {str(e)}",
                "findings": []
            }

        # Header definitions to check
        security_headers = {
            "strict-transport-security": {
                "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                "severity": "MEDIUM",
                "desc": "HTTP Strict Transport Security (HSTS) instructs the browser to always connect using HTTPS, preventing SSL stripping attacks.",
                "remedy": "Add the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to your web server configuration."
            },
            "content-security-policy": {
                "title": "Missing Content Security Policy (CSP) Header",
                "severity": "HIGH",
                "desc": "Content Security Policy (CSP) restricts the resources (such as JavaScript, CSS, Images) that the browser is allowed to load for a given page, offering defense-in-depth against XSS.",
                "remedy": "Implement a robust Content Security Policy header. For example: Content-Security-Policy: default-src 'self';"
            },
            "x-content-type-options": {
                "title": "Missing X-Content-Type-Options Header",
                "severity": "LOW",
                "desc": "The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should not be changed and be followed.",
                "remedy": "Configure the web server to send the X-Content-Type-Options: nosniff header."
            },
            "x-frame-options": {
                "title": "Missing X-Frame-Options Header",
                "severity": "MEDIUM",
                "desc": "X-Frame-Options prevents the website from being loaded in an iframe or object, which protects users against clickjacking attacks.",
                "remedy": "Configure the web server to send X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header, or use the CSP frame-ancestors directive."
            },
            "referrer-policy": {
                "title": "Missing Referrer-Policy Header",
                "severity": "INFO",
                "desc": "The Referrer-Policy HTTP header controls how much referrer information (sent via the Referer header) should be included with requests.",
                "remedy": "Add the Referrer-Policy: strict-origin-when-cross-origin header to web responses."
            },
            "permissions-policy": {
                "title": "Missing Permissions-Policy Header",
                "severity": "INFO",
                "desc": "Permissions-Policy allows developers to selectively enable, disable, and modify the behavior of various APIs and browser features (camera, geolocation, etc.).",
                "remedy": "Add a Permissions-Policy header configured with restricted features (e.g., geolocation=(), camera=())."
            }
        }

        # Check for missing headers
        for header, info in security_headers.items():
            if header not in headers_found:
                findings.append({
                    "module": "Header Scanner",
                    "target": self.url,
                    "severity": info["severity"],
                    "title": info["title"],
                    "description": info["desc"],
                    "evidence": f"Header '{header}' was not found in response.",
                    "remediation": info["remedy"]
                })
            else:
                # Add validation logic for headers if they exist
                val = headers_found[header]
                if header == "strict-transport-security" and "max-age" not in val:
                    findings.append({
                        "module": "Header Scanner",
                        "target": self.url,
                        "severity": "LOW",
                        "title": "Weak HSTS Header Configuration",
                        "description": "HSTS header is present but missing max-age or is misconfigured.",
                        "evidence": f"Strict-Transport-Security: {val}",
                        "remediation": "Configure HSTS with 'max-age=31536000' and 'includeSubDomains' (and optionally 'preload')."
                    })

        # --- NEW: CSP quality analysis when header is present -----------
        if "content-security-policy" in headers_found:
            self._check_csp_quality(findings, headers_found["content-security-policy"])

        # --- NEW: HSTS preload readiness check -------------------------
        if "strict-transport-security" in headers_found:
            self._check_hsts_preload(findings, headers_found["strict-transport-security"])

        # --- NEW: Deprecated header detection --------------------------
        self._check_deprecated_headers(findings, headers_found)

        # --- NEW: Cache-Control audit ----------------------------------
        self._check_cache_control(findings, headers_found)

        # Information disclosure headers checks
        info_headers = {
            "server": {
                "severity": "INFO",
                "title": "Web Server Signature Disclosure",
                "desc": "The server header discloses details about the web server backend software and potentially its version."
            },
            "x-powered-by": {
                "severity": "LOW",
                "title": "Technology Information Disclosure",
                "desc": "The X-Powered-By header discloses underlying backend frameworks/technologies (e.g. Express, PHP, ASP.NET)."
            },
            "x-aspnet-version": {
                "severity": "LOW",
                "title": "ASP.NET Version Disclosure",
                "desc": "The X-AspNet-Version header leaks the version of ASP.NET currently running on the server."
            }
        }

        for header, info in info_headers.items():
            if header in headers_found:
                val = headers_found[header]
                # Flag if it leaks specific version numbers or verbose details
                is_verbose = any(char.isdigit() for char in val) or len(val.split()) > 1
                sev = "LOW" if is_verbose or header != "server" else "INFO"

                findings.append({
                    "module": "Header Scanner",
                    "target": self.url,
                    "severity": sev,
                    "title": info["title"],
                    "description": info["desc"],
                    "evidence": f"{header.title()}: {val}",
                    "remediation": f"Disable or strip the '{header}' header in your web server configuration (e.g., exposeHeaders / ServerTokens off)."
                })

        return {
            "url": self.url,
            "headers": headers_found,
            "findings": findings
        }

Class = HeaderScanner
