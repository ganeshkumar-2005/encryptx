import urllib.parse
from utils.helpers import make_web_request


class VulnScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout

        # Custom 404 fingerprint — populated once by _fingerprint_custom_404()
        # Stores (status_code, content_length, key_phrases) for the server's
        # "not found" page so we can filter false positives during file probing.
        self._custom_404_fingerprint = None

    # ------------------------------------------------------------------
    # Custom 404 fingerprint helper
    # ------------------------------------------------------------------

    def _fingerprint_custom_404(self):
        """Request a guaranteed-nonexistent path and record the server's
        response characteristics so we can distinguish real files from
        custom 404 pages that return HTTP 200."""
        canary_path = "/this-page-definitely-does-not-exist-8f3k2j"
        canary_url = (
            f"{self.url}{canary_path}"
            if self.url.endswith("/")
            else f"{self.url}{canary_path}"
        )
        try:
            resp = make_web_request(canary_url, timeout=self.timeout)
            # Collect a set of distinguishing phrases from the 404 body
            body_lower = resp.text.lower() if resp.text else ""
            key_phrases = set()
            for phrase in [
                "not found", "404", "page not found", "does not exist",
                "page you requested", "cannot be found", "no longer available",
                "error", "sorry",
            ]:
                if phrase in body_lower:
                    key_phrases.add(phrase)

            self._custom_404_fingerprint = {
                "status_code": resp.status_code,
                "content_length": len(resp.text) if resp.text else 0,
                "key_phrases": key_phrases,
            }
        except Exception:
            # If the canary request itself fails, leave fingerprint as None;
            # file probing will fall back to basic status-code checks only.
            self._custom_404_fingerprint = None

    def _looks_like_custom_404(self, response) -> bool:
        """Return True if *response* matches the custom-404 fingerprint,
        indicating the server returned its generic "not found" page with
        an HTTP 200 status code."""
        if self._custom_404_fingerprint is None:
            return False

        fp = self._custom_404_fingerprint

        # If the canary itself got a non-200, the server uses proper status
        # codes — no custom-404 filtering needed.
        if fp["status_code"] != 200:
            return False

        # The response we're testing must also be 200 to be a false positive
        if response.status_code != 200:
            return False

        body_lower = response.text.lower() if response.text else ""

        # Heuristic 1: content length within ±15 % of the canary
        resp_len = len(response.text) if response.text else 0
        fp_len = fp["content_length"]
        if fp_len > 0:
            length_ratio = abs(resp_len - fp_len) / fp_len
            if length_ratio < 0.15:
                return True

        # Heuristic 2: most of the canary's key phrases appear in this body
        if fp["key_phrases"]:
            matched = sum(1 for p in fp["key_phrases"] if p in body_lower)
            if matched >= len(fp["key_phrases"]) * 0.6:
                return True

        return False

    # ------------------------------------------------------------------
    # CORS checks — deepened with multiple origin variations
    # ------------------------------------------------------------------

    def _check_cors(self, findings: list):
        """Checks for CORS origin reflections and misconfigurations."""
        try:
            # --- Original check: arbitrary evil origin -----------------
            headers = {"Origin": "https://evil.com"}
            response = make_web_request(self.url, headers=headers, timeout=self.timeout)
            allow_origin = response.headers.get("Access-Control-Allow-Origin")
            allow_creds = response.headers.get("Access-Control-Allow-Credentials")

            if allow_origin == "https://evil.com" and allow_creds == "true":
                findings.append({
                    "module": "Vulnerability Scanner",
                    "target": self.url,
                    "severity": "HIGH",
                    "title": "CORS Over-Permissive Origin Reflection with Credentials Allowed",
                    "description": "The server dynamically reflects the Origin header back in Access-Control-Allow-Origin and enables Access-Control-Allow-Credentials, allowing third-party sites to perform authenticated actions on behalf of the user.",
                    "evidence": f"Access-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: {allow_creds}",
                    "remediation": "Do not allow dynamic reflection of the Origin header unless validated against an explicit whitelist of trusted origins. Avoid wildcard origins when Allow-Credentials is true."
                })
            elif allow_origin == "*":
                findings.append({
                    "module": "Vulnerability Scanner",
                    "target": self.url,
                    "severity": "LOW",
                    "title": "CORS Wildcard Policy Allowed",
                    "description": "The server allows all origins via Access-Control-Allow-Origin: *.",
                    "evidence": f"Access-Control-Allow-Origin: *",
                    "remediation": "Ensure this is intended for public content. If the resource contains sensitive data, restrict access to authorized origins."
                })

            # --- Null origin ------------------------------------------
            # Some servers whitelist "null" (e.g. sandboxed iframes, file:// origins).
            # An attacker can craft a null origin via a sandboxed iframe.
            self._cors_probe(findings, origin="null", label="Null Origin",
                             description="The server accepts the 'null' Origin, which attackers can forge via sandboxed iframes or data: URIs.")

            # --- Subdomain matching bypass ----------------------------
            # Extract the target hostname to build evil.target.com
            parsed = urllib.parse.urlparse(self.url)
            hostname = parsed.hostname or ""
            scheme = parsed.scheme or "https"

            evil_subdomain = f"{scheme}://evil.{hostname}"
            self._cors_probe(findings, origin=evil_subdomain,
                             label="Subdomain Matching Bypass",
                             description=f"The server trusts arbitrary subdomains of {hostname}. An attacker controlling a subdomain (e.g. via subdomain takeover) can steal credentials cross-origin.")

            # --- Suffix matching bypass --------------------------------
            # e.g. target.com.evil.com — tests whether server only checks suffix
            evil_suffix = f"{scheme}://{hostname}.evil.com"
            self._cors_probe(findings, origin=evil_suffix,
                             label="Suffix Matching Bypass",
                             description=f"The server appears to match origins by suffix rather than exact domain, allowing {hostname}.evil.com to be trusted.")

            # --- Protocol downgrade (http vs https) --------------------
            if scheme == "https":
                http_origin = f"http://{hostname}"
                self._cors_probe(findings, origin=http_origin,
                                 label="Protocol Downgrade",
                                 description="The HTTPS server trusts an HTTP origin. An active network attacker can downgrade the origin to HTTP and exfiltrate data.")

        except Exception:
            pass

    def _cors_probe(self, findings: list, origin: str, label: str, description: str):
        """Helper: send a single CORS probe and record a finding if the
        origin is reflected with credentials enabled."""
        try:
            resp = make_web_request(self.url, headers={"Origin": origin}, timeout=self.timeout)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            # Origin reflected (exact match or wildcard) WITH credentials
            if acao == origin and acac.lower() == "true":
                findings.append({
                    "module": "Vulnerability Scanner",
                    "target": self.url,
                    "severity": "HIGH",
                    "title": f"CORS Misconfiguration: {label}",
                    "description": description,
                    "evidence": (
                        f"Origin sent: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    "remediation": "Validate the Origin header against a strict whitelist. Do not reflect arbitrary origins when credentials are enabled."
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Clickjacking
    # ------------------------------------------------------------------

    def _check_clickjacking(self, findings: list, headers: dict):
        """Checks for clickjacking protection headers."""
        x_frame = headers.get("x-frame-options", "").lower()
        csp = headers.get("content-security-policy", "").lower()

        has_xframe = "deny" in x_frame or "sameorigin" in x_frame
        has_csp_frame = "frame-ancestors" in csp

        if not has_xframe and not has_csp_frame:
            findings.append({
                "module": "Vulnerability Scanner",
                "target": self.url,
                "severity": "MEDIUM",
                "title": "Clickjacking Protection Missing",
                "description": "The site does not restrict framing via X-Frame-Options or Content-Security-Policy (frame-ancestors directive), leaving users vulnerable to clickjacking attacks.",
                "evidence": f"X-Frame-Options: {headers.get('x-frame-options', 'None')}\nContent-Security-Policy: {headers.get('content-security-policy', 'None')}",
                "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN, or add the 'frame-ancestors' directive to your Content-Security-Policy."
            })

    # ------------------------------------------------------------------
    # Open redirect — expanded parameter list
    # ------------------------------------------------------------------

    def _check_open_redirect(self, findings: list):
        """Tests common open redirect parameters."""
        redirect_payloads = [
            "https://google.com",
            "//google.com",
            "/\\google.com"
        ]
        # Expanded list of redirect parameter names observed in the wild
        redirect_params = [
            "url", "redirect", "redirect_url", "redirect_uri",
            "return", "return_to", "returnTo", "return_path",
            "next", "continue",
            "dest", "destination",
            "redir", "out", "view",
            "go", "goto",
            "login_url", "image_url",
        ]

        for param in redirect_params:
            for payload in redirect_payloads:
                test_url = f"{self.url}?{param}={urllib.parse.quote(payload)}"
                try:
                    response = make_web_request(test_url, timeout=self.timeout, allow_redirects=False)
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "")
                        if "google.com" in location:
                            findings.append({
                                "module": "Vulnerability Scanner",
                                "target": test_url,
                                "severity": "HIGH",
                                "title": "Open Redirect Vulnerability Detected",
                                "description": f"The application redirects a user to an external destination based on user-controlled parameter '{param}' without proper validation.",
                                "evidence": f"HTTP status: {response.status_code}\nLocation header: {location}",
                                "remediation": "Implement strict whitelisting for redirection targets, validate parameters against local routes only, or force local redirects by stripping external host names."
                            })
                            # Find one open redirect and move on to save time
                            return
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Sensitive file probing — with custom-404 filtering & content validation
    # ------------------------------------------------------------------

    def _check_sensitive_files(self, findings: list):
        """Checks for exposure of sensitive files.
        Uses the custom-404 fingerprint to filter false positives, and
        validates response content against expected file signatures."""

        # Content-signature validators for each sensitive path.
        # A validator returns True when the response body looks like
        # the genuine file rather than a generic error / 404 page.
        def _validate_env(text):
            # .env files contain KEY=VALUE pairs with DB_, API_, SECRET, etc.
            return any(kw in text for kw in ("DB_", "API_", "KEY", "SECRET", "PASSWORD"))

        def _validate_git_config(text):
            return "[core]" in text

        def _validate_robots(text):
            return "Disallow" in text or "Allow" in text or "User-agent" in text

        def _validate_sitemap(text):
            return "<urlset" in text or "<sitemapindex" in text

        def _validate_composer(text):
            return '"name"' in text and '"require"' in text

        def _validate_package_json(text):
            return '"name"' in text and ('"dependencies"' in text or '"version"' in text)

        def _validate_htaccess(text):
            # Real .htaccess files typically contain Apache directives
            return any(kw in text for kw in (
                "RewriteEngine", "RewriteRule", "RewriteCond",
                "Options", "DirectoryIndex", "AuthType", "Require",
                "Order", "Deny", "Allow", "Header",
            ))

        def _validate_wp_config(text):
            # Real wp-config.php must contain PHP opening tag + DB constants
            return "<?php" in text and any(kw in text for kw in (
                "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST",
                "table_prefix", "AUTH_KEY",
            ))

        sensitive_paths = [
            (".env", "Environment configuration file exposed", "CRITICAL", _validate_env),
            (".git/config", "Git repository configuration file exposed", "CRITICAL", _validate_git_config),
            ("robots.txt", "Robots.txt available (Information)", "INFO", _validate_robots),
            ("sitemap.xml", "Sitemap.xml available (Information)", "INFO", _validate_sitemap),
            ("wp-config.php", "WordPress configuration file backup exposure", "CRITICAL", _validate_wp_config),
            (".htaccess", "Apache config file exposure", "CRITICAL", _validate_htaccess),
            ("composer.json", "Composer dependency profile exposure", "INFO", _validate_composer),
            ("package.json", "Node.js dependency profile exposure", "INFO", _validate_package_json),
        ]

        for path, description, severity, validator in sensitive_paths:
            test_url = f"{self.url}/{path}" if not self.url.endswith('/') else f"{self.url}{path}"
            try:
                response = make_web_request(test_url, timeout=self.timeout)

                if response.status_code != 200:
                    continue

                # Filter out custom 404 pages masquerading as HTTP 200
                if self._looks_like_custom_404(response):
                    continue

                # Validate response body against expected file signatures
                body = response.text or ""
                if not validator(body):
                    continue

                findings.append({
                    "module": "Vulnerability Scanner",
                    "target": test_url,
                    "severity": severity,
                    "title": f"Sensitive File Exposed: {path}",
                    "description": f"The sensitive file '{path}' is publicly accessible on the web server, which could leak internal configurations or software dependencies.",
                    "evidence": f"File URL: {test_url}\nFirst line preview: {body.splitlines()[0][:100] if body else 'Empty'}",
                    "remediation": "Restrict access to configuration, database, backup, and environment files in your web server configurations."
                })
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Dangerous HTTP methods
    # ------------------------------------------------------------------

    def _check_dangerous_methods(self, findings: list):
        """Tests for dangerous HTTP methods."""
        try:
            # Test PUT
            response_put = make_web_request(self.url, method="PUT", data={"test": "data"}, timeout=self.timeout)
            if response_put.status_code in (200, 201, 204):
                findings.append({
                    "module": "Vulnerability Scanner",
                    "target": self.url,
                    "severity": "HIGH",
                    "title": "Dangerous HTTP Method Allowed: PUT",
                    "description": "The server accepts the PUT method on root URL, potentially allowing unauthorized file creation or modification.",
                    "evidence": f"PUT request returned HTTP: {response_put.status_code}",
                    "remediation": "Restrict HTTP methods in web server configurations. Disable PUT, DELETE, and TRACE."
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # CRLF injection
    # ------------------------------------------------------------------

    def _check_crlf_injection(self, findings: list):
        """Tests CRLF injection in parameter handling."""
        crlf_payload = "test%0d%0aSet-Cookie:%20scopex_crlf=1"
        test_url = f"{self.url}?q={crlf_payload}"
        try:
            response = make_web_request(test_url, timeout=self.timeout)
            if "scopex_crlf" in response.headers.get("Set-Cookie", ""):
                findings.append({
                    "module": "Vulnerability Scanner",
                    "target": test_url,
                    "severity": "HIGH",
                    "title": "CRLF Injection Vulnerability Detected",
                    "description": "The application reflects user input into HTTP headers without stripping Carriage Return (CR) and Line Feed (LF) characters, allowing HTTP response splitting or session fixation.",
                    "evidence": f"Response header: Set-Cookie contains 'scopex_crlf=1'",
                    "remediation": "Sanitize user inputs before printing them into HTTP response headers, ensuring CR and LF characters are stripped or encoded."
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Host header injection
    # ------------------------------------------------------------------

    def _check_host_header_injection(self, findings: list):
        """Tests for host header injection vulnerability."""
        try:
            headers = {"Host": "malicious-host.com"}
            response = make_web_request(self.url, headers=headers, timeout=self.timeout)
            # If the response redirects, links, or reflects the malicious host
            if "malicious-host.com" in response.text or "malicious-host.com" in response.headers.get("Location", ""):
                findings.append({
                    "module": "Vulnerability Scanner",
                    "target": self.url,
                    "severity": "MEDIUM",
                    "title": "Host Header Injection Vulnerability Detected",
                    "description": "The application dynamically constructs links, redirects, or header parameters using the client-provided HTTP Host header without validation.",
                    "evidence": f"Reflected Host header in response body or Location headers.",
                    "remediation": "Configure the web server to only bind/respond to the explicit server name or configured hostname. Do not trust or reflect the incoming Host header."
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # security.txt — RFC 9116 compliance check
    # ------------------------------------------------------------------

    def _check_security_txt(self, findings: list):
        """Check for the presence and RFC 9116 compliance of security.txt.

        RFC 9116 requires the file at /.well-known/security.txt (preferred)
        or /security.txt (legacy). Required fields: Contact, Expires.
        """
        # Paths to probe, in order of preference per RFC 9116
        security_txt_paths = [
            "/.well-known/security.txt",
            "/security.txt",
        ]
        found = False
        found_url = ""
        body = ""

        for path in security_txt_paths:
            url = (
                f"{self.url.rstrip('/')}{path}"
            )
            try:
                resp = make_web_request(url, timeout=self.timeout)
                if resp.status_code == 200 and resp.text:
                    content_type = resp.headers.get("Content-Type", "")
                    # security.txt should be plain text
                    if "text/" in content_type or "octet-stream" in content_type:
                        # Quick sanity: must contain "Contact:" to be a real security.txt
                        if "Contact:" in resp.text or "contact:" in resp.text.lower():
                            found = True
                            found_url = url
                            body = resp.text
                            break
            except Exception:
                continue

        if not found:
            # No valid security.txt found at either location
            findings.append({
                "module": "Vulnerability Scanner",
                "target": self.url,
                "severity": "INFO",
                "title": "Missing security.txt (RFC 9116)",
                "description": (
                    "No valid security.txt file was found at /.well-known/security.txt "
                    "or /security.txt. RFC 9116 recommends publishing a security.txt so "
                    "that security researchers can report vulnerabilities responsibly."
                ),
                "evidence": "Neither /.well-known/security.txt nor /security.txt returned a valid security.txt file.",
                "remediation": (
                    "Create a security.txt file at /.well-known/security.txt with at "
                    "least the 'Contact:' and 'Expires:' fields as specified by RFC 9116. "
                    "See https://securitytxt.org for a generator."
                )
            })
            return

        # --- Validate RFC 9116 required fields -------------------------
        body_lower = body.lower()
        issues = []

        # Required: Contact field
        if "contact:" not in body_lower:
            issues.append("Missing required 'Contact' field")

        # Required: Expires field (RFC 9116 §2.5.5)
        if "expires:" not in body_lower:
            issues.append("Missing required 'Expires' field")

        # Recommended: the file should be at /.well-known/ location
        if "/.well-known/" not in found_url:
            issues.append("File is at /security.txt instead of the recommended /.well-known/security.txt")

        # Recommended: should be served over HTTPS
        if found_url.startswith("http://"):
            issues.append("security.txt served over plain HTTP instead of HTTPS")

        # Optional but recommended: digital signature
        # (We just note its absence, not flag it as an issue)

        if issues:
            findings.append({
                "module": "Vulnerability Scanner",
                "target": found_url,
                "severity": "INFO",
                "title": "security.txt Found but Not Fully RFC 9116 Compliant",
                "description": (
                    "A security.txt file was found but has compliance issues per RFC 9116: "
                    + "; ".join(issues) + "."
                ),
                "evidence": f"URL: {found_url}\nIssues: {'; '.join(issues)}\nFirst 200 chars: {body[:200]}",
                "remediation": (
                    "Update your security.txt to include all required fields (Contact, Expires) "
                    "and serve it from /.well-known/security.txt over HTTPS. "
                    "See https://securitytxt.org for guidance."
                )
            })
        else:
            # Fully compliant — informational finding
            findings.append({
                "module": "Vulnerability Scanner",
                "target": found_url,
                "severity": "INFO",
                "title": "security.txt Present and RFC 9116 Compliant",
                "description": "A valid security.txt file was found that meets RFC 9116 requirements.",
                "evidence": f"URL: {found_url}\nFirst 200 chars: {body[:200]}",
                "remediation": "No action required. Ensure the Expires date is kept up to date."
            })

    # ------------------------------------------------------------------
    # Main scan orchestrator
    # ------------------------------------------------------------------

    def scan(self) -> dict:
        findings = []
        headers = {}

        try:
            response = make_web_request(self.url, timeout=self.timeout)
            headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception as e:
            return {
                "error": f"Failed to connect to target to scan vulnerabilities: {str(e)}",
                "findings": []
            }

        # Fingerprint the server's custom 404 page before file probing
        self._fingerprint_custom_404()

        self._check_cors(findings)
        self._check_clickjacking(findings, headers)
        self._check_open_redirect(findings)
        self._check_sensitive_files(findings)
        self._check_dangerous_methods(findings)
        self._check_crlf_injection(findings)
        self._check_host_header_injection(findings)
        self._check_security_txt(findings)

        return {
            "target_url": self.url,
            "findings": findings
        }

Class = VulnScanner
