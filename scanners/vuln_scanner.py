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

    def _check_cors(self, findings: list):
        """Checks for CORS origin reflections and misconfigurations."""
        try:
            # Check wildcard reflection
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
        except Exception:
            pass

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

    def _check_open_redirect(self, findings: list):
        """Tests common open redirect parameters."""
        redirect_payloads = [
            "https://google.com",
            "//google.com",
            "/\\google.com"
        ]
        redirect_params = ["url", "redirect", "next", "return", "dest", "destination", "go", "goto"]
        
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

    def _check_sensitive_files(self, findings: list):
        """Checks for exposure of sensitive files."""
        sensitive_paths = [
            (".env", "Environment configuration file exposed"),
            (".git/config", "Git repository configuration file exposed"),
            ("robots.txt", "Robots.txt available (Information)"),
            ("sitemap.xml", "Sitemap.xml available (Information)"),
            ("wp-config.php", "WordPress configuration file backup exposure"),
            (".htaccess", "Apache config file exposure"),
            ("composer.json", "Composer dependency profile exposure"),
            ("package.json", "Node.js dependency profile exposure")
        ]
        
        for path, description in sensitive_paths:
            test_url = f"{self.url}/{path}" if not self.url.endswith('/') else f"{self.url}{path}"
            try:
                response = make_web_request(test_url, timeout=self.timeout)
                # Ensure it's not a custom error page masquerading as 200 OK
                # Check file signature markers
                is_valid_file = False
                if response.status_code == 200:
                    if path == ".env" and ("DB_" in response.text or "API_" in response.text or "KEY" in response.text):
                        is_valid_file = True
                    elif path == ".git/config" and "[core]" in response.text:
                        is_valid_file = True
                    elif path == "robots.txt" and "Disallow" in response.text:
                        is_valid_file = True
                    elif path == "sitemap.xml" and "<urlset" in response.text:
                        is_valid_file = True
                    elif path in ("composer.json", "package.json") and '"name"' in response.text:
                        is_valid_file = True
                    elif path in (".htaccess", "wp-config.php"):
                        is_valid_file = True # If server returns 200 and matches file type
                        
                if is_valid_file:
                    severity = "CRITICAL" if path in (".env", ".git/config", "wp-config.php", ".htaccess") else "INFO"
                    findings.append({
                        "module": "Vulnerability Scanner",
                        "target": test_url,
                        "severity": severity,
                        "title": f"Sensitive File Exposed: {path}",
                        "description": f"The sensitive file '{path}' is publicly accessible on the web server, which could leak internal configurations or software dependencies.",
                        "evidence": f"File URL: {test_url}\nFirst line preview: {response.text.splitlines()[0][:100] if response.text else 'Empty'}",
                        "remediation": "Restrict access to configuration, database, backup, and environment files in your web server configurations."
                    })
            except Exception:
                pass

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

    def _check_crlf_injection(self, findings: list):
        """Tests CRLF injection in parameter handling."""
        crlf_payload = "test%0d%0aSet-Cookie:%20encryptx_crlf=1"
        test_url = f"{self.url}?q={crlf_payload}"
        try:
            response = make_web_request(test_url, timeout=self.timeout)
            if "encryptx_crlf" in response.headers.get("Set-Cookie", ""):
                findings.append({
                    "module": "Vulnerability Scanner",
                    "target": test_url,
                    "severity": "HIGH",
                    "title": "CRLF Injection Vulnerability Detected",
                    "description": "The application reflects user input into HTTP headers without stripping Carriage Return (CR) and Line Feed (LF) characters, allowing HTTP response splitting or session fixation.",
                    "evidence": f"Response header: Set-Cookie contains 'encryptx_crlf=1'",
                    "remediation": "Sanitize user inputs before printing them into HTTP response headers, ensuring CR and LF characters are stripped or encoded."
                })
        except Exception:
            pass

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
            
        self._check_cors(findings)
        self._check_clickjacking(findings, headers)
        self._check_open_redirect(findings)
        self._check_sensitive_files(findings)
        self._check_dangerous_methods(findings)
        self._check_crlf_injection(findings)
        self._check_host_header_injection(findings)
        
        return {
            "target_url": self.url,
            "findings": findings
        }
Class = VulnScanner
