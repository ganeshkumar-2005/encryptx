from utils.helpers import make_web_request

class HeaderScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout

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
