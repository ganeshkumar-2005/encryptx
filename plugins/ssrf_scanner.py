import urllib.parse
from .base_plugin import BasePlugin
from utils.helpers import make_web_request

class SSRFPlugin(BasePlugin):
    PLUGIN_ID = "10007"
    PLUGIN_NAME = "SSRF & Path Traversal Scanner"
    PLUGIN_FAMILY = "Web Application"
    PLUGIN_VERSION = "1.0"

    def run(self, progress_callback=None) -> dict:
        """Scan for SSRF, LFI, and Path Traversal vulnerabilities."""
        self.scan_parameters()
        return self.get_results()

    def scan_parameters(self):
        """Probes common URL parameters for SSRF and Path Traversal vulnerabilities."""
        # Find parameters in URL
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)

        # If target has no query params, test typical endpoints/parameter names on target
        if not params:
            test_params = ["file", "path", "page", "url", "link", "dest", "redirect", "file_name"]
            for param in test_params:
                self.check_param_vulnerabilities(self.url, param)
        else:
            for param in params.keys():
                self.check_param_vulnerabilities(self.url, param)

    def check_param_vulnerabilities(self, base_url: str, param_name: str):
        """Tests individual query parameter with path traversal, LFI and SSRF payloads."""
        
        # 1. Path Traversal & LFI Payloads
        traversal_payloads = [
            ("../../../etc/passwd", ["root:x:", "bin/bash"]),
            ("..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]"]),
            ("....//....//....//etc/passwd", ["root:x:", "bin/bash"]),
            ("etc/passwd", ["root:x:"])
        ]
        
        for payload, signatures in traversal_payloads:
            test_url = self.build_test_url(base_url, param_name, payload)
            try:
                res = make_web_request(test_url, timeout=self.timeout)
                if res and res.status_code == 200:
                    if any(sig in res.text for sig in signatures):
                        self.add_finding(
                            title=f"Path Traversal / Local File Inclusion ({param_name})",
                            severity="HIGH",
                            description=f"The parameter '{param_name}' is vulnerable to Path Traversal, allowing arbitrary file read.",
                            evidence=f"Payload: {payload} returned system file content signatures.",
                            remediation=f"Sanitize parameter '{param_name}' input by allowing only strict alphanumeric values, or use a safe lookup map.",
                            cvss=7.5
                        )
                        break
            except Exception:
                pass

        # 2. Null Byte Injection test
        null_byte_payloads = [
            ("../../../etc/passwd%00.png", ["root:x:"]),
            ("..\\..\\..\\windows\\win.ini%00.jpg", ["[extensions]"])
        ]
        for payload, signatures in null_byte_payloads:
            test_url = self.build_test_url(base_url, param_name, payload)
            try:
                res = make_web_request(test_url, timeout=self.timeout)
                if res and res.status_code == 200:
                    if any(sig in res.text for sig in signatures):
                        self.add_finding(
                            title=f"Null Byte Injection / Path Bypass ({param_name})",
                            severity="MEDIUM",
                            description=f"The parameter '{param_name}' is susceptible to Null Byte injection, which bypasses file extension checks.",
                            evidence=f"Payload: {payload} bypassed filter and returned file contents.",
                            remediation=f"Upgrade server runtime to reject null byte characters (%00 or \\x00) in input parameters.",
                            cve_ids=[],
                            cvss=6.5
                        )
                        break
            except Exception:
                pass

        # 3. SSRF Payloads
        ssrf_payloads = [
            ("http://127.0.0.1", ["localhost", "127.0.0.1", "index", "home"]),
            ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "security-groups"]),
            ("http://localhost", ["localhost", "127.0.0.1"])
        ]
        
        for payload, signatures in ssrf_payloads:
            test_url = self.build_test_url(base_url, param_name, payload)
            try:
                res = make_web_request(test_url, timeout=self.timeout)
                if res and res.status_code == 200:
                    if any(sig in res.text for sig in signatures):
                        self.add_finding(
                            title=f"Server-Side Request Forgery (SSRF) ({param_name})",
                            severity="CRITICAL",
                            description=f"The parameter '{param_name}' is vulnerable to SSRF, allowing attackers to force the server to connect to internal hosts.",
                            evidence=f"Payload: {payload} resolved internal host components.",
                            remediation=f"Do not allow arbitrary URLs to be passed to '{param_name}'. Whitelist permitted external target domains instead.",
                            cvss=9.1
                        )
                        break
            except Exception:
                pass

    def build_test_url(self, base_url: str, param: str, value: str) -> str:
        """Injects test value into URL query parameter."""
        parsed = urllib.parse.urlparse(base_url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        # Reconstruct query
        new_query = urllib.parse.urlencode(params, doseq=True)
        # Build final URL
        new_parsed = parsed._replace(query=new_query)
        if not new_parsed.query:
            # If base URL had no query, append parameter manually
            return f"{base_url}?{param}={urllib.parse.quote(value)}"
        return urllib.parse.urlunparse(new_parsed)
