import re
from utils.helpers import make_web_request

class TechFingerprinter:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout
        
        # Simple local database mapping software signatures and versions to critical CVEs
        # (simulates CVE lookup for top 10 most common server packages)
        self.cve_database = {
            "Apache/2.4.49": [
                {"id": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49."}
            ],
            "Apache/2.4.50": [
                {"id": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Path traversal and remote code execution in Apache HTTP Server 2.4.50."}
            ],
            "nginx/1.18.0": [
                {"id": "CVE-2021-23017", "severity": "HIGH", "desc": "1-byte memory overwrite in resolver module."}
            ],
            "WordPress/6.0": [
                {"id": "CVE-2022-21661", "severity": "HIGH", "desc": "SQL injection vulnerability via WP_Query."}
            ],
            "PHP/8.1.0-dev": [
                {"id": "RCE-Backdoor", "severity": "CRITICAL", "desc": "User-Agentt backdoor RCE signature."}
            ]
        }

    def scan(self) -> dict:
        findings = []
        technologies = {}
        
        try:
            res = make_web_request(self.url, timeout=self.timeout)
            headers = {k.lower(): v for k, v in res.headers.items()}
            html = res.text
        except Exception as e:
            return {
                "error": f"Failed to connect to target to scan technology: {str(e)}",
                "findings": []
            }
            
        # 1. Header fingerprinting
        # Server header
        server = headers.get("server", "")
        if server:
            technologies["Server"] = server
            
        # X-Powered-By
        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            technologies["Framework"] = x_powered
            
        # Set-Cookie identifiers
        set_cookie = headers.get("set-cookie", "")
        if "PHPSESSID" in set_cookie:
            technologies["Language"] = "PHP"
        elif "JSESSIONID" in set_cookie:
            technologies["Language"] = "Java"
        elif "session" in set_cookie:
            pass # general session cookie

        # 2. HTML/Meta Tag/JS fingerprinting
        # WordPress check
        if "wp-content" in html or "wp-includes" in html:
            version_match = re.search(r'generator" content="WordPress\s?([0-9\.]+)"', html, re.IGNORECASE)
            version = version_match.group(1) if version_match else "Unknown"
            technologies["CMS"] = f"WordPress/{version}"
            
        # jQuery check
        if "jquery" in html.lower():
            jquery_match = re.search(r'jquery[a-zA-Z0-9\.\-]*\.js', html, re.IGNORECASE)
            technologies["JS Library"] = "jQuery"
            
        # React/Angular check
        if "react" in html.lower() or "data-reactroot" in html:
            technologies["Frontend Framework"] = "React"
        elif "ng-app" in html or "angular" in html.lower():
            technologies["Frontend Framework"] = "Angular"

        # Check CVE database for match
        for category, tech_val in technologies.items():
            for vuln_key, cves in self.cve_database.items():
                if vuln_key.lower() in tech_val.lower():
                    for cve in cves:
                        findings.append({
                            "module": "Technology Fingerprinter",
                            "target": self.url,
                            "severity": cve["severity"],
                            "title": f"Known CVE Found in {category}: {cve['id']}",
                            "description": f"The detected software version '{tech_val}' matches a signature with known vulnerabilities: {cve['desc']}",
                            "evidence": f"Detected technology: {tech_val}\nCVE Identifier: {cve['id']}\nSeverity: {cve['severity']}",
                            "remediation": "Update the affected software module or server daemon to the latest secure vendor release."
                        })
                        
        return {
            "url": self.url,
            "technologies": technologies,
            "findings": findings
        }
Class = TechFingerprinter
