import urllib.parse
from bs4 import BeautifulSoup
from utils.helpers import make_web_request

class XSSScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout
        
        # Test payloads representing different injection contexts
        self.payloads = [
            # HTML body context
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            # Attribute context
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            "javascript:alert(1)",
            # Filter evasion polyglots
            "jaVasCript:/*-/*`/*\\'`/*\"'/**/((alert(1)))",
            "<svg><animatetransform onbegin=alert(1)>"
        ]

    def _check_dom_xss(self, html_content: str) -> list:
        """Parses HTML and searches for potential DOM XSS sources and sinks."""
        dom_findings = []
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Search all scripts
        scripts = soup.find_all("script")
        
        dangerous_sinks = ["innerHTML", "document.write", "eval", "setTimeout", "setInterval", "location.href"]
        dangerous_sources = ["location.hash", "location.search", "document.URL", "document.referrer"]
        
        for idx, script in enumerate(scripts):
            script_text = script.string or ""
            found_sources = [src for src in dangerous_sources if src in script_text]
            found_sinks = [sink for sink in dangerous_sinks if sink in script_text]
            
            if found_sources and found_sinks:
                dom_findings.append({
                    "context": f"Script block {idx + 1}",
                    "sources": found_sources,
                    "sinks": found_sinks,
                    "snippet": script_text[:200]
                })
        return dom_findings

    def scan(self, progress_callback=None) -> dict:
        findings = []
        
        try:
            baseline = make_web_request(self.url, timeout=self.timeout)
            baseline_html = baseline.text
        except Exception as e:
            return {
                "error": f"Failed to connect to target to scan XSS: {str(e)}",
                "findings": []
            }
            
        # Parse DOM XSS threats first
        dom_threats = self._check_dom_xss(baseline_html)
        for dt in dom_threats:
            findings.append({
                "module": "XSS Scanner",
                "target": self.url,
                "severity": "MEDIUM",
                "title": "Potential DOM-Based XSS Detected",
                "description": f"The client-side JavaScript utilizes dynamic sources ({', '.join(dt['sources'])}) and outputs to dangerous sinks ({', '.join(dt['sinks'])}) which can facilitate DOM-based Cross-Site Scripting.",
                "evidence": f"Location: {dt['context']}\nSources found: {dt['sources']}\nSinks found: {dt['sinks']}\nSnippet: {dt['snippet']}",
                "remediation": "Avoid using dangerous sinks like innerHTML or eval. Use safe alternatives such as textContent or innerText, and implement robust sanitization using libraries like DOMPurify."
            })

        # Scan parameters for Reflected XSS
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        total_steps = len(params) * len(self.payloads)
        if total_steps == 0:
            # Fallback to test fake parameter
            params = {"q": ["1"]}
            total_steps = len(self.payloads)
            
        step = 0
        for param, values in params.items():
            for payload in self.payloads:
                step += 1
                if progress_callback:
                    progress_callback(step, total_steps)
                    
                test_params = params.copy()
                test_params[param] = [payload]
                
                query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                    parsed_url.params, query, parsed_url.fragment
                ))
                
                try:
                    res = make_web_request(test_url, timeout=self.timeout)
                    # If payload is reflected literally without escaping
                    if payload in res.text:
                        findings.append({
                            "module": "XSS Scanner",
                            "target": test_url,
                            "severity": "HIGH",
                            "title": "Reflected Cross-Site Scripting (XSS) Vulnerability",
                            "description": f"The application reflects untrusted input parameter '{param}' directly back into the response without sanitization or HTML encoding.",
                            "evidence": f"Parameter: {param}\nPayload: {payload}\nReflected in response body: True",
                            "remediation": "Apply context-aware output encoding to all dynamic values printed in HTML body, attributes, and scripts. Utilize Content-Security-Policy headers."
                        })
                        break # Skip remaining payloads for this parameter
                except Exception:
                    pass
                    
        return {
            "target": self.url,
            "findings": findings
        }
Class = XSSScanner
