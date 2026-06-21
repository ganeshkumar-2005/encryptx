import urllib.parse
from utils.helpers import make_web_request

class WAFDetector:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout
        
        # WAF signatures based on headers
        self.waf_signatures = {
            "Cloudflare": [("cf-ray", "*"), ("server", "cloudflare"), ("__cfduid", "*")],
            "AWS WAF": [("x-amz-id-2", "*"), ("x-amz-request-id", "*"), ("server", "awselb")],
            "ModSecurity / OWASP CRS": [("server", "mod_security"), ("x-powered-by", "mod_security")],
            "Imperva / Incapsula": [("x-iinfo", "*"), ("visid_incap", "*"), ("server", "incapsula")],
            "Akamai": [("server", "akamaiGHost"), ("x-akamai-transformed", "*")]
        }

    def scan(self) -> dict:
        findings = []
        detected_waf = "None"
        confidence = "Low"
        
        try:
            # 1. Passive detection
            res = make_web_request(self.url, timeout=self.timeout)
            headers = {k.lower(): v.lower() for k, v in res.headers.items()}
            
            for waf_name, sigs in self.waf_signatures.items():
                match_count = 0
                for h_name, h_val in sigs:
                    if h_name in headers:
                        if h_val == "*" or h_val in headers[h_name]:
                            match_count += 1
                if match_count > 0:
                    detected_waf = waf_name
                    confidence = "High" if match_count >= len(sigs) or match_count > 1 else "Medium"
                    break
                    
            # 2. Active probing (Send a simulated malicious request to trigger WAF)
            if detected_waf == "None":
                # Try SQLi / XSS string in URL parameter to trigger blocking page
                test_url = f"{self.url}?test=<script>alert(1)</script> OR 1=1"
                try:
                    res_probe = make_web_request(test_url, timeout=self.timeout)
                    # Check for classic block codes (403, 406, 501, 999)
                    if res_probe.status_code in (403, 406, 999):
                        detected_waf = "Generic WAF/IDS"
                        confidence = "Medium"
                        # Check block body for specific signatures
                        body = res_probe.text.lower()
                        if "cloudflare" in body:
                            detected_waf = "Cloudflare"
                            confidence = "High"
                        elif "sucuri" in body:
                            detected_waf = "Sucuri WAF"
                            confidence = "High"
                        elif "mod_security" in body or "modsecurity" in body:
                            detected_waf = "ModSecurity"
                            confidence = "High"
                except Exception:
                    pass
                    
            if detected_waf != "None":
                findings.append({
                    "module": "WAF Detector",
                    "target": self.url,
                    "severity": "INFO",
                    "title": f"Web Application Firewall (WAF) Detected: {detected_waf}",
                    "description": f"A Web Application Firewall (WAF) or CDN security layer was identified protecting the target host.",
                    "evidence": f"WAF: {detected_waf}\nConfidence: {confidence}",
                    "remediation": "No remediation required. The presence of a WAF improves security posture, but audit scanners must bypass or work with WAF configurations during testing."
                })
                
        except Exception as e:
            return {
                "error": f"Failed to connect to target for WAF detection: {str(e)}",
                "findings": []
            }
            
        return {
            "target": self.url,
            "waf_detected": detected_waf,
            "confidence": confidence,
            "findings": findings
        }
Class = WAFDetector
