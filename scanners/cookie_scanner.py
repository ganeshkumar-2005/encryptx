import base64
import json
from utils.helpers import make_web_request

class CookieScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout

    def _decode_jwt(self, jwt_str: str) -> dict:
        """Decodes JWT structure (claims and headers) without verification."""
        try:
            parts = jwt_str.split('.')
            if len(parts) != 3:
                return {}
            # Base64 decode header and payload
            # Pad if necessary
            def b64_decode(s):
                s += '=' * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s).decode('utf-8'))
                
            return {
                "header": b64_decode(parts[0]),
                "payload": b64_decode(parts[1])
            }
        except Exception:
            return {}

    def scan(self) -> dict:
        findings = []
        cookies_list = []
        
        try:
            res = make_web_request(self.url, timeout=self.timeout)
            
            # Extract raw Set-Cookie headers
            # requests handles raw cookies in res.cookies, but we also want raw values
            for header_name, header_value in res.headers.items():
                if header_name.lower() == "set-cookie":
                    # Parse properties manually to audit flags
                    cookie_parts = [p.strip() for p in header_value.split(';')]
                    cookie_name_val = cookie_parts[0]
                    
                    if '=' not in cookie_name_val:
                        continue
                        
                    name, val = cookie_name_val.split('=', 1)
                    
                    flags = {
                        "httponly": False,
                        "secure": False,
                        "samesite": "None"
                    }
                    
                    for part in cookie_parts[1:]:
                        part_lower = part.lower()
                        if part_lower == "httponly":
                            flags["httponly"] = True
                        elif part_lower == "secure":
                            flags["secure"] = True
                        elif part_lower.startswith("samesite"):
                            if '=' in part:
                                flags["samesite"] = part.split('=', 1)[1]
                                
                    cookies_list.append({
                        "name": name,
                        "value": val,
                        "flags": flags
                    })
                    
                    # Security checks per cookie
                    # 1. HttpOnly flag check
                    if not flags["httponly"]:
                        findings.append({
                            "module": "Cookie Security Scanner",
                            "target": self.url,
                            "severity": "MEDIUM",
                            "title": f"Cookie Missing HttpOnly Flag: {name}",
                            "description": f"The cookie '{name}' is missing the HttpOnly flag, which makes it accessible to client-side scripts and increases the threat of session theft via XSS.",
                            "evidence": f"Set-Cookie: {header_value}",
                            "remediation": "Configure your application or framework to set the HttpOnly flag on all cookies, especially session cookies."
                        })
                        
                    # 2. Secure flag check
                    if not flags["secure"]:
                        findings.append({
                            "module": "Cookie Security Scanner",
                            "target": self.url,
                            "severity": "MEDIUM",
                            "title": f"Cookie Missing Secure Flag: {name}",
                            "description": f"The cookie '{name}' is missing the Secure flag, allowing it to be transmitted over cleartext HTTP connections.",
                            "evidence": f"Set-Cookie: {header_value}",
                            "remediation": "Enable the Secure flag on all cookies to ensure they are only sent over encrypted SSL/TLS channels."
                        })

                    # 3. JWT analysis in cookie values
                    jwt_data = self._decode_jwt(val)
                    if jwt_data:
                        alg = jwt_data.get("header", {}).get("alg", "").lower()
                        if alg == "none":
                            findings.append({
                                "module": "Cookie Security Scanner",
                                "target": self.url,
                                "severity": "CRITICAL",
                                "title": "JWT Cookie Permissive 'none' Algorithm Allowed",
                                "description": f"The cookie '{name}' contains a JSON Web Token that accepts the 'none' signature algorithm, which could allow signature verification bypass.",
                                "evidence": f"JWT Header: {jwt_data['header']}",
                                "remediation": "Do not accept JWTs with the 'none' algorithm. Configure JWT verification libraries to strictly require signed algorithms like RS256 or HS256."
                            })
                        elif "hs" in alg:
                            # Warn about symmetric signatures if key length is not auditable
                            pass
                            
        except Exception as e:
            return {
                "error": f"Failed to connect to target to scan cookies: {str(e)}",
                "findings": []
            }
            
        return {
            "target": self.url,
            "cookies": cookies_list,
            "findings": findings
        }
Class = CookieScanner
