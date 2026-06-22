import base64
import json
import hashlib
import hmac
from utils.helpers import make_web_request

class CookieScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout
        
        # Common weak JWT secrets for brute-force check
        self._common_secrets = [
            "secret", "password", "123456", "key", "jwt_secret",
            "changeme", "admin", "test", "default", "token_secret"
        ]

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
                "payload": b64_decode(parts[1]),
                "signature": parts[2]
            }
        except Exception:
            return {}

    def _check_jwt_weak_secret(self, jwt_str: str, jwt_data: dict) -> str:
        """Attempts to verify JWT signature against common weak secrets.
        
        Returns the weak secret if found, empty string otherwise.
        Only works for HS256/HS384/HS512 symmetric algorithms.
        """
        alg = jwt_data.get("header", {}).get("alg", "").upper()
        
        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512
        }
        
        if alg not in hash_map:
            return ""
        
        parts = jwt_str.split('.')
        signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')
        
        # Decode the actual signature from the JWT
        sig_padded = parts[2] + '=' * (4 - len(parts[2]) % 4)
        try:
            actual_sig = base64.urlsafe_b64decode(sig_padded)
        except Exception:
            return ""
        
        for secret in self._common_secrets:
            expected_sig = hmac.new(
                secret.encode('utf-8'),
                signing_input,
                hash_map[alg]
            ).digest()
            if hmac.compare_digest(expected_sig, actual_sig):
                return secret
        return ""

    def scan(self) -> dict:
        findings = []
        cookies_list = []
        
        try:
            res = make_web_request(self.url, timeout=self.timeout)
            
            # Fix: Use raw headers to get ALL Set-Cookie headers.
            # The requests library collapses duplicate headers, so
            # res.headers["Set-Cookie"] only returns the last one.
            # response.raw.headers.getlist() preserves all of them.
            raw_set_cookies = []
            try:
                raw_set_cookies = res.raw.headers.getlist("Set-Cookie")
            except AttributeError:
                # Fallback: iterate headers items (may miss duplicates)
                raw_set_cookies = [v for k, v in res.headers.items() if k.lower() == "set-cookie"]
            
            for header_value in raw_set_cookies:
                # Parse properties manually to audit flags
                cookie_parts = [p.strip() for p in header_value.split(';')]
                cookie_name_val = cookie_parts[0]
                
                if '=' not in cookie_name_val:
                    continue
                    
                name, val = cookie_name_val.split('=', 1)
                
                flags = {
                    "httponly": False,
                    "secure": False,
                    "samesite": None,
                    "domain": None,
                    "path": None
                }
                
                for part in cookie_parts[1:]:
                    part_lower = part.lower().strip()
                    if part_lower == "httponly":
                        flags["httponly"] = True
                    elif part_lower == "secure":
                        flags["secure"] = True
                    elif part_lower.startswith("samesite"):
                        if '=' in part:
                            flags["samesite"] = part.split('=', 1)[1].strip()
                    elif part_lower.startswith("domain"):
                        if '=' in part:
                            flags["domain"] = part.split('=', 1)[1].strip()
                    elif part_lower.startswith("path"):
                        if '=' in part:
                            flags["path"] = part.split('=', 1)[1].strip()
                            
                cookies_list.append({
                    "name": name,
                    "value": val[:20] + "..." if len(val) > 20 else val,
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
                
                # 3. SameSite=None without Secure flag (CSRF risk)
                if flags["samesite"] and flags["samesite"].lower() == "none" and not flags["secure"]:
                    findings.append({
                        "module": "Cookie Security Scanner",
                        "target": self.url,
                        "severity": "HIGH",
                        "title": f"Cookie SameSite=None Without Secure Flag: {name}",
                        "description": f"The cookie '{name}' has SameSite=None but lacks the Secure flag. Modern browsers reject this combination, and it exposes the cookie to cross-site request forgery attacks.",
                        "evidence": f"Set-Cookie: {header_value}",
                        "remediation": "When using SameSite=None, the Secure flag MUST also be set. Consider using SameSite=Lax or SameSite=Strict if cross-site access is not required."
                    })
                
                # 4. Missing SameSite attribute entirely
                if flags["samesite"] is None:
                    findings.append({
                        "module": "Cookie Security Scanner",
                        "target": self.url,
                        "severity": "LOW",
                        "title": f"Cookie Missing SameSite Attribute: {name}",
                        "description": f"The cookie '{name}' does not specify a SameSite attribute. While most modern browsers default to Lax, explicitly setting it is a defense-in-depth best practice.",
                        "evidence": f"Set-Cookie: {header_value}",
                        "remediation": "Set SameSite=Lax or SameSite=Strict on all cookies to prevent cross-site request forgery."
                    })

                # 5. JWT analysis in cookie values
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
                    elif alg.startswith("hs"):
                        # Attempt to crack JWT with common weak secrets
                        weak_secret = self._check_jwt_weak_secret(val, jwt_data)
                        if weak_secret:
                            findings.append({
                                "module": "Cookie Security Scanner",
                                "target": self.url,
                                "severity": "CRITICAL",
                                "title": f"JWT Signed With Weak Secret: {name}",
                                "description": f"The JWT in cookie '{name}' is signed with a commonly-guessable secret ('{weak_secret}'). An attacker can forge arbitrary JWT tokens.",
                                "evidence": f"JWT Algorithm: {alg.upper()}, Weak secret: '{weak_secret}'",
                                "remediation": "Use a cryptographically random secret of at least 256 bits for HMAC-based JWT signing. Consider migrating to RS256 (asymmetric) for better key management."
                            })
                            
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
