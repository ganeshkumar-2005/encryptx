from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.helpers import make_web_request

class AuthScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout
        
        # Admin paths list
        self.admin_paths = [
            "admin", "administrator", "wp-admin", "login", "admin/login",
            "dashboard", "manage", "portal", "cpanel", "phpmyadmin",
            "wp-login.php", "user/login", "auth/login", "signin", "controlpanel"
        ]

    def _test_path(self, path: str) -> dict:
        test_url = f"{self.url}/{path}" if not self.url.endswith('/') else f"{self.url}{path}"
        result = {
            "path": path,
            "url": test_url,
            "exists": False,
            "status_code": 0
        }
        try:
            res = make_web_request(test_url, timeout=self.timeout)
            if res.status_code in (200, 301, 302, 401):
                result["exists"] = True
                result["status_code"] = res.status_code
        except Exception:
            pass
        return result

    def scan(self, progress_callback=None) -> dict:
        findings = []
        discovered_panels = []
        total = len(self.admin_paths)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._test_path, path): path for path in self.admin_paths}
            
            for index, future in enumerate(as_completed(futures)):
                res = future.result()
                if res["exists"]:
                    discovered_panels.append(res)
                if progress_callback:
                    progress_callback(index + 1, total)
                    
        for p in discovered_panels:
            findings.append({
                "module": "Authentication & Admin Scanner",
                "target": p["url"],
                "severity": "MEDIUM",
                "title": f"Exposed Administrative Portal / Login Panel: /{p['path']}",
                "description": f"An exposed administrative path or login form was discovered on the server. Publicly accessible login endpoints increase susceptibility to brute-force attacks.",
                "evidence": f"Path: /{p['path']}\nStatus returned: {p['status_code']}",
                "remediation": "Restrict access to management interfaces using IP access lists, VPN connection mandates, or obscure paths."
            })
            
        return {
            "target": self.url,
            "panels": discovered_panels,
            "findings": findings
        }
Class = AuthScanner
