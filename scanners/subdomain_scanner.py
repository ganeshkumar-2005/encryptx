import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

class SubdomainScanner:
    def __init__(self, target: str, subdomains: list = None):
        self.target = target
        if "://" in target:
            self.domain = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            self.domain = target.split("/")[0].split(":")[0]
        
        # Remove common starting subdomains if present to get root domain
        parts = self.domain.split('.')
        if len(parts) > 2:
            # simple check for multi-level domains (e.g. co.uk)
            if parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
                self.root_domain = ".".join(parts[-3:])
            else:
                self.root_domain = ".".join(parts[-2:])
        else:
            self.root_domain = self.domain

        # Built-in wordlist of common subdomains
        self.subdomains = subdomains or [
            "www", "mail", "ftp", "admin", "blog", "dev", "staging", "api", "test", "portal", 
            "secure", "vpn", "support", "webmail", "shop", "status", "git", "gitlab", "cpanel",
            "dns", "ns1", "ns2", "mx", "docs", "app", "dashboard", "monitor", "beta", "demo",
            "db", "database", "sql", "internal", "intranet", "corp", "m", "news", "static",
            "assets", "images", "cdn", "shop", "store", "forum", "help", "billing", "accounts"
        ]

    def _resolve_subdomain(self, sub: str) -> dict:
        subdomain_url = f"{sub}.{self.root_domain}"
        result = {
            "subdomain": subdomain_url,
            "resolved": False,
            "ip": ""
        }
        try:
            ip = socket.gethostbyname(subdomain_url)
            result["resolved"] = True
            result["ip"] = ip
        except Exception:
            pass
        return result

    def scan(self, progress_callback=None) -> dict:
        discovered = []
        total = len(self.subdomains)
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._resolve_subdomain, sub): sub for sub in self.subdomains}
            
            for index, future in enumerate(as_completed(futures)):
                res = future.result()
                if res["resolved"]:
                    discovered.append(res)
                
                if progress_callback:
                    progress_callback(index + 1, total)

        findings = []
        for d in discovered:
            findings.append({
                "module": "Subdomain Scanner",
                "target": d["subdomain"],
                "severity": "INFO",
                "title": "Discovered Active Subdomain",
                "description": f"The active subdomain '{d['subdomain']}' was discovered via DNS resolution.",
                "evidence": f"Subdomain resolves to IP: {d['ip']}",
                "remediation": "Review the discovered subdomain to ensure it is intended to be active and properly secured. Ensure it is included in your threat modeling and vulnerability management cycles."
            })
            
        return {
            "root_domain": self.root_domain,
            "discovered": discovered,
            "findings": findings
        }
