import socket
import string
import random
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
            # Check for multi-level TLDs (e.g. co.uk, com.au, org.uk, gov.in)
            multi_level_tlds = ("co", "com", "org", "net", "gov", "edu", "ac", "govt", "mil")
            if parts[-2] in multi_level_tlds:
                self.root_domain = ".".join(parts[-3:])
            else:
                self.root_domain = ".".join(parts[-2:])
        else:
            self.root_domain = self.domain

        # Built-in wordlist of common subdomains (deduplicated)
        default_subs = [
            "www", "mail", "ftp", "admin", "blog", "dev", "staging", "api", "test", "portal", 
            "secure", "vpn", "support", "webmail", "shop", "status", "git", "gitlab", "cpanel",
            "dns", "ns1", "ns2", "mx", "docs", "app", "dashboard", "monitor", "beta", "demo",
            "db", "database", "sql", "internal", "intranet", "corp", "m", "news", "static",
            "assets", "images", "cdn", "store", "forum", "help", "billing", "accounts"
        ]
        self.subdomains = subdomains or list(dict.fromkeys(default_subs))  # deduplicate preserving order
        
        # Wildcard detection state
        self._wildcard_ip = None

    def _detect_wildcard(self) -> str:
        """Detect wildcard DNS by resolving a random non-existent subdomain.
        
        If a randomly generated subdomain resolves, the domain has a wildcard
        DNS record (*.domain.com) and all brute-force results would be false positives.
        
        Returns the wildcard IP if detected, empty string otherwise.
        """
        # Generate a random subdomain that almost certainly doesn't exist
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        wildcard_host = f"{random_sub}.{self.root_domain}"
        try:
            ip = socket.gethostbyname(wildcard_host)
            return ip  # Wildcard detected
        except Exception:
            return ""

    def _resolve_subdomain(self, sub: str) -> dict:
        subdomain_url = f"{sub}.{self.root_domain}"
        result = {
            "subdomain": subdomain_url,
            "resolved": False,
            "ip": ""
        }
        try:
            ip = socket.gethostbyname(subdomain_url)
            # If wildcard is active, only count as "resolved" if IP differs from wildcard
            if self._wildcard_ip and ip == self._wildcard_ip:
                return result  # Same as wildcard — likely false positive
            result["resolved"] = True
            result["ip"] = ip
        except Exception:
            pass
        return result

    def scan(self, progress_callback=None) -> dict:
        discovered = []
        total = len(self.subdomains)
        
        # Step 1: Wildcard DNS detection
        self._wildcard_ip = self._detect_wildcard()
        
        findings = []
        if self._wildcard_ip:
            findings.append({
                "module": "Subdomain Scanner",
                "target": self.root_domain,
                "severity": "INFO",
                "title": "Wildcard DNS Record Detected",
                "description": f"The domain '{self.root_domain}' has a wildcard DNS record (*.{self.root_domain}). "
                               f"Non-existent subdomains resolve to {self._wildcard_ip}. "
                               f"Only subdomains resolving to different IPs are reported as genuine discoveries.",
                "evidence": f"Random subdomain resolved to: {self._wildcard_ip}",
                "remediation": "Wildcard DNS records can expose information about infrastructure. Ensure this is intentional."
            })
        
        # Step 2: Enumerate subdomains (filtering out wildcard matches)
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._resolve_subdomain, sub): sub for sub in self.subdomains}
            
            for index, future in enumerate(as_completed(futures)):
                res = future.result()
                if res["resolved"]:
                    discovered.append(res)
                
                if progress_callback:
                    progress_callback(index + 1, total)

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
            "wildcard_detected": bool(self._wildcard_ip),
            "wildcard_ip": self._wildcard_ip or None,
            "discovered": discovered,
            "findings": findings
        }
