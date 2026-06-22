import re
from bs4 import BeautifulSoup, Comment
from utils.helpers import make_web_request

class InfoDisclosureScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout
        
        # Sensitive regex patterns
        self.patterns = {
            "Internal IPv4": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Potential API Key": r'(?:key|api|token|secret|password|db_pass)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,80})["\']'
        }

    def _extract_comments(self, html: str) -> list:
        """Finds HTML comments that might disclose system features or TODOs.
        
        Uses BeautifulSoup's Comment type to properly extract HTML comments
        (<!-- ... -->) rather than string matching, which would miss them.
        """
        soup = BeautifulSoup(html, "html.parser")
        # BeautifulSoup Comment objects contain just the comment text (without <!-- -->)
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        
        findings = []
        for comment in comments:
            comment_text = comment.strip()
            if any(kw in comment_text.lower() for kw in ["todo", "fixme", "pass", "user", "db", "internal", "config"]):
                findings.append(comment_text)
        return findings

    def scan(self, progress_callback=None) -> dict:
        findings = []
        disclosed_info = {}
        
        try:
            res = make_web_request(self.url, timeout=self.timeout)
            html = res.text
        except Exception as e:
            return {
                "error": f"Failed to connect to target to scan info disclosure: {str(e)}",
                "findings": []
            }

        # 1. Regex pattern matching
        total_patterns = len(self.patterns)
        for idx, (name, pattern) in enumerate(self.patterns.items()):
            if progress_callback:
                progress_callback(idx + 1, total_patterns)
                
            matches = list(set(re.findall(pattern, html, re.IGNORECASE)))
            if matches:
                # Truncate and sanitize to avoid writing PII into audit logs
                redacted_matches = [str(m)[:30] + "..." if len(str(m)) > 30 else str(m) for m in matches]
                disclosed_info[name] = redacted_matches
                
                severity = "HIGH" if name == "Potential API Key" else "INFO"
                findings.append({
                    "module": "Information Disclosure Scanner",
                    "target": self.url,
                    "severity": severity,
                    "title": f"Leaked Information: {name}",
                    "description": f"The response body contains patterns indicating leakage of sensitive info: {name}.",
                    "evidence": f"Pattern: {name}\nFound items (redacted): {', '.join(redacted_matches[:5])}",
                    "remediation": "Review page output templates to ensure debugging details, keys, internal database identifiers, and code comments are stripped."
                })

        # 2. Extract HTML Comments
        comments = self._extract_comments(html)
        if comments:
            findings.append({
                "module": "Information Disclosure Scanner",
                "target": self.url,
                "severity": "LOW",
                "title": "Sensitive Code Comments in HTML Source",
                "description": "Developer HTML comments (containing words like TODO, FIXME, internal configuration details, etc.) were leaked in the source code.",
                "evidence": f"Found {len(comments)} sensitive comments.\nSample: {comments[0][:150]}",
                "remediation": "Configure production builds to remove development comments and TODO markers before building templates."
            })
            
        return {
            "target": self.url,
            "disclosed_info": disclosed_info,
            "findings": findings
        }
Class = InfoDisclosureScanner
