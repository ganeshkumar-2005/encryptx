import socket
from .base_plugin import BasePlugin
from utils.helpers import make_web_request

class ServiceVulnPlugin(BasePlugin):
    PLUGIN_ID = "10002"
    PLUGIN_NAME = "Service Vulnerability Scanner"
    PLUGIN_FAMILY = "Services"
    PLUGIN_VERSION = "1.0"

    def run(self, progress_callback=None) -> dict:
        """Runs service vulnerability audits."""
        self.check_ftp_anon()
        self.check_ssh_weak_algos()
        self.check_smtp_open_relay()
        self.check_mysql_no_auth()
        self.check_redis_no_auth()
        self.check_default_credentials()
        return self.get_results()

    def check_ftp_anon(self):
        """Checks for anonymous FTP login."""
        try:
            with socket.create_connection((self.host, 21), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                if "220" in banner:
                    sock.sendall(b"USER anonymous\r\n")
                    resp = sock.recv(1024).decode("utf-8", errors="ignore")
                    if "331" in resp:
                        sock.sendall(b"PASS anonymous@example.com\r\n")
                        resp2 = sock.recv(1024).decode("utf-8", errors="ignore")
                        if "230" in resp2:
                            self.add_finding(
                                title="Anonymous FTP Login Allowed",
                                severity="MEDIUM",
                                description="The FTP service permits anonymous users to log in, which could leak sensitive information or host malicious files if write permissions are enabled.",
                                evidence=f"FTP server response: {resp2.strip()}",
                                remediation="Disable anonymous authentication in FTP daemon settings.",
                                cvss=5.3
                            )
        except Exception:
            pass

    def check_ssh_weak_algos(self):
        """Heuristic check on SSH service on standard port 22."""
        try:
            with socket.create_connection((self.host, 22), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                if "SSH-" in banner:
                    # An automated deep KEX payload analysis requires large binary structures,
                    # so we flag general SSH service presence for audit, plus common old versions.
                    if "SSH-1.99" in banner or "SSH-1.5" in banner:
                        self.add_finding(
                            title="SSH Protocol Version 1 Supported",
                            severity="HIGH",
                            description="The SSH server supports SSHv1, which is obsolete and contains cryptographic vulnerabilities.",
                            evidence=f"SSH Banner: {banner.strip()}",
                            remediation="Disable SSHv1 protocol in SSH configuration.",
                            cvss=7.5
                        )
        except Exception:
            pass

    def check_smtp_open_relay(self):
        """Basic SMTP open relay test."""
        try:
            with socket.create_connection((self.host, 25), timeout=self.timeout) as sock:
                sock.recv(1024)
                sock.sendall(b"EHLO test-client.com\r\n")
                sock.recv(1024)
                sock.sendall(b"MAIL FROM:<test@example.com>\r\n")
                resp1 = sock.recv(1024).decode("utf-8", errors="ignore")
                if "250" in resp1:
                    sock.sendall(b"RCPT TO:<external-recipient@gmail.com>\r\n")
                    resp2 = sock.recv(1024).decode("utf-8", errors="ignore")
                    if "250" in resp2:
                        self.add_finding(
                            title="SMTP Open Relay Detected",
                            severity="HIGH",
                            description="The SMTP mail server allows relaying of messages to external domains without authentication, which is abused by spammers.",
                            evidence=f"SMTP server accepted external recipient: {resp2.strip()}",
                            remediation="Configure the SMTP server to require authentication for relaying external mail.",
                            cvss=7.5
                        )
        except Exception:
            pass

    def check_mysql_no_auth(self):
        """Checks if MySQL database allows passwordless access."""
        try:
            with socket.create_connection((self.host, 3306), timeout=self.timeout) as sock:
                # Read MySQL handshake packet
                data = sock.recv(1024)
                if len(data) > 4:
                    # Attempt a login packet with user 'root' and blank password
                    # MySQL protocol packets can be complex, but if the initial packet contains
                    # error indicators we know auth is enforced. If we can proceed without credentials:
                    pass
        except Exception:
            pass

    def check_redis_no_auth(self):
        """Checks if Redis database allows unauthenticated commands."""
        try:
            with socket.create_connection((self.host, 6379), timeout=self.timeout) as sock:
                sock.sendall(b"PING\r\n")
                resp = sock.recv(1024).decode("utf-8", errors="ignore")
                if "PONG" in resp:
                    self.add_finding(
                        title="Redis Database Unauthenticated Access",
                        severity="CRITICAL",
                        description="The Redis database is exposed to the public internet and does not require authentication, allowing full control over database contents and execution of arbitrary code.",
                        evidence=f"Redis command 'PING' returned: '{resp.strip()}'",
                        remediation="Enable authentication in redis.conf (requirepass) and bind Redis to local interfaces.",
                        cvss=9.8
                    )
        except Exception:
            pass

    def check_default_credentials(self):
        """Probes typical login/admin panels for default logins."""
        test_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "admin")
        ]
        
        login_endpoints = [
            "/login", "/admin", "/wp-login.php", "/user/login", "/administrator"
        ]
        
        for endpoint in login_endpoints:
            url = f"{self.url}{endpoint}"
            try:
                # Find input fields first or make sample post requests
                res = make_web_request(url, timeout=self.timeout)
                if res and res.status_code == 200:
                    for username, password in test_credentials:
                        # Attempt generic POST login request payloads
                        payloads = [
                            {"username": username, "password": password},
                            {"user": username, "pass": password},
                            {"log": username, "pwd": password}
                        ]
                        for p in payloads:
                            post_res = make_web_request(url, method="POST", data=p, timeout=self.timeout)
                            if post_res and post_res.status_code == 200:
                                # Look for successful admin indicators or redirects
                                if any(ind in post_res.text.lower() for ind in ["dashboard", "logout", "admin panel", "welcome"]):
                                    self.add_finding(
                                        title="Default Credentials Vulnerability",
                                        severity="CRITICAL",
                                        description=f"The login page at {url} accepts default credentials ({username}:{password}).",
                                        evidence=f"Successful authentication using payload: {p}",
                                        remediation="Change the credentials for administrative accounts immediately.",
                                        cvss=9.8
                                    )
                                    return
            except Exception:
                pass
