import re
from bs4 import BeautifulSoup
from .base_plugin import BasePlugin
from utils.helpers import make_web_request

class CMSPlugin(BasePlugin):
    PLUGIN_ID = "10003"
    PLUGIN_NAME = "CMS Vulnerability Scanner"
    PLUGIN_FAMILY = "Web CMS"
    PLUGIN_VERSION = "1.0"

    def run(self, progress_callback=None) -> dict:
        """Scan target for CMS fingerprints and versions."""
        self.check_wordpress()
        self.check_joomla()
        self.check_drupal()
        return self.get_results()

    def check_wordpress(self):
        """WordPress vulnerability scanner checks."""
        # WordPress indicators
        wp_paths = ["/wp-content/", "/wp-includes/", "/wp-links-opml.php"]
        is_wp = False
        
        # Probe index first
        index_res = make_web_request(self.url, timeout=self.timeout)
        if index_res and index_res.status_code == 200:
            if any(path in index_res.text for path in wp_paths):
                is_wp = True

        if not is_wp:
            return

        version = "Unknown"
        # Try to find generator meta tag
        soup = BeautifulSoup(index_res.text, "html.parser")
        gen_meta = soup.find("meta", attrs={"name": "generator"})
        if gen_meta and "WordPress" in gen_meta.get("content", ""):
            version_match = re.search(r"WordPress\s+([0-9\.]+)", gen_meta["content"])
            if version_match:
                version = version_match.group(1)

        self.add_finding(
            title="WordPress CMS Detected",
            severity="INFO",
            description=f"WordPress CMS was identified on the target host. Version: {version}.",
            evidence=f"WordPress patterns found in page source. Version: {version}",
            remediation="Ensure WordPress core, plugins, and themes are updated regularly.",
            cvss=0.0
        )

        # WP XMLRPC Abuse check
        xmlrpc_url = f"{self.url}/xmlrpc.php"
        xmlrpc_res = make_web_request(xmlrpc_url, timeout=self.timeout)
        if xmlrpc_res and xmlrpc_res.status_code == 200 and "XML-RPC server accepts POST requests" in xmlrpc_res.text:
            self.add_finding(
                title="WordPress XML-RPC Enabled",
                severity="MEDIUM",
                description="WordPress XML-RPC interface is enabled on the server, permitting external APIs to communicate. This can be exploited for brute-force attacks and DDoS amplification.",
                evidence=f"XML-RPC endpoint active at: {xmlrpc_url}",
                remediation="Disable XML-RPC by using a plugin or blocking xmlrpc.php via .htaccess / Nginx config.",
                cve_ids=["CVE-2018-7600"], # Generic XMLRPC DDoS references
                cvss=5.3
            )

        # WP User Enumeration
        user_url = f"{self.url}/wp-json/wp/v2/users"
        user_res = make_web_request(user_url, timeout=self.timeout)
        if user_res and user_res.status_code == 200 and "slug" in user_res.text:
            try:
                users = user_res.json()
                usernames = [u.get("slug") for u in users if "slug" in u]
                if usernames:
                    self.add_finding(
                        title="WordPress Username Enumeration",
                        severity="MEDIUM",
                        description="WordPress REST API exposes user profile details, letting attackers discover valid system login accounts.",
                        evidence=f"Discovered usernames: {', '.join(usernames)} via {user_url}",
                        remediation="Restrict public access to wp-json/wp/v2/users REST API endpoint.",
                        cvss=5.3
                    )
            except Exception:
                pass

    def check_joomla(self):
        """Joomla vulnerability scanner checks."""
        joomla_detected = False
        
        # Test Administrator panel and media assets
        res = make_web_request(f"{self.url}/administrator/", timeout=self.timeout)
        if res and (res.status_code == 200 or "joomla" in res.text.lower()):
            joomla_detected = True

        if not joomla_detected:
            return

        # Check configuration backups
        config_files = ["/configuration.php.bak", "/configuration.php~", "/configuration.php.old"]
        for cfile in config_files:
            cres = make_web_request(f"{self.url}{cfile}", timeout=self.timeout)
            if cres and cres.status_code == 200 and ("$host" in cres.text or "$password" in cres.text):
                self.add_finding(
                    title="Joomla configuration.php Backup Exposed",
                    severity="HIGH",
                    description=f"An exposed Joomla configuration file backup was found at {cfile}. This contains plain-text database credentials.",
                    evidence=f"Found database connection strings in: {self.url}{cfile}",
                    remediation="Delete backup configuration files from the public root folder immediately.",
                    cvss=7.5
                )

    def check_drupal(self):
        """Drupal vulnerability scanner checks."""
        drupal_detected = False
        res = make_web_request(f"{self.url}/core/misc/drupal.js", timeout=self.timeout)
        if res and res.status_code == 200:
            drupal_detected = True
        else:
            # Check headers/meta generator
            idx_res = make_web_request(self.url, timeout=self.timeout)
            if idx_res and "Drupal" in idx_res.text:
                drupal_detected = True

        if not drupal_detected:
            return

        # Try to find version from CHANGELOG.txt
        version = "Unknown"
        changelog_res = make_web_request(f"{self.url}/CHANGELOG.txt", timeout=self.timeout)
        if changelog_res and changelog_res.status_code == 200:
            match = re.search(r"Drupal\s+([0-9\.]+)", changelog_res.text)
            if match:
                version = match.group(1)

        self.add_finding(
            title="Drupal CMS Detected",
            severity="INFO",
            description=f"Drupal CMS was identified. Version: {version}.",
            evidence=f"Drupal JavaScript or metadata observed. Changelog Version: {version}",
            remediation="Keep Drupal core security releases updated.",
            cvss=0.0
        )

        # Check for Drupalgeddon 2 vulnerability (CVE-2018-7600)
        if version != "Unknown":
            try:
                parts = [int(p) for p in version.split(".")]
                is_vulnerable = False
                if len(parts) >= 2:
                    if parts[0] == 7 and parts[1] < 58:
                        is_vulnerable = True
                    elif parts[0] == 8 and parts[1] == 5 and len(parts) >= 3 and parts[2] < 1:
                        is_vulnerable = True
                    elif parts[0] == 8 and parts[1] < 5:
                        is_vulnerable = True
                
                if is_vulnerable:
                    self.add_finding(
                        title="Outdated Drupal Version (Drupalgeddon RCE Vulnerability)",
                        severity="CRITICAL",
                        description=f"The Drupal site version {version} is vulnerable to Drupalgeddon 2 Remote Code Execution.",
                        evidence=f"Version {version} is less than patched core releases (7.58 / 8.5.1).",
                        remediation="Apply latest Drupal core security updates immediately.",
                        cve_ids=["CVE-2018-7600"],
                        cvss=9.8
                    )
            except Exception:
                pass
