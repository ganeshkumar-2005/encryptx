"""
BasePlugin - Abstract base class for all EncryptX plugins.
Every plugin must inherit from this class and implement the run() method.
Modeled after Nessus plugin architecture with CVE references, CVSS scoring,
and standardized finding output format.
"""
from abc import ABC, abstractmethod
from datetime import datetime


class BasePlugin(ABC):
    """Base class that all EncryptX plugins must inherit from."""
    
    # Plugin metadata - override in subclass
    PLUGIN_ID = "0000"
    PLUGIN_NAME = "Base Plugin"
    PLUGIN_FAMILY = "General"
    PLUGIN_VERSION = "1.0"
    RISK_FACTOR = "INFO"         # CRITICAL, HIGH, MEDIUM, LOW, INFO
    CVSS_SCORE = 0.0             # 0.0 - 10.0
    CVE_IDS = []                 # List of CVE identifiers
    DESCRIPTION = ""
    SOLUTION = ""

    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout
        self.findings = []
        
        # Normalize target
        if "://" in target:
            self.host = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            self.host = target.split("/")[0].split(":")[0]
            
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target

    def add_finding(self, title: str, severity: str, description: str,
                    evidence: str = "", remediation: str = "",
                    cve_ids: list = None, cvss: float = None,
                    plugin_id: str = None):
        """Registers a standardized finding from this plugin."""
        self.findings.append({
            "module": f"Plugin: {self.PLUGIN_NAME}",
            "plugin_id": plugin_id or self.PLUGIN_ID,
            "plugin_family": self.PLUGIN_FAMILY,
            "target": self.url,
            "severity": severity.upper(),
            "title": title,
            "description": description,
            "evidence": evidence,
            "remediation": remediation or self.SOLUTION,
            "cve_ids": cve_ids or [],
            "cvss_score": cvss or self.CVSS_SCORE,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    @abstractmethod
    def run(self, progress_callback=None) -> dict:
        """
        Execute the plugin scan. Must be implemented by all subclasses.
        
        Returns:
            dict with keys:
                - 'plugin_name': str
                - 'plugin_family': str  
                - 'findings': list of finding dicts
                - 'error': str (optional, if scan failed)
        """
        pass

    def get_results(self) -> dict:
        """Returns standardized results after run() completes."""
        return {
            "plugin_id": self.PLUGIN_ID,
            "plugin_name": self.PLUGIN_NAME,
            "plugin_family": self.PLUGIN_FAMILY,
            "plugin_version": self.PLUGIN_VERSION,
            "target": self.url,
            "findings": self.findings
        }

    @staticmethod
    def cvss_to_severity(score: float) -> str:
        """Converts a CVSS 3.1 score to a severity label."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        return "INFO"
