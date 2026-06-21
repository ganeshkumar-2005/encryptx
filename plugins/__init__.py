"""
EncryptX Advanced Plugin System
Nessus-style plugin architecture for deep vulnerability scanning.
"""
from .base_plugin import BasePlugin
from .ssl_vulns import SSLVulnPlugin
from .service_vulns import ServiceVulnPlugin
from .cms_scanner import CMSPlugin
from .network_vulns import NetworkVulnPlugin
from .compliance import CompliancePlugin
from .subdomain_takeover import SubdomainTakeoverPlugin
from .ssrf_scanner import SSRFPlugin

# Plugin registry - all available plugins
PLUGIN_REGISTRY = {
    "ssl": {
        "class": SSLVulnPlugin,
        "name": "SSL/TLS Vulnerability Scanner",
        "description": "Checks for Heartbleed, POODLE, BEAST, DROWN, FREAK, CRIME"
    },
    "services": {
        "class": ServiceVulnPlugin,
        "name": "Service Vulnerability Scanner",
        "description": "FTP anon, SSH weak algos, SMTP relay, DB no-auth checks"
    },
    "cms": {
        "class": CMSPlugin,
        "name": "CMS Vulnerability Scanner",
        "description": "WordPress, Joomla, Drupal specific vulnerability detection"
    },
    "network": {
        "class": NetworkVulnPlugin,
        "name": "Network Vulnerability Scanner",
        "description": "DNS zone transfer, SNMP community, SMB signing checks"
    },
    "compliance": {
        "class": CompliancePlugin,
        "name": "Compliance & Scoring Engine",
        "description": "OWASP Top 10 mapping, PCI-DSS checks, A-F security grading"
    },
    "takeover": {
        "class": SubdomainTakeoverPlugin,
        "name": "Subdomain Takeover Scanner",
        "description": "Dangling CNAME, cloud provider takeover detection"
    },
    "ssrf": {
        "class": SSRFPlugin,
        "name": "SSRF & Path Traversal Scanner",
        "description": "SSRF, LFI/RFI, path traversal, null byte injection"
    }
}

def get_plugin(name: str, target: str, **kwargs):
    """Instantiates and returns a plugin by registry name."""
    if name not in PLUGIN_REGISTRY:
        raise ValueError(f"Unknown plugin: '{name}'. Available: {list(PLUGIN_REGISTRY.keys())}")
    return PLUGIN_REGISTRY[name]["class"](target, **kwargs)

def list_plugins() -> list:
    """Returns list of all registered plugins with metadata."""
    return [
        {"id": k, "name": v["name"], "description": v["description"]}
        for k, v in PLUGIN_REGISTRY.items()
    ]

__all__ = [
    'BasePlugin', 'SSLVulnPlugin', 'ServiceVulnPlugin', 'CMSPlugin',
    'NetworkVulnPlugin', 'CompliancePlugin', 'SubdomainTakeoverPlugin',
    'SSRFPlugin', 'PLUGIN_REGISTRY', 'get_plugin', 'list_plugins'
]
