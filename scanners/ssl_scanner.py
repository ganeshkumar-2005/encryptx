import socket
import ssl
from datetime import datetime

class SSLScanner:
    def __init__(self, target: str, port: int = 443, timeout: float = 5.0):
        self.target = target
        if "://" in target:
            self.host = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            self.host = target.split("/")[0].split(":")[0]
        self.port = port
        self.timeout = timeout

    def scan(self) -> dict:
        findings = []
        cert_info = {}
        tls_versions_supported = []
        
        # Check if the host resolves/port connects first
        try:
            socket.gethostbyname(self.host)
        except socket.gaierror as e:
            return {
                "error": f"Failed to resolve host for SSL scan: {str(e)}",
                "findings": []
            }

        # Try to establish SSL handshake and extract cert
        context = ssl.create_default_context()
        # Allow checking older protocols to audit security
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            conn = socket.create_connection((self.host, self.port), timeout=self.timeout)
            sock = context.wrap_socket(conn, server_hostname=self.host)
            
            # Get peer certificate
            der_cert = sock.getpeercert(binary_form=True)
            cert = sock.getpeercert()
            
            # Extract TLS connection info
            cipher = sock.cipher()
            tls_version = sock.version()
            
            sock.close()
            
            # Parse cert details
            if cert:
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                # Format Dates: 'Nov 24 23:59:59 2026 GMT'
                not_before_str = cert.get('notBefore')
                not_after_str = cert.get('notAfter')
                
                not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                now = datetime.utcnow()
                
                days_to_expire = (not_after - now).days
                
                cert_info = {
                    "subject": subject.get('commonName', ''),
                    "issuer": issuer.get('commonName', issuer.get('organizationName', '')),
                    "valid_from": not_before.strftime('%Y-%m-%d %H:%M:%S'),
                    "valid_to": not_after.strftime('%Y-%m-%d %H:%M:%S'),
                    "days_to_expire": days_to_expire,
                    "expired": now > not_after,
                    "tls_version": tls_version,
                    "cipher": cipher[0],
                    "cipher_bits": cipher[2]
                }
                
                # Perform security checks
                if cert_info["expired"]:
                    findings.append({
                        "module": "SSL/TLS Scanner",
                        "target": f"{self.host}:{self.port}",
                        "severity": "CRITICAL",
                        "title": "Expired SSL/TLS Certificate",
                        "description": f"The SSL/TLS certificate for {self.host} expired on {cert_info['valid_to']}.",
                        "evidence": f"Expiration date: {cert_info['valid_to']}",
                        "remediation": "Renew the SSL/TLS certificate immediately."
                    })
                elif days_to_expire < 30:
                    findings.append({
                        "module": "SSL/TLS Scanner",
                        "target": f"{self.host}:{self.port}",
                        "severity": "MEDIUM",
                        "title": "SSL/TLS Certificate Expiring Soon",
                        "description": f"The SSL/TLS certificate for {self.host} will expire in {days_to_expire} days.",
                        "evidence": f"Expiration date: {cert_info['valid_to']} ({days_to_expire} days left)",
                        "remediation": "Plan renewal of the SSL/TLS certificate before expiration."
                    })
                    
                # Check for Self-Signed Cert
                if subject.get('commonName') == issuer.get('commonName') and subject.get('commonName') is not None:
                    findings.append({
                        "module": "SSL/TLS Scanner",
                        "target": f"{self.host}:{self.port}",
                        "severity": "HIGH",
                        "title": "Self-Signed SSL/TLS Certificate",
                        "description": "The certificate issuer matches the subject, indicating a self-signed certificate which is untrusted by clients.",
                        "evidence": f"Issuer: {cert_info['issuer']}\nSubject: {cert_info['subject']}",
                        "remediation": "Acquire a certificate from a trusted public Certificate Authority (CA) like Let's Encrypt."
                    })

                # Check TLS protocol version
                # TLS 1.0 or 1.1 are obsolete and insecure
                if tls_version in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "module": "SSL/TLS Scanner",
                        "target": f"{self.host}:{self.port}",
                        "severity": "HIGH",
                        "title": "Insecure TLS Protocol Version Supported",
                        "description": f"The server negotiated {tls_version}. TLS 1.0 and 1.1 are prone to attacks like BEAST and POODLE and lack support for modern cipher suites.",
                        "evidence": f"Negotiated Protocol: {tls_version}",
                        "remediation": "Configure the server to disable TLS 1.0 and 1.1. Only enable TLS 1.2 and TLS 1.3."
                    })
                elif tls_version == "SSLv3" or tls_version == "SSLv2":
                    findings.append({
                        "module": "SSL/TLS Scanner",
                        "target": f"{self.host}:{self.port}",
                        "severity": "CRITICAL",
                        "title": "SSL Protocol Version Supported",
                        "description": f"The server negotiated deprecated protocol {tls_version} which is completely broken and insecure.",
                        "evidence": f"Negotiated Protocol: {tls_version}",
                        "remediation": "Disable SSLv2 and SSLv3 protocols immediately on the server."
                    })

                # Check cipher suite strength
                weak_ciphers = ["RC4", "3DES", "DES", "MD5", "EXPORT", "NULL", "CBC"]
                negotiated_cipher = cipher[0]
                if any(w in negotiated_cipher for w in weak_ciphers):
                    findings.append({
                        "module": "SSL/TLS Scanner",
                        "target": f"{self.host}:{self.port}",
                        "severity": "MEDIUM",
                        "title": "Weak SSL/TLS Cipher Suite Negotiated",
                        "description": f"The server negotiated a cipher suite that includes weak algorithms ({negotiated_cipher}).",
                        "evidence": f"Cipher Suite: {negotiated_cipher}",
                        "remediation": "Update the server cipher configuration to disallow weak ciphers (RC4, 3DES, DES, MD5, and CBC-mode ciphers where possible) and prioritize forward-secrecy cipher suites like ECDHE."
                    })
            else:
                findings.append({
                    "module": "SSL/TLS Scanner",
                    "target": f"{self.host}:{self.port}",
                    "severity": "HIGH",
                    "title": "SSL Connection Active but Certificate Missing",
                    "description": "Handshake succeeded but no certificate details could be extracted.",
                    "evidence": f"Negotiated Version: {tls_version}",
                    "remediation": "Verify server configurations."
                })
                
        except Exception as e:
            # Server might not be running SSL/TLS on port 443
            return {
                "error": f"Failed to negotiate SSL connection: {str(e)}",
                "findings": []
            }

        return {
            "host": self.host,
            "port": self.port,
            "certificate": cert_info,
            "findings": findings
        }
