import socket
import struct
from .base_plugin import BasePlugin

class NetworkVulnPlugin(BasePlugin):
    PLUGIN_ID = "10004"
    PLUGIN_NAME = "Network Vulnerability Scanner"
    PLUGIN_FAMILY = "Network"
    PLUGIN_VERSION = "1.0"

    def run(self, progress_callback=None) -> dict:
        """Runs network-level vulnerability checks."""
        self.check_dns_zone_transfer()
        self.check_snmp_default_community()
        self.check_smb_signing()
        self.check_ntp_amplification()
        self.check_exposed_databases()
        return self.get_results()

    def check_dns_zone_transfer(self):
        """Attempts a DNS zone transfer (AXFR) query manually."""
        try:
            # Build manual DNS query AXFR header
            # Transaction ID: 0x1234, Flags: 0x0000 (Standard Query)
            # Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
            dns_header = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
            
            # Format target domain for query (e.g. example.com -> \x07example\x03com\x00)
            domain_parts = self.host.split(".")
            query_name = b""
            for part in domain_parts:
                query_name += struct.pack("B", len(part)) + part.encode("ascii")
            query_name += b"\x00"
            
            # AXFR Type (252), Class IN (1)
            dns_question = query_name + struct.pack(">HH", 252, 1)
            packet = dns_header + dns_question
            # DNS TCP packets are prefixed with a 2-byte length
            tcp_packet = struct.pack(">H", len(packet)) + packet
            
            with socket.create_connection((self.host, 53), timeout=self.timeout) as sock:
                sock.sendall(tcp_packet)
                resp_len_data = sock.recv(2)
                if len(resp_len_data) == 2:
                    resp_len = struct.unpack(">H", resp_len_data)[0]
                    resp = sock.recv(resp_len)
                    # If server returns zone answers (AXFR response usually contains SOA records)
                    # We check if it is not REFUSED (DNS RCODE 5)
                    if len(resp) > 4:
                        flags = struct.unpack(">H", resp[2:4])[0]
                        rcode = flags & 0x000F
                        if rcode == 0:  # No Error - Zone Transfer accepted!
                            self.add_finding(
                                title="DNS Zone Transfer (AXFR) Enabled",
                                severity="MEDIUM",
                                description="The DNS server on this host allows full AXFR zone transfers to unauthorized IPs. Attackers can enumerate all records.",
                                evidence="DNS TCP server responded to AXFR query with RCODE 0 (Success).",
                                remediation="Configure the DNS server to allow zone transfers only to trusted secondary DNS servers (e.g., allow-transfer configuration).",
                                cvss=5.3
                            )
        except Exception:
            pass

    def check_snmp_default_community(self):
        """Probes UDP port 161 with default public community string."""
        # Simple SNMPv1 GetRequest packet for sysDescr (1.3.6.1.2.1.1.1.0)
        # using community string 'public'
        snmp_public_probe = b"\x30\x29\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1c\x02\x04\x05\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(snmp_public_probe, (self.host, 161))
                resp, _ = sock.recvfrom(1024)
                if len(resp) > 0:
                    self.add_finding(
                        title="SNMP Default Community String 'public' Exposed",
                        severity="HIGH",
                        description="The SNMP service is running with the default community string 'public', allowing read access to system properties.",
                        evidence="SNMP service replied to public community query.",
                        remediation="Disable SNMP if not needed, or change default community string to a strong, secret value.",
                        cvss=7.5
                    )
        except Exception:
            pass

    def check_smb_signing(self):
        """Checks if SMB signing is not required on port 445."""
        # Minimal NetBIOS Session Request & SMB Negotiate Protocol
        smb_negotiate = (
            b"\x00\x00\x00\x85"  # NetBIOS length
            b"\xff\x53\x4d\x42"  # SMB Header magic
            b"\x72"              # Negotiate Command
            b"\x00\x00\x00\x00"  # Status
            b"\x18"              # Flags
            b"\x53\xc8"          # Flags2
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\xff\xff"
            b"\x00\x00"
            b"\x00\x00"          # Mid
            b"\x00\x62"          # Byte count
            b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00" # NT LM 0.12 dialect
        )
        try:
            with socket.create_connection((self.host, 445), timeout=self.timeout) as sock:
                sock.sendall(smb_negotiate)
                resp = sock.recv(1024)
                if len(resp) > 37:
                    # Security Mode is at offset 37 of negotiate response
                    security_mode = resp[37]
                    # Bit 2 (0x04) in Security Mode: Signing Required
                    signing_required = (security_mode & 0x04) != 0
                    if not signing_required:
                        self.add_finding(
                            title="SMB Signing Not Required",
                            severity="MEDIUM",
                            description="SMB signing is not enforced on this server. This permits attackers on the same network layer to perform SMB relay attacks.",
                            evidence="SMB security mode flag check: signing is supported but not required.",
                            remediation="Enable SMB signing policy: 'Microsoft network server: Digitally sign communications (always)'.",
                            cvss=5.3
                        )
        except Exception:
            pass

    def check_ntp_amplification(self):
        """Checks if NTP monlist command is enabled on UDP port 123."""
        # NTP v2 Mode 7 (Private) Request - Command: MON_GETLIST (42)
        ntp_monlist_payload = struct.pack("!BBBBHHH", 0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(ntp_monlist_payload, (self.host, 123))
                resp, _ = sock.recvfrom(1024)
                if len(resp) > 4:
                    self.add_finding(
                        title="NTP monlist Command Enabled (DDoS Amplification)",
                        severity="MEDIUM",
                        description="The NTP server responds to 'monlist' queries, allowing remote attackers to retrieve active client lists and amplify traffic in DDoS attacks.",
                        evidence="NTP server returned monlist response to UDP request.",
                        remediation="Disable monlist support by updating NTP daemon config or restricting access via firewall.",
                        cvss=5.3
                    )
        except Exception:
            pass

    def check_exposed_databases(self):
        """Scans for database ports exposed directly to the internet."""
        db_ports = {
            3306: "MySQL Database",
            5432: "PostgreSQL Database",
            27017: "MongoDB Database",
            1521: "Oracle Database",
            1433: "Microsoft SQL Server"
        }
        for port, name in db_ports.items():
            try:
                with socket.create_connection((self.host, port), timeout=2.0) as sock:
                    self.add_finding(
                        title=f"Exposed Database Service ({name})",
                        severity="HIGH",
                        description=f"The database port ({port}) is open and listening publicly, leaving it prone to brute force attacks.",
                        evidence=f"Exposed listening socket on port {port}",
                        remediation="Filter the database port to localhost or restrict connection access using network firewall rules.",
                        cvss=7.5
                    )
            except Exception:
                pass
