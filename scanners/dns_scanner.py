import socket

class DNSScanner:
    def __init__(self, target: str):
        self.target = target
        if "://" in target:
            self.host = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            self.host = target.split("/")[0].split(":")[0]

    def scan(self) -> dict:
        findings = []
        dns_records = {}
        
        # Resolve common DNS records using socket (stdlib only)
        # Note: Standard socket getaddrinfo handles host resolution.
        try:
            # 1. Resolve A (IPv4)
            ips_v4 = []
            try:
                addr_info_v4 = socket.getaddrinfo(self.host, None, socket.AF_INET, socket.SOCK_STREAM)
                ips_v4 = list(set([x[4][0] for x in addr_info_v4]))
                dns_records["A"] = ips_v4
            except Exception:
                dns_records["A"] = []

            # 2. Resolve AAAA (IPv6)
            ips_v6 = []
            try:
                addr_info_v6 = socket.getaddrinfo(self.host, None, socket.AF_INET6, socket.SOCK_STREAM)
                ips_v6 = list(set([x[4][0] for x in addr_info_v6]))
                dns_records["AAAA"] = ips_v6
            except Exception:
                dns_records["AAAA"] = []

            # Basic DNS check: verify if A record resolved
            if not dns_records["A"] and not dns_records["AAAA"]:
                findings.append({
                    "module": "DNS Scanner",
                    "target": self.host,
                    "severity": "HIGH",
                    "title": "DNS Host Resolution Failed",
                    "description": f"The host '{self.host}' could not be resolved to any IP address.",
                    "evidence": "No A or AAAA records found.",
                    "remediation": "Check target spelling and DNS zone file configuration."
                })
            else:
                # Private IP address checks (RFC 1918)
                for ip in dns_records["A"]:
                    parts = [int(x) for x in ip.split('.')]
                    is_private = (
                        parts[0] == 10 or
                        (parts[0] == 172 and 16 <= parts[1] <= 31) or
                        (parts[0] == 192 and parts[1] == 168) or
                        parts[0] == 127
                    )
                    if is_private:
                        findings.append({
                            "module": "DNS Scanner",
                            "target": self.host,
                            "severity": "MEDIUM",
                            "title": "Private IP Address Leak in DNS",
                            "description": f"The target resolved to a private RFC 1918 IP address: {ip}.",
                            "evidence": f"A record points to internal address: {ip}",
                            "remediation": "Ensure this is intended (e.g. scanning an internal environment) and that external DNS zones do not leak private network topologies."
                        })
            
            # Reverse DNS lookup (PTR check)
            ptr_record = "None"
            if dns_records["A"]:
                try:
                    ptr_info = socket.gethostbyaddr(dns_records["A"][0])
                    ptr_record = ptr_info[0]
                    dns_records["PTR"] = ptr_record
                except Exception:
                    dns_records["PTR"] = "None"
            else:
                dns_records["PTR"] = "None"

        except Exception as e:
            return {
                "error": f"Error performing DNS lookup: {str(e)}",
                "findings": []
            }

        return {
            "host": self.host,
            "records": dns_records,
            "findings": findings
        }
