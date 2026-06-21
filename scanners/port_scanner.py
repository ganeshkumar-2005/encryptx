import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class PortScanner:
    def __init__(self, target: str, ports: list = None, timeout: float = 2.0):
        # Extract host or IP
        self.target = target
        if "://" in target:
            self.target = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            self.target = target.split("/")[0].split(":")[0]
            
        self.ports = ports or [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        self.timeout = timeout
        self.common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "Microsoft-DS",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            9200: "Elasticsearch", 27017: "MongoDB"
        }

    def _grab_banner(self, sock: socket.socket) -> str:
        """Attempts basic banner grabbing from open socket."""
        try:
            # Send a basic probe if needed, or just read
            sock.settimeout(1.5)
            # Many protocols (SSH, FTP, SMTP) send banner immediately on connect
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                return banner
            # Try HTTP probe
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if "Server:" in banner:
                for line in banner.split("\r\n"):
                    if line.startswith("Server:"):
                        return line
            return ""
        except Exception:
            return ""

    def _scan_port(self, port: int) -> dict:
        """Scans a single port and returns status."""
        result = {
            "port": port,
            "status": "closed",
            "service": self.common_services.get(port, "Unknown"),
            "banner": "",
            "severity": "INFO"
        }
        
        try:
            # Determine IP family
            addr_info = socket.getaddrinfo(self.target, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, socktype, proto, canonname, sockaddr in addr_info:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(self.timeout)
                conn = sock.connect_ex(sockaddr)
                if conn == 0:
                    result["status"] = "open"
                    result["banner"] = self._grab_banner(sock)
                    # Evaluate risk based on open critical ports
                    if port in [21, 23]: # FTP, Telnet cleartext
                        result["severity"] = "HIGH"
                    elif port in [22, 135, 139, 445, 1433, 3306, 3389]: # Remote administration/DBs
                        result["severity"] = "MEDIUM"
                    elif port in [80, 443]:
                        result["severity"] = "INFO"
                    else:
                        result["severity"] = "LOW"
                    sock.close()
                    break
                sock.close()
        except Exception:
            pass
            
        return result

    def scan(self, progress_callback=None) -> dict:
        """Concurrently scans target ports."""
        open_ports = []
        closed_count = 0
        total_ports = len(self.ports)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self._scan_port, port): port for port in self.ports}
            
            for index, future in enumerate(as_completed(futures)):
                res = future.result()
                if res["status"] == "open":
                    open_ports.append(res)
                else:
                    closed_count += 1
                
                if progress_callback:
                    progress_callback(index + 1, total_ports)
                    
        elapsed = time.time() - start_time
        
        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])
        
        # Formulate findings
        findings = []
        for p in open_ports:
            findings.append({
                "module": "Port Scanner",
                "target": f"{self.target}:{p['port']}",
                "severity": p["severity"],
                "title": f"Open Port Detected ({p['port']}/{p['service']})",
                "description": f"Port {p['port']} running {p['service']} is open on the target host.",
                "evidence": f"Service: {p['service']}\nBanner: {p['banner'] or 'None captured'}",
                "remediation": f"Ensure this port is firewalled and not exposed to the public internet unless required. "
                               f"If running, ensure it uses secure credentials and up-to-date software versions."
            })
            
        return {
            "elapsed_seconds": elapsed,
            "open_ports": open_ports,
            "closed_ports_count": closed_count,
            "findings": findings
        }
Class = PortScanner
