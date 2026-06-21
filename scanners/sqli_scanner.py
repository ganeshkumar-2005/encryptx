import time
import urllib.parse
from utils.helpers import make_web_request

class SQLiScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout
        
        # SQL error signatures for error-based SQLi
        self.sql_errors = {
            "MySQL": [
                "SQL syntax", "mysql_fetch", "check the manual that corresponds to your MySQL server version",
                "MySqlClient", "valid MySQL result", "Expression #1 of SELECT list", "Warning: mysqli"
            ],
            "PostgreSQL": [
                "PostgreSQL query failed", "PG::Error", "Warning: pg_", "invalid input syntax for integer",
                "relation", "Severity: ERROR", "Query failed: ERROR: syntax error at or near"
            ],
            "Microsoft SQL Server": [
                "Driver", "SQLServer JDBC Driver", "OLE DB Provider", "Unclosed quotation mark",
                "Microsoft OLE DB Provider for SQL Server", "SQL Server error", "Warning: mssql"
            ],
            "Oracle": [
                "ORA-00933", "ORA-01756", "Oracle error", "Oracle OCI", "Oracle driver",
                "PL/SQL", "Warning: oci_"
            ],
            "SQLite": [
                "SQLite/JDBCDriver", "SQLite.Exception", "System.Data.SQLite.SQLiteException",
                "Warning: sqlite", "sqlite3_"
            ]
        }
        
        # Test payloads
        self.error_payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "1' OR 1=1 --", "1\" OR 1=1 --"]
        self.time_payloads = [
            ("sleep(5)", "MySQL"),
            ("pg_sleep(5)", "PostgreSQL"),
            ("WAITFOR DELAY '0:0:5'", "MSSQL"),
            ("dbms_pipe.receive_message('a',5)", "Oracle")
        ]

    def _fingerprint_db_error(self, body: str) -> str:
        """Determines database type from response body error signatures."""
        for db, errors in self.sql_errors.items():
            for err in errors:
                if err.lower() in body.lower():
                    return db
        return ""

    def scan(self, progress_callback=None) -> dict:
        findings = []
        
        # Get baseline request
        try:
            baseline_start = time.time()
            baseline_res = make_web_request(self.url, timeout=self.timeout)
            baseline_time = time.time() - baseline_start
            baseline_len = len(baseline_res.text)
        except Exception as e:
            return {
                "error": f"Failed to connect to target to scan SQLi: {str(e)}",
                "findings": []
            }

        # Scan URL parameters
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        total_steps = len(params) * (len(self.error_payloads) + len(self.time_payloads))
        if total_steps == 0:
            # Add a fake parameter check if no query parameters exist
            params = {"id": ["1"]}
            total_steps = (len(self.error_payloads) + len(self.time_payloads))
            
        step = 0
        for param, values in params.items():
            # 1. Error-based testing
            for payload in self.error_payloads:
                step += 1
                if progress_callback:
                    progress_callback(step, total_steps)
                    
                # Craft modified query parameters
                test_params = params.copy()
                test_params[param] = [payload]
                
                # Reconstruct query URL
                query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                    parsed_url.params, query, parsed_url.fragment
                ))
                
                try:
                    res = make_web_request(test_url, timeout=self.timeout)
                    db_type = self._fingerprint_db_error(res.text)
                    
                    if db_type:
                        findings.append({
                            "module": "SQL Injection Scanner",
                            "target": test_url,
                            "severity": "CRITICAL",
                            "title": "Error-Based SQL Injection Vulnerability",
                            "description": f"The parameter '{param}' is vulnerable to Error-Based SQL Injection. An database error signature representing {db_type} was observed in the response.",
                            "evidence": f"Parameter: {param}\nPayload: {payload}\nDB Signature: {db_type}\nResponse contains database error string.",
                            "remediation": "Use parameterized queries (prepared statements) for all database operations. Never concatenate untrusted user inputs directly into SQL statements."
                        })
                        break # Found SQLi on parameter, skip further tests on it
                except Exception:
                    pass
            
            # 2. Time-based blind testing (if no error-based SQLi found on parameter)
            if not any(f["target"].startswith(self.url) for f in findings):
                for payload, db in self.time_payloads:
                    step += 1
                    if progress_callback:
                        progress_callback(step, total_steps)
                        
                    test_params = params.copy()
                    test_params[param] = [payload]
                    query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                        parsed_url.params, query, parsed_url.fragment
                    ))
                    
                    try:
                        start_time = time.time()
                        res = make_web_request(test_url, timeout=self.timeout + 6.0)
                        elapsed = time.time() - start_time
                        
                        # Check if request was delayed by approximately 5 seconds
                        # Add buffer for network jitter
                        if elapsed >= 4.8 and elapsed > (baseline_time + 3.0):
                            findings.append({
                                "module": "SQL Injection Scanner",
                                "target": test_url,
                                "severity": "CRITICAL",
                                "title": "Time-Based Blind SQL Injection Vulnerability",
                                "description": f"The parameter '{param}' is vulnerable to Time-Based Blind SQL Injection. The server response was delayed significantly ({elapsed:.2f}s) when injecting sleep payloads.",
                                "evidence": f"Parameter: {param}\nPayload: {payload}\nBaseline Time: {baseline_time:.2f}s\nPayload response time: {elapsed:.2f}s",
                                "remediation": "Implement robust parameterized queries. Use ORMs or predefined stored procedures to strictly enforce separation of data and code."
                            })
                            break
                    except Exception:
                        pass
                        
        return {
            "target": self.url,
            "findings": findings
        }
Class = SQLiScanner
