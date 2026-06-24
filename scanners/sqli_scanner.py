import time
import urllib.parse
from utils.helpers import make_web_request
from .crawler import Crawler

class SQLiScanner:
    def __init__(self, target: str, discovered_urls: list = None, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.discovered_urls = discovered_urls or []
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
        # Confirmation payloads use a shorter delay (2s) to rule out network jitter
        self.time_confirm_payloads = {
            "MySQL": "sleep(2)",
            "PostgreSQL": "pg_sleep(2)",
            "MSSQL": "WAITFOR DELAY '0:0:2'",
            "Oracle": "dbms_pipe.receive_message('a',2)"
        }

    def _fingerprint_db_error(self, body: str) -> str:
        """Determines database type from response body error signatures."""
        for db, errors in self.sql_errors.items():
            for err in errors:
                if err.lower() in body.lower():
                    return db
        return ""

    def _scan_url(self, url: str, baseline_time: float, findings: list):
        """Scans a single URL with parameters for Error-Based and Time-Based SQLi."""
        if not hasattr(self, 'confirmed_params'):
            self.confirmed_params = set()
        if not hasattr(self, 'current_step'):
            self.current_step = 0
        if not hasattr(self, 'total_steps'):
            self.total_steps = 1
        if not hasattr(self, 'progress_callback'):
            self.progress_callback = None

        parsed = urllib.parse.urlparse(url)
        current_params = urllib.parse.parse_qs(parsed.query)

        for param, values in current_params.items():
            if param in self.confirmed_params:
                # Skip testing parameter if we already proved it vulnerable
                self.current_step += (len(self.error_payloads) + len(self.time_payloads))
                if self.progress_callback:
                    self.progress_callback(self.current_step, self.total_steps)
                continue

            # 1. Error-based testing
            for payload in self.error_payloads:
                self.current_step += 1
                if self.progress_callback:
                    self.progress_callback(self.current_step, self.total_steps)
                    
                # Craft modified query parameters
                test_params = current_params.copy()
                test_params[param] = [payload]
                
                # Reconstruct query URL
                query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = parsed._replace(query=query).geturl()
                
                try:
                    res = make_web_request(test_url, timeout=self.timeout)
                    db_type = self._fingerprint_db_error(res.text)
                    
                    if db_type:
                        self.confirmed_params.add(param)
                        findings.append({
                            "module": "SQL Injection Scanner",
                            "target": test_url,
                            "severity": "CRITICAL",
                            "title": "Error-Based SQL Injection Vulnerability",
                            "description": f"The parameter '{param}' is vulnerable to Error-Based SQL Injection. An database error signature representing {db_type} was observed in the response.",
                            "evidence": f"Parameter: {param}\nPayload: {payload}\nDB Signature: {db_type}\nResponse contains database error string.",
                            "remediation": "Use parameterized queries (prepared statements) for all database operations. Never concatenate untrusted user inputs directly into SQL statements."
                        })
                        break # Found SQLi on parameter, skip further error tests on it
                except Exception:
                    pass
                    
            # 2. Time-based blind testing
            if param not in self.confirmed_params:
                for payload, db in self.time_payloads:
                    self.current_step += 1
                    if self.progress_callback:
                        self.progress_callback(self.current_step, self.total_steps)
                        
                    test_params = current_params.copy()
                    test_params[param] = [payload]
                    query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = parsed._replace(query=query).geturl()
                    
                    try:
                        start_time = time.time()
                        res = make_web_request(test_url, timeout=self.timeout + 6.0)
                        elapsed = time.time() - start_time
                        
                        # Check if request was delayed by approximately 5 seconds
                        if elapsed >= 4.8 and elapsed > (baseline_time + 3.0):
                            confirm_payload = self.time_confirm_payloads.get(db, payload)
                            confirm_params = current_params.copy()
                            confirm_params[param] = [confirm_payload]
                            confirm_query = urllib.parse.urlencode(confirm_params, doseq=True)
                            confirm_url = parsed._replace(query=confirm_query).geturl()

                            confirm_start = time.time()
                            make_web_request(confirm_url, timeout=self.timeout + 4.0)
                            confirm_elapsed = time.time() - confirm_start

                            if confirm_elapsed >= 1.8 and confirm_elapsed < 4.0:
                                self.confirmed_params.add(param)
                                findings.append({
                                    "module": "SQL Injection Scanner",
                                    "target": test_url,
                                    "severity": "CRITICAL",
                                    "title": "Time-Based Blind SQL Injection Vulnerability",
                                    "description": f"The parameter '{param}' is vulnerable to Time-Based Blind SQL Injection. The server response is controllably delayed via SQL payload. Target DB: {db}",
                                    "evidence": f"Parameter: {param}\nPayload: {payload}\nPayload 1 (5s): {elapsed:.2f}s delay\nPayload 2 (2s): {confirm_elapsed:.2f}s delay\nTarget DB: {db}",
                                    "remediation": "Use parameterized queries (prepared statements) to prevent injection."
                                })
                                break # Found SQLi, skip further time tests on this param
                    except Exception:
                        pass

    def scan(self, progress_callback=None) -> dict:
        findings = []
        
        # Get baseline request
        try:
            baseline_start = time.time()
            baseline_res = make_web_request(self.url, timeout=self.timeout)
            baseline_time = time.time() - baseline_start
        except Exception as e:
            return {
                "error": f"Failed to connect to target to scan SQLi: {str(e)}",
                "findings": []
            }

        # Run Crawler (pass make_web_request to enable mocking in tests)
        crawler = Crawler(self.url, timeout=self.timeout, make_request_fn=make_web_request)
        try:
            crawl_results = crawler.crawl()
            urls_to_test = crawl_results["urls_with_params"]
        except Exception:
            urls_to_test = []

        if not urls_to_test:
            # No URL parameters to test — log INFO and skip gracefully
            findings.append({
                "module": "SQL Injection Scanner",
                "target": self.url,
                "severity": "INFO",
                "title": "No URL Parameters Found to Test",
                "description": "The target URL does not contain any query string parameters. SQL injection testing requires injectable parameters.",
                "evidence": f"URL: {self.url}\nQuery string: (empty)",
                "remediation": "Provide a URL with query parameters (e.g., ?id=1) for SQL injection testing."
            })
            if progress_callback:
                progress_callback(1, 1)
            return {
                "target": self.url,
                "findings": findings
            }
            
        # Calculate total steps across all URLs to test
        total_steps = 0
        for u in urls_to_test:
             try:
                 p_url = urllib.parse.urlparse(u)
                 p = urllib.parse.parse_qs(p_url.query)
                 total_steps += len(p) * (len(self.error_payloads) + len(self.time_payloads))
             except Exception:
                 pass
        
        # Setup class attributes for progress and confirmed params tracking
        self.progress_callback = progress_callback
        self.current_step = 0
        self.total_steps = total_steps
        self.confirmed_params = set()

        for current_url in urls_to_test:
            self._scan_url(current_url, baseline_time, findings)

        # Progress callback cleanup
        if progress_callback:
            progress_callback(total_steps, total_steps)

        return {
            "target": self.url,
            "findings": findings
        }

Class = SQLiScanner
