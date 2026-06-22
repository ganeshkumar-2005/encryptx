# EncryptX — Terminal-Based Infrastructure Security Auditing Toolkit

![EncryptX Interactive Banner](assets/banner.png)

EncryptX is an advanced, terminal-based security auditing and vulnerability scanning toolkit. Built in Python, it integrates **14 specialized scanning modules**, **7 advanced vulnerability plugins**, and a **compliance and risk scoring engine**. EncryptX focuses on clean, raw socket and protocol-level security checks using only Python's standard library and the `requests` library for web interactions.

Developed by **Ganesh Kumar**.

---

## Table of Contents
- [Project Architecture](#project-architecture)
- [Design Methodology & Capabilities](#design-methodology--capabilities)
- [Core Auditing Modules (14 Scanners)](#core-auditing-modules-14-scanners)
- [Advanced Vulnerability Plugins](#advanced-vulnerability-plugins)
- [Compliance & Risk Scoring Engine](#compliance--risk-scoring-engine)
- [PDF Report Generation](#pdf-report-generation)
- [Configuration Details](#configuration-details)
- [Installation & Setup](#installation--setup)
- [Usage Guide & Commands](#usage-guide--commands)
- [Known Limitations & Architecture Tradeoffs](#known-limitations--architecture-tradeoffs)
- [Legal & Disclaimer](#legal--disclaimer)

---

## Project Architecture

EncryptX is structured modularly to run checks concurrently using native Python thread pools.

```
EncryptX/
├── encryptx.py              # CLI Controller (built on Click & Rich)
├── config.json              # Configurations (profiles, timeouts, subdomain wordlists)
├── requirements.txt         # Package dependencies
├── .gitignore               # Excludes reports, local caches, and environments
├── scanners/                # Module implementations for the 14 basic/deep scans
│   ├── __init__.py          # Exports all scanners
│   ├── port_scanner.py      # TCP port scanner & banner grabber (Host-aware)
│   ├── header_scanner.py    # HTTP security headers auditor (Parses CSP, checks HSTS & cache directives)
│   ├── ssl_scanner.py       # SSL certificate check & TLS ciphers strength audit
│   ├── dns_scanner.py       # DNS zone analysis & IP leaks detection
│   ├── subdomain_scanner.py # Subdomain brute-forcer (with Wildcard DNS record protection)
│   ├── vuln_scanner.py      # CORS bypass, Clickjacking, Open Redirect, Sensitive files, CRLF, Host Header Injection
│   ├── sqli_scanner.py      # Active SQL Injection tester (Error-based & time-blind with verification)
│   ├── xss_scanner.py       # Active Cross-Site Scripting tester (Reflected HTML-encoding aware, DOM-based source/sink)
│   ├── tech_fingerprinter.py# Technology stack parser & CVE lookup
│   ├── cookie_scanner.py    # Cookie attributes (SameSite/Secure audit) & JWT weak-key brute-forcer
│   ├── waf_detector.py      # Passive/Active WAF & CDN detector
│   ├── info_disclosure.py   # Information leaks (IPs, private keys, secrets in comments/scripts)
│   ├── auth_scanner.py      # Administration panel finder
│   └── api_scanner.py       # API routes discovery & GraphQL introspector
├── plugins/                 # Vulnerability plugins checking CVEs and configurations
│   ├── __init__.py          # Plugin registry & dynamic loader
│   ├── base_plugin.py       # Abstract base class for standardized results
│   ├── ssl_vulns.py         # SSL attacks (Heartbleed CVE-2014-0160 exploitation, POODLE, DROWN, FREAK, CRIME)
│   ├── service_vulns.py     # Protocol auth checks (FTP, SSH banner/CVE audit, SMTP, Redis, MySQL empty-pass login)
│   ├── cms_scanner.py       # CMS audits (WordPress user/plugin enum, Joomla, Drupalgeddon 2 CVE-2018-7600 check)
│   ├── network_vulns.py     # Protocol security (DNS AXFR nameserver resolver, SNMP, SMB signing, LDAP anonymous bind)
│   ├── subdomain_takeover.py# Dangling CNAME & cloud takeover detection
│   ├── ssrf_scanner.py      # LFI, RFI, Path Traversal, Null Byte, SSRF parameters injection
│   └── compliance.py        # Compliance mapping (OWASP Top 10, PCI-DSS) & grading engine
├── reports/                 # Reporting system
│   ├── __init__.py
│   └── pdf_report.py        # FPDF2 layout builder with indented text blocks
└── utils/                   # Helpers package
    ├── __init__.py
    ├── banner.py            # Console ASCII Art banner & disclaimer
    └── helpers.py           # Network request wrappers & validation helpers
```

---

## Design Methodology & Capabilities

EncryptX is designed to run security assessments without spawning subprocesses or wrapping binary utilities like `nmap` or `openssl`. 

### Key Technical Achievements:
- **Low-Level Protocol Implementations**: DNS zone transfers, SNMP probes, SMB signing negotiation, LDAP anonymous binds, and MySQL handshake decoding are implemented directly in pure Python using raw sockets and bytes formatting (`struct.pack` / `struct.unpack`).
- **Real Heartbleed (CVE-2014-0160) Exploitation**: Unlike shallow version-checking tools, `ssl_vulns.py` establishes a raw TLS connection, sends a custom TLS ClientHello with the Heartbeat extension, transmits a malformed heartbeat payload request (specifying a payload length of 16KB while sending only 1 byte), and parses the response to verify if server memory was leaked.
- **Python 3.10+ Cryptography Compatibility**: Implements fallback raw socket negotiation for older SSLv2/SSLv3 protocols (such as POODLE and DROWN checks) when modern Python environments refuse to load deprecated SSL context wrappers.
- **WAF and Wildcard Protections**: Includes wildcard DNS detection (preventing false subdomains from being flagged) and custom 404 response page fingerprinting to eliminate false positives in file discovery.

---

## Core Auditing Modules (14 Scanners)

### 1. Port Scanner (`scanners/port_scanner.py`)
- **Methodology**: Uses concurrent raw TCP socket connection attempts.
- **Capabilities**: Captures protocol banners, utilizing the actual target hostname in HTTP header requests to trigger realistic web server responses instead of generic errors.
- **Default Ports**: Scans 50+ common administration, database, and message queue ports.

### 2. HTTP Header Scanner (`scanners/header_scanner.py`)
- **Analyzed Headers**: Audits `Strict-Transport-Security`, `Content-Security-Policy` (CSP), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Deep CSP Audit**: Parses directives to flag dangerous directives (like `unsafe-inline`, `unsafe-eval`, `data:` URIs, or wildcard scopes) and identifies missing clickjacking protection.
- **Server Disclosures**: Detects backend version leakages in headers such as `Server`, `X-Powered-By`, and `X-AspNet-Version`.

### 3. SSL Scanner (`scanners/ssl_scanner.py`)
- **Certificate Validity**: Validates expiration dates, issuer hierarchies, and hostname matching.
- **Cipher Suite Auditing**: Enumerates supported cipher suites, warning about obsolete protocols (TLS 1.0, TLS 1.1) and truly broken/weak ciphers (RC4, 3DES, NULL, EXPORT).

### 4. DNS Scanner (`scanners/dns_scanner.py`)
- **DNS Records**: Resolves standard records (A, AAAA, MX, TXT, NS, CNAME).
- **Leak Detection**: Flags if public records point to RFC 1918 private IP addresses (IP leakage).

### 5. Subdomain Scanner (`scanners/subdomain_scanner.py`)
- **Enumeration**: Performs dictionary-based subdomain brute-forcing.
- **Wildcard Protection**: Resolves a random, non-existent subdomain beforehand; if it resolves, the target domain uses a wildcard DNS record, and the scanner pauses to prevent high false-positive rates.

### 6. Vulnerability Scanner (`scanners/vuln_scanner.py`)
- **CORS Audit**: Probes with multiple origin variations (e.g., `null`, subdomains, suffix bypasses like `target.com.attacker.com`, and protocol downgrades).
- **Clickjacking**: Checks framing options on the target endpoint.
- **Open Redirect**: Probes 15+ common redirection parameters (`redirect_url`, `return_to`, `next`, `dest`, etc.) with external payload links.
- **Sensitive Files**: Probes for backup/configuration files (`.git`, `.env`, `wp-config.php`, `.htaccess`). It fingerprints the server's custom 404 response layout to ignore false HTTP 200/OK status codes and validates response content signatures (e.g., expecting `RewriteEngine` inside `.htaccess`).
- **RFC 9116 security.txt**: Validates presence and compliance of `security.txt` files, checking for required Contact and Expires directives.

### 7. SQL Injection Scanner (`scanners/sqli_scanner.py`)
- **Error-Based**: Injects characters (`'`, `"`, `\`) and monitors response content for database system error templates (MySQL, MSSQL, Oracle, PGSQL).
- **Time-Blind Verification**: Injects delay payloads (`pg_sleep`, `sleep`). When a delay is observed, it confirms the vulnerability by sending a secondary verification payload with a different delay interval, ruling out random network jitter.

### 8. XSS Scanner (`scanners/xss_scanner.py`)
- **Reflected XSS**: Injects script payloads and parses the response to ensure they reflect unescaped. If the payload is reflected but HTML-encoded (e.g., `&lt;script&gt;`), it reports the reflection as secure.
- **DOM-Based XSS**: Parses target scripts for client-side sources (`location.hash`, `document.URL`) referencing dangerous sinks (`eval`, `document.write`, `innerHTML`).

### 9. Technology Fingerprinter (`scanners/tech_fingerprinter.py`)
- **Fingerprinting**: Identifies software stacks based on headers, cookies, and DOM components.
- **CVE Mapping**: Cross-references detected technologies with a localized vulnerability dictionary.

### 10. Cookie Scanner (`scanners/cookie_scanner.py`)
- **Audit**: Analyzes cookies for `HttpOnly`, `Secure`, and `SameSite` configurations.
- **JWT Cryptography Audit**: Detects JWT cookies, checking for the `none` algorithm and brute-forcing symmetric signatures (HS256/HS384/HS512) against common weak secrets.

### 11. WAF Detector (`scanners/waf_detector.py`)
- **Signatures**: Identifies web application firewalls (Cloudflare, AWS WAF, ModSecurity, Akamai, etc.) based on headers and blocked requests.

### 12. Information Disclosure (`scanners/info_disclosure.py`)
- **Scraper**: Reviews comments and script files using BeautifulSoup.
- **Regex Extraction**: Flags private IPs, AWS credentials, SSH private keys (PEM), emails, and Slack Webhooks.

### 13. Administration Scanner (`scanners/auth_scanner.py`)
- **Exposures**: Probes common admin panels and login portals.

### 14. API Scanner (`scanners/api_scanner.py`)
- **Routes**: Searches for REST API version points.
- **GraphQL**: Submits introspection query payloads to `/graphql` using appropriate `application/json` structures to check for exposed database schemas.

---

## Advanced Vulnerability Plugins

Plugins are loaded dynamically and return standardized findings with CVSS scores and CVE IDs.

### 1. SSL Attacks (`plugins/ssl_vulns.py`)
- **Heartbleed (CVE-2014-0160)**: Fully implemented TLS record-level heartbeat request test.
- **POODLE (CVE-2014-3566)**: Checks for SSLv3 support.
- **DROWN (CVE-2016-0800)**: Checks for SSLv2 support.
- **FREAK (CVE-2015-0204)**: Verifies if weak export-grade 512-bit keys are accepted.
- **CRIME (CVE-2012-4929)**: Identifies active TLS-level compression.

### 2. Service Protocol Audits (`plugins/service_vulns.py`)
- **FTP Anonymous (CVE-1999-0497)**: Checks if the target FTP server allows passwordless anonymous access.
- **SSH Protocol & CVE Checker**: Resolves the SSH service banner, checks for legacy SSHv1 support, and compares the SSH version against historical CVE databases.
- **SMTP Open Relay**: Verifies if mail transfer agents accept relay mail for unauthorized external recipients.
- **DB Passwordless Exposures**: Decodes MySQL protocol handshake greeting packets on port 3306 and attempts passwordless root login. Performs a similar authentication check against Redis.

### 3. CMS Scanner (`plugins/cms_scanner.py`)
- **WordPress**: Runs REST API author enumeration (`?author=1..10`), WordPress plugin version discovery via readme.txt parsing, XML-RPC DDoS amplification checks, and WordPress core version audits.
- **Joomla & Drupal**: Checks core configurations and audits for outdated Drupal cores vulnerable to Drupalgeddon 2 (CVE-2018-7600).

### 4. Network Security (`plugins/network_vulns.py`)
- **DNS AXFR**: Resolves target nameservers (NS records) via DNS queries and performs zone transfer attempts directly against the authoritative nameservers.
- **SNMP**: Checks for public/private SNMP community strings.
- **SMB Signing**: Inspects SMB protocol responses on port 445 to determine if message signing is required.
- **LDAP**: Connects to port 389 and sends a raw LDAP BindRequest with empty credentials to verify anonymous bind permissions.

### 5. Subdomain Takeover (`plugins/subdomain_takeover.py`)
- **Takeovers**: Assesses target CNAMES pointing to inactive third-party cloud hosting providers.

### 6. SSRF & Path Traversal (`plugins/ssrf_scanner.py`)
- **Probes**: Audits query fields for Local File Inclusion (LFI) and Server-Side Request Forgery (SSRF) vulnerabilities using common directory paths and loopback URLs.

---

## Compliance & Risk Scoring Engine

The **Compliance & Scoring Plugin (`plugins/compliance.py`)** runs as the final step in the scan:
1. **OWASP Top 10 Mapping**: Maps findings to categories (e.g., Cryptographic Failures for weak SSL configurations, Security Misconfigurations for missing headers, Injection for XSS/SQLi).
2. **PCI-DSS Compliance**: Evaluates findings against specific PCI DSS v3.2.1 requirements (Requirement 2.3 for default passwords, Requirement 4.1 for strong cryptography).
3. **Host Security Posture Rating**: Assigns a letter grade (**A, B, C, D, or F**) using a CVSS-weighted scoring algorithm.

---

## PDF Report Generation

The PDF generator (`reports/pdf_report.py`) builds clean, readable security audit reports:
- **Severity-based Sorting**: Findings are grouped by severity (Critical, High, Medium, Low, Info) with corresponding color banners.
- **Technical Details**: Includes CVSS scores, CVE numbers, evidence fields, and step-by-step remediation advice.
- **Layout**: Uses FPDF2 block formats with proper left margins and paragraph indentation.

---

## Configuration Details

Configurations are managed in `config.json`:
- **profiles**:
  - `quick`: Scans common web ports (80, 443) and basic HTTP headers.
  - `standard`: Adds SSL/TLS analysis, core web vulnerabilities, and WAF checks.
  - `full`: Performs a full port sweep, all web scanners, and dynamically loads all advanced vulnerability plugins.
- **dns_wordlist**: Subdomain prefixes utilized during brute-force operations.

---

## Installation & Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ganeshkumar-2005/encryptx.git
   cd encryptx
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   # On macOS/Linux:
   source venv/bin/activate
   # On Windows:
   venv\Scripts\activate
   ```

3. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage Guide & Commands

### 1. Run a Scan
- **Standard Audit**:
  ```bash
  python encryptx.py scan --target example.com
  ```
- **Full Spectrum Scan** (Basic + Deep Scanners + All Plugins):
  ```bash
  python encryptx.py scan --target example.com --all
  ```
- **Automated CI/CD / Non-Interactive Mode** (Bypasses CLI confirmation prompts):
  ```bash
  python encryptx.py scan --target example.com --all --force
  ```
- **Specific Scans**:
  ```bash
  python encryptx.py scan --target example.com --ports --ssl
  python encryptx.py scan --target example.com --plugin-ssl --plugin-compliance
  ```

### 2. Generate PDF Report
Processes the JSON output from a scan and saves a PDF to your **Downloads** directory:
```bash
python encryptx.py report --input output/scan_YYYYMMDD_HHMMSS.json
```

### 3. Interactive Config Panel
```bash
python encryptx.py config
```

---

## Known Limitations & Architecture Tradeoffs

To ensure a lightweight footprint, EncryptX uses pure Python implementations. Understanding these tradeoffs is important:

- **No Heavy Network Drivers (Nmap/Masscan)**: EncryptX's port scanner runs in user space using Python's `socket` library. It does not perform SYN scanning (half-open) and relies on full TCP handshakes (`connect_ex`). This makes it slower and more visible in firewall logs than native binary tools.
- **No Native OpenSSL Wrapping**: Legitimate SSL testing tools (like `testssl.sh`) query remote endpoints by negotiating specific cipher suites using local OpenSSL binaries. EncryptX builds raw handshake payloads using Python's `ssl` module or custom socket bytes, which may not catch complex renegotiation bugs.
- **Thread Pool Limits**: Multi-threading in Python is subject to the Global Interpreter Lock (GIL). For heavy networking, this is mostly fine (I/O bound), but dictionary brute-forcing of thousands of subdomains is less efficient than Go-based tools like `amass` or `subfinder`.
- **WAF Interference**: Because EncryptX uses standard HTTP requests, active WAFs can block its IP address during SQLi or XSS scanning, resulting in false negatives.

---

## Legal & Disclaimer

**AUTHORIZED USE ONLY**: Usage of EncryptX for scanning targets without prior written authorization is strictly prohibited. The developer, **Ganesh Kumar**, assumes no liability for misuse, damage, or loss caused by this software.
