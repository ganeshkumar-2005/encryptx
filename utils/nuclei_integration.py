import subprocess
import sys
import os
import tempfile
import json
import uuid
from rich.console import Console

console = Console()

def check_nuclei_installed():
    """
    Checks if Nuclei is installed by running nuclei -version.
    If not installed, prints a clear error message and exits gracefully.
    """
    try:
        is_windows = os.name == 'nt'
        subprocess.run(["nuclei", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, shell=is_windows)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, PermissionError):
        console.print("\n[bold red]Error: Nuclei is not installed or not found in your system's PATH.[/bold red]")
        console.print("[yellow]Please install Nuclei from: https://github.com/projectdiscovery/nuclei[/yellow]\n")
        sys.exit(0)

def run_nuclei_integration(target):
    """
    Runs Nuclei scanner as a subprocess against the target and returns converted findings.
    """
    temp_dir = tempfile.gettempdir()
    temp_output_file = os.path.join(temp_dir, f"nuclei_out_{uuid.uuid4().hex}.json")
    
    findings = []
    try:
        cmd = [
            "nuclei",
            "-u", target,
            "-json-export", temp_output_file,
            "-silent",
            "-severity", "critical,high,medium,low"
        ]
        
        # Execute Nuclei scan and wait for completion
        is_windows = os.name == 'nt'
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, shell=is_windows)
        
        # Parse the JSONL results
        if os.path.exists(temp_output_file):
            with open(temp_output_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        info = data.get("info", {})
                        
                        title = info.get("name", "Nuclei Finding")
                        severity = info.get("severity", "info").upper()
                        host = data.get("host", "")
                        matched_at = data.get("matched-at", "")
                        curl_command = data.get("curl-command", "")
                        description = info.get("description", "")
                        remediation = info.get("remediation", "")
                        
                        evidence = matched_at
                        if curl_command:
                            evidence = f"{matched_at}\nCommand: {curl_command}"
                            
                        finding = {
                            "module": "Nuclei Integration",
                            "target": host,
                            "severity": severity,
                            "title": title,
                            "description": description,
                            "evidence": evidence,
                            "remediation": remediation
                        }
                        findings.append(finding)
                    except Exception:
                        pass
    finally:
        # Clean up temp file
        if os.path.exists(temp_output_file):
            try:
                os.remove(temp_output_file)
            except Exception:
                pass
                
    return findings
