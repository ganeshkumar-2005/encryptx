import sys
from rich.console import Console
from rich.panel import Panel
from rich.align import Align

BANNER_TEXT = r"""
  ______                             _  __  __
 |  ____|                           | | \ \/ /
 | |__   _ __   ___ _ __ _   _ _ __ | |_ \  / 
 |  __| | '_ \ / __| '__| | | | '_ \| __| /  \ 
 | |____| | | | (__| |  | |_| | |_) | |_ /  \ \
 |______|_| |_|\___|_|   \__, | .__/ \__/_/\_\_\
                          __/ | |               
                         |___/|_|               
"""

DISCLAIMER = """[bold red]LEGAL DISCLAIMER:[/bold red]
EncryptX is a professional security auditing and vulnerability scanning toolkit.
Usage of EncryptX for scanning targets without prior written authorization is strictly
prohibited and may violate computer crime laws (e.g., Computer Fraud and Abuse Act).
The developers assume no liability for misuse, damage, or loss caused by this tool.

[bold yellow]By using this software, you agree to assume all responsibility for its application.[/bold yellow]
"""

def display_banner(console: Console):
    """Displays the EncryptX ASCII banner and a formatted panel showing version, status, and legal disclaimer."""
    console.print(Align.center(f"[bold cyan]{BANNER_TEXT}[/bold cyan]"))
    console.print(Align.center("[bold white]* Professional Vulnerability Scanning & Security Audit Suite *[/bold white]"))
    console.print(Align.center("[cyan]Version: 1.0.0 | Engine: Python 3.10+ | Developed by Ganesh Kumar[/cyan]\n"))
    
    disclaimer_panel = Panel(
        DISCLAIMER,
        title="[!] SECURITY WARNING & CONDITIONS",
        border_style="red",
        expand=False
    )
    console.print(Align.center(disclaimer_panel))
