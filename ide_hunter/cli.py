"""
Command line interface for the IDE Hunter with Rich framework
"""

import argparse
import asyncio
import logging
import re
import fnmatch
import csv
import os
from datetime import datetime
from typing import Optional, Dict, Any, Set
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich import box
from rich.align import Align
from rich.layout import Layout
import sys

from ide_hunter.scanner import IDEextensionsscanner
from ide_hunter.models import Severity
from ide_hunter.utils.logging_utils import setup_logging
from ide_hunter.utils.output import OutputFormatter

# Initialize Rich console
console = Console()

def sanitize_iocs(text: str) -> str:
    """Add safeguards to IOCs to prevent accidental execution."""
    import re
    
    # IP addresses - replace ALL dots with [.]
    text = re.sub(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', r'\1[.]\2[.]\3[.]\4', text)
    
    # URLs - replace protocol and dots
    text = re.sub(r'https?://', r'hxxps?://', text)
    text = re.sub(r'wss?://', r'wxxs?://', text)
    
    # Domains - replace dots in domain names
    text = re.sub(r'([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})', r'\1[.]\2', text)
    
    # Email addresses
    text = re.sub(r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})', r'\1@\2[.]\3', text)
    
    return text

def sanitize_code_execution(text: str) -> str:
    """Add safeguards to prevent accidental code execution."""
    import re
    
    # Dangerous function calls - add [.] before parentheses
    dangerous_functions = [
        'eval', 'exec', 'Function', 'setTimeout', 'setInterval', 
        'setImmediate', 'process.nextTick', 'require', 'import',
        'document.write', 'innerHTML', 'outerHTML', 'insertAdjacentHTML',
        'createElement', 'appendChild', 'removeChild', 'replaceChild',
        'system', 'execve', 'fork', 'popen', 'shell_exec', 'passthru',
        'proc_open', 'popen', 'exec', 'system', 'cmd', 'powershell',
        'atob', 'btoa', 'base64_decode', 'base64_encode', 'decodeURIComponent', 'unescape'
    ]
    
    for func in dangerous_functions:
        # Add [.] before parentheses to make functions unexecutable
        text = re.sub(rf'\b{func}\s*\(', f'{func}[.](', text)
    
    # Shell commands
    shell_commands = ['bash', 'sh', 'cmd', 'powershell', 'curl', 'wget', 'nc', 'netcat', 'telnet', 'ssh', 'scp', 'rsync']
    for cmd in shell_commands:
        text = re.sub(rf'\b{cmd}\b', f'{cmd}[.]', text)
    
    return text

def calculate_dynamic_column_widths(terminal_width: int, num_columns: int, min_widths: list = None) -> list:
    """
    Calculate dynamic column widths based on terminal width.
    
    Args:
        terminal_width: Width of the terminal
        num_columns: Number of columns in the table
        min_widths: List of minimum widths for each column
    
    Returns:
        List of calculated column widths
    """
    if min_widths is None:
        min_widths = [10] * num_columns
    
    # Reserve space for borders and padding (approximately 10 characters)
    available_width = terminal_width - 10
    
    # Calculate base width per column
    base_width = available_width // num_columns
    
    # Ensure minimum widths are respected
    column_widths = []
    for i, min_width in enumerate(min_widths):
        column_widths.append(max(base_width, min_width))
    
    # Adjust if total exceeds available width
    total_width = sum(column_widths)
    if total_width > available_width:
        # Scale down proportionally
        scale_factor = available_width / total_width
        column_widths = [int(width * scale_factor) for width in column_widths]
    
    return column_widths

def truncate_text(text: str, max_width: int, suffix: str = "...") -> str:
    """
    Truncate text to fit within specified width.
    
    Args:
        text: Text to truncate
        max_width: Maximum width
        suffix: Suffix to add when truncating
    
    Returns:
        Truncated text
    """
    if len(text) <= max_width:
        return text
    
    if max_width <= len(suffix):
        return suffix[:max_width]
    
    return text[:max_width - len(suffix)] + suffix

def truncate_file_path(file_path: str, max_width: int) -> str:
    """
    Intelligently truncate file paths to show the most important parts.
    
    Args:
        file_path: Full file path
        max_width: Maximum width
    
    Returns:
        Truncated file path
    """
    if len(file_path) <= max_width:
        return file_path
    
    # Try to show the filename and some parent directory
    path_parts = file_path.replace('\\', '/').split('/')
    filename = path_parts[-1] if path_parts else file_path
    
    if len(filename) >= max_width - 3:
        return "..." + filename[-(max_width-3):]
    
    # Show filename + some parent path
    remaining_width = max_width - len(filename) - 3
    if len(path_parts) > 1:
        parent = path_parts[-2] if len(path_parts) > 1 else ""
        if len(parent) > remaining_width:
            parent = "..." + parent[-(remaining_width-3):]
        return f"{parent}/{filename}"
    
    return "..." + filename

def load_domains_whitelist(whitelist_path: str) -> Set[str]:
    """Load domains whitelist from file."""
    whitelist = set()
    
    if not os.path.exists(whitelist_path):
        console.print(f"[yellow]Warning: Whitelist file not found: {whitelist_path}[/yellow]")
        return whitelist
    
    try:
        with open(whitelist_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines, comments, and header lines
                if line and not line.startswith('#') and line.lower() not in ['domain', 'domains']:
                    # Normalize domain (lowercase, remove www.)
                    domain = line.lower()
                    if domain.startswith('www.'):
                        domain = domain[4:]
                    whitelist.add(domain)
        
        console.print(f"[green]Loaded {len(whitelist)} domains from whitelist[/green]")
        
    except Exception as e:
        console.print(f"[red]Error loading whitelist: {e}[/red]")
    
    return whitelist

def is_domain_whitelisted(url: str, whitelist: Set[str]) -> bool:
    """Check if a URL's domain is in the whitelist."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check exact match
        if domain in whitelist:
            return True
        
        # Check subdomain matches (e.g., api.github.com matches github.com)
        domain_parts = domain.split('.')
        for i in range(len(domain_parts)):
            subdomain = '.'.join(domain_parts[i:])
            if subdomain in whitelist:
                return True
        
        return False
        
    except Exception:
        return False

def create_clickable_text(text: str, full_text: str, max_width: int, style: str = "white") -> Text:
    """
    Create clickable text that shows full content when selected.
    
    Args:
        text: Display text (may be truncated)
        full_text: Full text to show
        max_width: Maximum display width
        style: Rich style for the text
    
    Returns:
        Rich Text object with clickable functionality
    """
    # Create the display text
    display_text = truncate_text(text, max_width)
    
    # Create Rich Text object
    rich_text = Text(display_text, style=style)
    
    # Add a subtle indicator if text is truncated
    if len(text) > max_width:
        rich_text.append(" [dim](click for full)[/dim]", style="dim")
    
    return rich_text

def show_full_content_panel(title: str, content: str, content_type: str = "text"):
    """
    Show full content in a detailed panel.
    
    Args:
        title: Panel title
        content: Full content to display
        content_type: Type of content (text, file_path, code, etc.)
    """
    console = Console()
    
    if content_type == "file_path":
        # For file paths, show clickable link
        file_url = "file:///" + content.replace('\\', '/')
        panel_content = f"""[bold]Full Path:[/bold] {content}

[bold]Actions:[/bold]
• [link={file_url}]Open in File Explorer[/link]
• Copy to clipboard: [dim]{content}[/dim]"""
    elif content_type == "code":
        # For code context, use syntax highlighting
        panel_content = f"""[bold]Full Context:[/bold]
[code]{content}[/code]"""
    else:
        # For regular text
        panel_content = f"""[bold]Full Content:[/bold]
{content}"""
    
    panel = Panel(
        panel_content,
        title=f"[bold blue]{title}[/bold blue]",
        border_style="green",
        expand=True
    )
    
    console.print(panel)

def interactive_issue_details(issues_by_severity):
    """
    Provide interactive way to view full details of security issues.
    
    Args:
        issues_by_severity: Dictionary of issues grouped by severity
    """
    console = Console()
    
    # Flatten all issues with unique IDs
    all_issues = []
    issue_id = 1
    
    for severity, issues in issues_by_severity.items():
        for ext_name, issue in issues:
            all_issues.append({
                'id': issue_id,
                'severity': severity,
                'extension': ext_name,
                'issue': issue
            })
            issue_id += 1
    
    if not all_issues:
        console.print("[yellow]No issues to display.[/yellow]")
        return
    
    # Show summary table
    summary_table = Table(title="Security Issues Summary", box=box.ROUNDED)
    summary_table.add_column("ID", style="cyan", justify="right", width=4)
    summary_table.add_column("Severity", style="red")
    summary_table.add_column("Extension", style="blue")
    summary_table.add_column("Issue", style="white")
    summary_table.add_column("File", style="dim")
    summary_table.add_column("Full Path", style="dim")
    
    for issue_data in all_issues:
        issue = issue_data['issue']
        # Extract just the filename for the File column
        filename = Path(issue.file_path).name
        # Show full path (truncated) for the Full Path column
        full_path_display = truncate_file_path(str(issue.file_path), 50)
        summary_table.add_row(
            str(issue_data['id']),
            issue_data['severity'].name,
            truncate_text(issue_data['extension'], 25),
            truncate_text(issue.description, 30),
            filename,
            full_path_display
        )
    
    console.print(summary_table)
    console.print()
    
    # Interactive selection
    while True:
        try:
            console.print("[bold green]Interactive Mode:[/bold green]")
            console.print("• Enter issue ID to view full details")
            console.print("• Enter 'snippet <ID>' to view code snippet")
            console.print("• Enter 'save <ID>' to save malicious code to file")
            console.print("• Enter 'q' to quit")
            console.print("• Enter 'all' to show all details")
            
            choice = Prompt.ask("\n[bold]Your choice[/bold]", default="q")
            
            if choice.lower() == 'q':
                break
            elif choice.lower() == 'all':
                show_all_issue_details(all_issues)
            elif choice.lower().startswith('snippet'):
                try:
                    issue_id = int(choice.split()[1])
                    issue_data = next((i for i in all_issues if i['id'] == issue_id), None)
                    if issue_data:
                        show_code_snippet(issue_data)
                    else:
                        console.print(f"[red]Issue ID {issue_id} not found.[/red]")
                except (ValueError, IndexError):
                    console.print("[red]Please enter a valid snippet command: 'snippet <ID>'[/red]")
            elif choice.lower().startswith('save'):
                try:
                    issue_id = int(choice.split()[1])
                    issue_data = next((i for i in all_issues if i['id'] == issue_id), None)
                    if issue_data:
                        save_malicious_code(issue_data)
                    else:
                        console.print(f"[red]Issue ID {issue_id} not found.[/red]")
                except (ValueError, IndexError):
                    console.print("[red]Please enter a valid save command: 'save <ID>'[/red]")
            else:
                try:
                    issue_id = int(choice)
                    issue_data = next((i for i in all_issues if i['id'] == issue_id), None)
                    if issue_data:
                        show_issue_detail(issue_data)
                    else:
                        console.print(f"[red]Issue ID {issue_id} not found.[/red]")
                except ValueError:
                    console.print("[red]Please enter a valid issue ID, 'snippet <ID>', 'save <ID>', 'all', or 'q'.[/red]")
            
            console.print()
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Exiting interactive mode...[/yellow]")
            break

def show_issue_detail(issue_data):
    """Show detailed information for a specific issue."""
    console = Console()
    issue = issue_data['issue']
    
    detail_content = f"""[bold]Issue ID:[/bold] {issue_data['id']}
[bold]Severity:[/bold] {issue_data['severity'].name}
[bold]Extension:[/bold] {issue_data['extension']}
[bold]Issue Description:[/bold] {issue.description}
[bold]Full Path:[/bold] {issue.file_path}
[bold]Line Number:[/bold] {issue.line_number or 'N/A'}
[bold]Full Context:[/bold]
{issue.context}"""
    
    panel = Panel(
        detail_content,
        title=f"[bold red]Security Issue Details[/bold red]",
        border_style="red",
        expand=True
    )
    
    console.print(panel)

def show_all_issue_details(all_issues):
    """Show all issues in detailed format."""
    console = Console()
    
    for issue_data in all_issues:
        show_issue_detail(issue_data)
        console.print()

def show_code_snippet(issue_data):
    """Show code snippet with smart size detection and security safeguards."""
    console = Console()
    issue = issue_data['issue']
    
    try:
        # Read file content
        with open(issue.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.splitlines()
        total_lines = len(lines)
        
        # Smart size detection
        if total_lines > 50:
            console.print(f"[yellow]Code snippet is large ({total_lines} lines)[/yellow]")
            if Confirm.ask("Save to file for review?"):
                save_malicious_code(issue_data)
            return
        
        # Show snippet with context
        start_line = max(1, (issue.line_number or 1) - 5)
        end_line = min(total_lines, (issue.line_number or 1) + 15)
        
        snippet_content = "\n".join(lines[start_line-1:end_line])
        
        # Apply security safeguards
        safe_snippet = sanitize_code_execution(snippet_content)
        safe_description = sanitize_iocs(issue.description)
        
        panel_content = f"""[bold]File:[/bold] {issue.file_path.name}
[bold]Lines:[/bold] {start_line}-{end_line} of {total_lines}
[bold]Risk Level:[/bold] {issue_data['severity'].name}
[bold]Detected Issue:[/bold] {safe_description}

[bold]Code Snippet:[/bold]
[code]{safe_snippet}[/code]

[yellow]WARNING: This code contains potentially malicious patterns[/yellow]
[dim]Note: IOCs and dangerous functions have been sanitized for safety[/dim]"""
        
        panel = Panel(
            panel_content,
            title=f"[bold red]Code Snippet - Issue #{issue_data['id']}[/bold red]",
            border_style="red",
            expand=True
        )
        console.print(panel)
        
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")

def save_malicious_code(issue_data):
    """Save malicious code to file for review with security safeguards."""
    console = Console()
    issue = issue_data['issue']
    
    try:
        # Generate safe filename
        safe_name = "".join(c for c in issue_data['extension'] if c.isalnum() or c in (' ', '-', '_')).rstrip()
        filename = f"malicious_code_{issue_data['id']}_{safe_name}.txt"
        
        # Read and save content
        with open(issue.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Apply safeguards to the content
        safe_content = sanitize_code_execution(content)
        safe_content = sanitize_iocs(safe_content)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Malicious Code Analysis Report\n")
            f.write(f"# Issue ID: {issue_data['id']}\n")
            f.write(f"# Extension: {issue_data['extension']}\n")
            f.write(f"# Severity: {issue_data['severity'].name}\n")
            f.write(f"# File: {issue.file_path}\n")
            f.write(f"# Description: {sanitize_iocs(issue.description)}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {'='*50}\n")
            f.write(f"# SECURITY NOTICE: IOCs and dangerous functions have been sanitized\n")
            f.write(f"# Original functions: eval, exec, atob, etc. are shown as eval[.], exec[.], atob[.]\n")
            f.write(f"# Original URLs: http://example.com are shown as hxxp://example[.]com\n")
            f.write(f"# {'='*50}\n\n")
            f.write(safe_content)
        
        console.print(f"[green]Malicious code saved to: {filename}[/green]")
        console.print(f"[dim]You can now review the full content safely[/dim]")
        console.print(f"[yellow]Note: IOCs and dangerous functions have been sanitized for safety[/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error saving file: {e}[/red]")

def create_banner() -> Panel:
    """Create a beautiful banner using Rich."""
    banner_text = Text()
    banner_text.append("██╗██████╗ ███████╗    ███████╗██╗  ██╗████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ \n", style="bold cyan")
    banner_text.append("██║██╔══██╗██╔════╝    ██╔════╝╚██╗██╔╝╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n", style="bold cyan")
    banner_text.append("██║██║  ██║█████╗      █████╗   ╚███╔╝    ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n", style="bold cyan")
    banner_text.append("██║██║  ██║██╔══╝      ██╔══╝   ██╔██╗    ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n", style="bold cyan")
    banner_text.append("██║██████╔╝███████╗    ███████╗██╔╝ ██╗   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n", style="bold cyan")
    banner_text.append("╚═╝╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n", style="bold cyan")
    
    subtitle = Text("IDE Extensions Forensics", style="bold yellow")
    author = Text("By Almog Mendelson", style="italic dim")
    description = Text("Scan and analyze IDE Code extensions for potential security risks.", style="dim")
    
    return Panel(
        Align.center(banner_text + "\n" + subtitle + "\n" + author + "\n" + description),
        title="[bold red]IDE Hunter[/bold red]",
        border_style="bright_blue",
        box=box.DOUBLE,
        padding=(1, 2)
    )

def create_features_table() -> Table:
    """Create a features table using Rich."""
    table = Table(title="Key Features", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Feature", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    
    features = [
        ("Pattern Detection", "Detects malicious patterns embedded in IDE extension files"),
        ("YARA Integration", "Integrated with YARA rules for enhanced security analysis"),
        ("Multiple Formats", "Export results in CSV/JSON format or display in terminal"),
        ("Severity Filtering", "Filters findings based on severity (INFO → CRITICAL)"),
        ("URL Extraction", "Extracts and reports all URLs found in extensions"),
        ("Progress Tracking", "Real-time progress bars and detailed logging"),
        ("Rich Interface", "Beautiful terminal interface with colors and formatting")
    ]
    
    for feature, description in features:
        table.add_row(feature, description)
    
    return table

def parse_arguments():
    """Parse command line arguments with Rich help formatting."""
    # Create parser with Rich banner
    parser = argparse.ArgumentParser(
        description="IDE Hunter - Security Scanner",
        epilog="Use --help for detailed information about each option.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Define arguments with Rich-style help
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="Print only extension metadata without security findings",
    )
    parser.add_argument(
        "--list-urls",
        action="store_true",
        help="Extract all URLs found in high-risk files",
    )
    parser.add_argument(
        "--ide",
        type=str,
        choices=["vscode", "pycharm"],
        help="Specify the IDE to scan ('vscode' or 'pycharm')",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Specify custom output file path (CSV or JSON)",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["csv", "json"],
        default="csv",
        help="Output format (csv or json)",
    )
    parser.add_argument(
        "-p", "--path",
        type=str,
        default=None,
        help="Custom VS Code extensions directory path",
    )
    parser.add_argument(
        "--severity",
        type=str,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Severity level to report",
    )
    parser.add_argument(
        "--use-yara",
        action="store_true",
        help="Enable YARA-based scanning for deeper analysis",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner display",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Enable interactive mode for viewing full issue details",
    )
    parser.add_argument(
        "--whitelist",
        type=str,
        default="domains_whitelist.txt",
        help="Path to domains whitelist file (default: domains_whitelist.txt)",
    )

    return parser.parse_args()

def display_startup_info(args):
    """Display startup information with Rich formatting."""
    if not args.no_banner:
        console.print(create_banner())
        console.print()
        console.print(create_features_table())
        console.print()
    
    # Display scan configuration
    config_table = Table(title="Scan Configuration", box=box.ROUNDED, show_header=True, header_style="bold green")
    config_table.add_column("Setting", style="cyan", no_wrap=True)
    config_table.add_column("Value", style="white")
    
    config_table.add_row("IDE Target", args.ide or "Both (VS Code & PyCharm)")
    config_table.add_row("YARA Rules", "Enabled" if args.use_yara else "Disabled")
    config_table.add_row("Output Format", args.format.upper())
    config_table.add_row("Output File", args.output or "Console")
    config_table.add_row("Severity Filter", args.severity or "All levels")
    config_table.add_row("Debug Mode", "Enabled" if args.debug else "Disabled")
    config_table.add_row("Custom Path", args.path or "Default paths")
    
    console.print(config_table)
    console.print()

async def async_run(args):
    """Run the scanner with the provided arguments using Rich interface."""
    logger = logging.getLogger(__name__)
    
    try:
        # Display startup information
        display_startup_info(args)
        
        # Validate YARA if enabled
        if args.use_yara:
            try:
                import yara
                console.print("[green]YARA module loaded successfully[/green]")
            except ImportError:
                console.print("[red]Error: YARA module not found. Please install yara-python package.[/red]")
                return 1

        # Initialize scanner
        with console.status("[bold green]Initializing scanner..."):
            scanner = IDEextensionsscanner(
                ide=args.ide,
                extensions_path=args.path,
                use_yara=args.use_yara,
            )

        # Run scan with progress tracking
        console.print("\n[bold green]Starting security scan of IDE extensions...[/bold green]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Scanning extensions...", total=100)
            
            # Start the scan
            results = await scanner.scan_all_extensions()
            progress.update(task, completed=100)

        # Apply severity filtering if specified
        if args.severity:
            from ide_hunter.models import Severity
            severity_enum = Severity[args.severity]
            results = scanner.filter_by_severity(results, severity_enum)

        # Handle output with Rich formatting
        if args.metadata:
            display_metadata_results(results)
        elif args.list_urls:
            await display_url_results(scanner, results, args.output, args.whitelist)
        else:
            if args.output:
                await save_results_to_file(scanner, results, args)
            else:
                display_scan_results(scanner, results, args)

        return 0

    except Exception as e:
        console.print(f"\n[red]Error during scan: {str(e)}[/red]")
        console.print("[yellow]Check the log file for more details.[/yellow]")
        return 1

def display_metadata_results(results):
    """Display metadata results with Rich formatting."""
    console.print("\n[bold blue]IDE Extension Metadata Summary[/bold blue]\n")
    
    if not results:
        console.print("[yellow]No extensions found.[/yellow]")
        return
    
    # Calculate dynamic column widths
    terminal_width = console.size.width
    column_widths = calculate_dynamic_column_widths(
        terminal_width, 
        4,  # Extension, Version, Publisher, Files Scanned
        [20, 12, 15, 12]  # Minimum widths
    )
    
    table = Table(title="Extensions Overview", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Extension", style="cyan", no_wrap=True, width=column_widths[0])
    table.add_column("Version", style="green", width=column_widths[1])
    table.add_column("Publisher", style="blue", width=column_widths[2])
    table.add_column("Files Scanned", style="yellow", justify="right", width=column_widths[3])
    
    for ext in results:
        # Truncate extension name if too long
        ext_name = truncate_text(ext.name, column_widths[0])
        version = truncate_text(ext.version or "Unknown", column_widths[1])
        publisher = truncate_text(ext.publisher or "Unknown", column_widths[2])
        
        table.add_row(
            ext_name,
            version,
            publisher,
            str(len(ext.scanned_files))
        )
    
    console.print(table)

async def display_url_results(scanner, results, output_file, whitelist_path="domains_whitelist.txt"):
    """Display URL extraction results with Rich formatting."""
    console.print("\n[bold blue]URL Extraction Results[/bold blue]\n")
    
    # Load domains whitelist
    whitelist = load_domains_whitelist(whitelist_path)
    
    # Extract URLs directly without printing (to avoid tabulate output)
    url_pattern = re.compile(r"https?://[^\s\"'>]+")
    extracted_urls = {}
    filtered_count = 0
    
    # Import patterns
    from ide_hunter.patterns import HIGH_RISK_FILES
    import fnmatch
    
    # Extract URLs from each extension's files
    for extension in results:
        for file_path in extension.scanned_files:
            # Check if it's a high-risk file
            if not any(
                fnmatch.fnmatch(file_path.name, pattern)
                for pattern in HIGH_RISK_FILES
            ):
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                urls = set(url_pattern.findall(content))
                if urls:
                    # Filter out whitelisted domains
                    filtered_urls = set()
                    for url in urls:
                        if not is_domain_whitelisted(url, whitelist):
                            filtered_urls.add(url)
                        else:
                            filtered_count += 1
                    
                    if filtered_urls:
                        extracted_urls[file_path] = filtered_urls

            except Exception as e:
                console.print(f"[red]Error reading {file_path}: {e}[/red]")
    
    # Display filtering statistics
    if filtered_count > 0:
        console.print(f"[dim]Filtered out {filtered_count} URLs from whitelisted domains[/dim]\n")
    
    if not extracted_urls:
        console.print("[green]No URLs found in scanned files.[/green]")
        return
    
    # Create Rich table for display
    table = Table(title="URLs Found", box=box.ROUNDED)
    table.add_column("File", style="cyan", no_wrap=False)
    table.add_column("URL", style="blue", no_wrap=False)
    
    # Calculate dynamic column widths
    terminal_width = console.size.width
    file_col_width, url_col_width = calculate_dynamic_column_widths(
        terminal_width, 2, [30, 50]
    )
    
    for file_path, url_list in extracted_urls.items():
        for url in url_list:
            file_display = truncate_file_path(str(file_path), file_col_width)
            url_display = truncate_text(url, url_col_width)
            table.add_row(file_display, url_display)
    
    console.print(table)
    
    # Save to file if requested
    if output_file:
        await save_urls_to_file(extracted_urls, output_file)

async def save_urls_to_file(extracted_urls, output_file):
    """Save extracted URLs to a CSV file."""
    directory = os.path.dirname(output_file)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["File Path", "URL"])

        for file_path, urls in extracted_urls.items():
            for url in urls:
                writer.writerow([str(file_path), url])

    console.print(f"[green]URLs saved to: {output_file}[/green]")

async def save_results_to_file(scanner, results, args):
    """Save results to file with Rich feedback."""
    if args.format == "json":
        json_output = OutputFormatter.format_as_json(
            results,
            len(results),
            len(scanner.scanned_files),
            scanner.elapsed_time,
            sum(len(ext.security_issues) for ext in results)
        )
        with open(args.output, 'w') as f:
            f.write(json_output)
        console.print(f"[green]JSON report saved to: {args.output}[/green]")
    else:
        scanner.generate_reports(results, args.output)
        console.print(f"[green]CSV report saved to: {args.output}[/green]")

def display_scan_results(scanner, results, args):
    """Display scan results with Rich formatting."""
    if args.format == "json":
        json_output = OutputFormatter.format_as_json(
            results,
            len(results),
            len(scanner.scanned_files),
            scanner.elapsed_time,
            sum(len(ext.security_issues) for ext in results)
        )
        console.print(Syntax(json_output, "json", theme="monokai", line_numbers=True))
    else:
        display_console_results(scanner, results, args)

def display_console_results(scanner, results, args=None):
    """Display console results with Rich formatting."""
    console.print("\n[bold blue]IDE Extension Security Scan Summary[/bold blue]\n")
    
    # Summary statistics
    total_issues = sum(len(ext.security_issues) for ext in results)
    
    summary_table = Table(title="Scan Statistics", box=box.ROUNDED, show_header=True, header_style="bold green")
    summary_table.add_column("Metric", style="cyan", no_wrap=True)
    summary_table.add_column("Value", style="white", justify="right")
    
    summary_table.add_row("Extensions Scanned", str(len(results)))
    summary_table.add_row("Files Scanned", str(len(scanner.scanned_files)))
    summary_table.add_row("Security Issues Found", str(total_issues))
    summary_table.add_row("Scan Duration", f"{scanner.elapsed_time:.2f}s")
    
    console.print(summary_table)
    console.print()
    
    if not results:
        console.print("[yellow]No extensions found to scan.[/yellow]")
        return
    
    # Extensions overview with dynamic column widths
    terminal_width = console.size.width
    column_widths = calculate_dynamic_column_widths(
        terminal_width, 
        5,  # Extension, Version, Publisher, Issues, Files
        [20, 12, 15, 8, 8]  # Minimum widths
    )
    
    extensions_table = Table(title="Extensions Overview", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    extensions_table.add_column("Extension", style="cyan", no_wrap=True, width=column_widths[0])
    extensions_table.add_column("Version", style="green", width=column_widths[1])
    extensions_table.add_column("Publisher", style="blue", width=column_widths[2])
    extensions_table.add_column("Issues", style="yellow", justify="right", width=column_widths[3])
    extensions_table.add_column("Files", style="dim", justify="right", width=column_widths[4])
    
    for ext in results:
        issues_count = len(ext.security_issues)
        issues_display = f"[red]{issues_count}[/red]" if issues_count > 0 else "[green]0[/green]"
        
        # Truncate text to fit column widths
        ext_name = truncate_text(ext.name, column_widths[0])
        version = truncate_text(ext.version or "Unknown", column_widths[1])
        publisher = truncate_text(ext.publisher or "Unknown", column_widths[2])
        
        extensions_table.add_row(
            ext_name,
            version,
            publisher,
            issues_display,
            str(len(ext.scanned_files))
        )
    
    console.print(extensions_table)
    
    # Security issues by severity
    if total_issues > 0:
        if args.interactive:
            # Group issues by severity for interactive mode
            issues_by_severity = {}
            for ext in results:
                for issue in ext.security_issues:
                    if issue.severity not in issues_by_severity:
                        issues_by_severity[issue.severity] = []
                    issues_by_severity[issue.severity].append((ext.name, issue))
            
            if issues_by_severity:
                console.print("\n[bold green]Interactive Mode Enabled[/bold green]")
                console.print("You can now view full details of each security issue.\n")
                interactive_issue_details(issues_by_severity)
            else:
                console.print("\n[bold green]No security issues found matching the specified criteria![/bold green]")
        else:
            display_security_issues(results)
    else:
        console.print("\n[bold green]No security issues detected![/bold green]")

def display_security_issues(results):
    """Display security issues grouped by severity with Rich formatting."""
    # Group issues by severity
    issues_by_severity = {}
    for ext in results:
        for issue in ext.security_issues:
            if issue.severity not in issues_by_severity:
                issues_by_severity[issue.severity] = []
            issues_by_severity[issue.severity].append((ext.name, issue))
    
    # Check if there are any issues to display
    if not issues_by_severity:
        console.print("\n[bold green]No security issues found matching the specified criteria![/bold green]")
        return
    
    console.print("\n[bold red]Security Issues Found[/bold red]\n")
    
    # Display issues by severity (highest first)
    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim"
    }
    
    for severity in sorted(Severity, key=lambda x: x.value, reverse=True):
        if severity in issues_by_severity:
            issues = issues_by_severity[severity]
            color = severity_colors[severity]
            
            console.print(f"[{color}]{severity.name} Issues ({len(issues)})[/{color}]\n")
            
            # Calculate dynamic column widths for security issues table
            terminal_width = console.size.width
            column_widths = calculate_dynamic_column_widths(
                terminal_width, 
                5,  # Extension, Issue, File, Line, Context
                [20, 25, 30, 6, 40]  # Minimum widths
            )
            
            issues_table = Table(box=box.SIMPLE, show_header=True, header_style=color)
            issues_table.add_column("Extension", style="cyan", no_wrap=True, width=column_widths[0])
            issues_table.add_column("Issue", style="white", width=column_widths[1])
            issues_table.add_column("File", style="dim", width=column_widths[2])
            issues_table.add_column("Line", style="dim", justify="right", width=column_widths[3])
            issues_table.add_column("Context", style="italic", width=column_widths[4])
            
            for ext_name, issue in issues:
                # Truncate content to fit column widths with indicators
                ext_name_truncated = truncate_text(ext_name, column_widths[0])
                if len(ext_name) > column_widths[0]:
                    ext_name_truncated += " [dim]...[/dim]"
                
                issue_desc = truncate_text(issue.description, column_widths[1])
                if len(issue.description) > column_widths[1]:
                    issue_desc += " [dim]...[/dim]"
                
                file_path_truncated = truncate_file_path(str(issue.file_path), column_widths[2])
                if len(str(issue.file_path)) > column_widths[2]:
                    file_path_truncated += " [dim]...[/dim]"
                
                context_truncated = truncate_text(issue.context, column_widths[4])
                if len(issue.context) > column_widths[4]:
                    context_truncated += " [dim]...[/dim]"
                
                issues_table.add_row(
                    ext_name_truncated,
                    issue_desc,
                    file_path_truncated,
                    str(issue.line_number or "N/A"),
                    context_truncated
                )
            
            console.print(issues_table)
            console.print()
    
    # Add helpful message about interactive mode (only once at the end)
    if issues_by_severity:
        console.print("[dim]Tip: Use --interactive flag to view full details of each issue[/dim]")
        console.print()

def run_with_args(args):
    """Run the scanner with the provided arguments."""
    # Set up logging based on debug flag
    if args.debug:
        # Debug logs only to file, not console (reduces output spam)
        setup_logging(logging.DEBUG, console_output=False)
    else:
        # Disable all logging except critical errors
        logging.getLogger().setLevel(logging.CRITICAL)
        # Disable specific loggers
        logging.getLogger('ide_hunter').setLevel(logging.CRITICAL)
        logging.getLogger('ide_hunter.scanner').setLevel(logging.CRITICAL)
        logging.getLogger('ide_hunter.analyzers').setLevel(logging.CRITICAL)
        logging.getLogger('ide_hunter.utils').setLevel(logging.CRITICAL)
    
    return asyncio.run(async_run(args))