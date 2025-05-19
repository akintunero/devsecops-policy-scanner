"""
Command-line interface for DSP Scanner.
"""

import asyncio
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax

from dsp_scanner.core.scanner import Scanner
from dsp_scanner.core.results import ScanResult, Severity
from dsp_scanner.utils.logger import get_logger

app = typer.Typer(
    name="dsp-scanner",
    help="Advanced DevSecOps Policy Scanner for infrastructure security",
    add_completion=False,
)
console = Console()
logger = get_logger(__name__)

@app.command()
def scan(
    path: str = typer.Argument(
        ...,
        help="Path to scan (file or directory)",
    ),
    platforms: Optional[List[str]] = typer.Option(
        None,
        "--platform",
        "-p",
        help="Platforms to scan (docker, kubernetes, terraform, helm)",
    ),
    compliance: Optional[List[str]] = typer.Option(
        None,
        "--compliance",
        "-c",
        help="Compliance frameworks to check against",
    ),
    severity: str = typer.Option(
        "medium",
        "--severity",
        "-s",
        help="Minimum severity level to report",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for the report",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format (text, json, html)",
    ),
    enable_ai: bool = typer.Option(
        True,
        "--ai/--no-ai",
        help="Enable/disable AI-powered analysis",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
):
    """
    Scan infrastructure code for security issues and compliance violations.
    """
    try:
        # Validate path
        scan_path = Path(path)
        if not scan_path.exists():
            console.print(f"[red]Error:[/red] Path does not exist: {path}")
            raise typer.Exit(1)

        # Show scan configuration
        _display_scan_config(
            path=path,
            platforms=platforms,
            compliance=compliance,
            severity=severity,
            enable_ai=enable_ai,
        )

        # Run the scan
        result = asyncio.run(_run_scan(
            path=scan_path,
            platforms=platforms,
            compliance=compliance,
            severity=severity,
            enable_ai=enable_ai,
        ))

        # Display results
        _display_results(result, format=format)

        # Save report if output path specified
        if output:
            _save_report(result, output, format)

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)

@app.command()
def validate(
    policy_file: str = typer.Argument(
        ...,
        help="Path to policy file to validate",
    ),
):
    """
    Validate a custom policy file.
    """
    try:
        policy_path = Path(policy_file)
        if not policy_path.exists():
            console.print(f"[red]Error:[/red] Policy file does not exist: {policy_file}")
            raise typer.Exit(1)

        # Validate policy
        from dsp_scanner.core.policy import Policy
        policy_content = policy_path.read_text()
        Policy(
            name="validation_test",
            description="Validation test",
            platform="test",
            rego_policy=policy_content,
        )

        console.print("[green]Policy validation successful![/green]")

    except Exception as e:
        console.print(f"[red]Policy validation failed:[/red] {str(e)}")
        raise typer.Exit(1)

@app.command()
def init(
    path: str = typer.Argument(
        ".",
        help="Path to initialize configuration",
    ),
):
    """
    Initialize DSP Scanner configuration in the current directory.
    """
    try:
        config_path = Path(path) / ".dsp-scanner.yml"
        if config_path.exists():
            if not typer.confirm("Configuration file already exists. Overwrite?"):
                raise typer.Exit(0)

        # Create default configuration
        config_content = """# DSP Scanner Configuration
scan:
  platforms:
    - docker
    - kubernetes
    - terraform
    - helm
  severity_threshold: medium
  enable_ai: true
  compliance:
    - cis
    - nist

reporting:
  format: html
  output: security-report
  include_evidence: true

notifications:
  slack:
    enabled: false
    webhook: ""
  email:
    enabled: false
    smtp_server: ""
    recipients: []

integrations:
  github:
    enabled: false
    token: ""
  jira:
    enabled: false
    url: ""
    token: ""
"""
        config_path.write_text(config_content)
        console.print(f"[green]Configuration initialized at {config_path}[/green]")

    except Exception as e:
        console.print(f"[red]Initialization failed:[/red] {str(e)}")
        raise typer.Exit(1)

async def _run_scan(
    path: Path,
    platforms: Optional[List[str]],
    compliance: Optional[List[str]],
    severity: str,
    enable_ai: bool,
) -> ScanResult:
    """Run the security scan."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Initialize scanner
        progress.add_task("Initializing scanner...", total=None)
        scanner = Scanner(
            enable_ai=enable_ai,
            compliance_frameworks=compliance,
            severity_threshold=severity,
        )

        # Run scan
        progress.add_task("Scanning infrastructure code...", total=None)
        result = await scanner.scan_path(
            path=str(path),
            platforms=platforms,
        )

        return result

def _display_scan_config(
    path: str,
    platforms: Optional[List[str]],
    compliance: Optional[List[str]],
    severity: str,
    enable_ai: bool,
):
    """Display scan configuration."""
    table = Table(title="Scan Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Path", path)
    table.add_row("Platforms", ", ".join(platforms) if platforms else "All")
    table.add_row("Compliance", ", ".join(compliance) if compliance else "None")
    table.add_row("Severity Threshold", severity)
    table.add_row("AI Analysis", "Enabled" if enable_ai else "Disabled")

    console.print(table)
    console.print()

def _display_results(result: ScanResult, format: str):
    """Display scan results."""
    if format == "json":
        import json
        console.print_json(json.dumps(result.get_summary()))
        return

    # Display summary
    summary = result.get_summary()
    console.print(Panel.fit(
        f"[bold]Scan Complete![/bold]\n\n"
        f"Total Findings: {summary['total_findings']}\n"
        f"Files Scanned: {summary['scan_metrics']['files_scanned']}\n"
        f"Duration: {summary['scan_metrics']['duration_seconds']:.2f}s",
        title="Summary",
        border_style="green",
    ))
    console.print()

    # Display findings by severity
    table = Table(title="Findings by Severity")
    table.add_column("Severity", style="cyan")
    table.add_column("Count", style="green", justify="right")

    for severity, count in summary["findings_by_severity"].items():
        table.add_row(
            severity.upper(),
            str(count),
        )

    console.print(table)
    console.print()

    # Display detailed findings
    if result.findings:
        console.print("[bold]Detailed Findings:[/bold]")
        for finding in result.findings:
            _display_finding(finding)

def _display_finding(finding):
    """Display a single finding."""
    severity_colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "green",
    }

    panel = Panel(
        f"[bold]{finding.title}[/bold]\n\n"
        f"{finding.description}\n\n"
        f"[bold]Location:[/bold] {finding.location}\n"
        f"[bold]Platform:[/bold] {finding.platform}\n"
        + (f"\n[bold]Code:[/bold]\n{Syntax(finding.code_snippet, 'python')}\n" if finding.code_snippet else "")
        + (f"\n[bold]Recommendation:[/bold]\n{finding.recommendation}" if finding.recommendation else ""),
        title=f"[{severity_colors[finding.severity]}]{finding.severity.value.upper()}[/{severity_colors[finding.severity]}]",
        border_style=severity_colors[finding.severity],
    )
    console.print(panel)
    console.print()

def _save_report(result: ScanResult, output: str, format: str):
    """Save scan results to a file."""
    output_path = Path(output)

    if format == "json":
        import json
        output_path.with_suffix(".json").write_text(
            json.dumps(result.get_summary(), indent=2)
        )
    elif format == "html":
        _generate_html_report(result, output_path.with_suffix(".html"))
    else:
        # Default to text format
        with console.capture() as capture:
            _display_results(result, format="text")
        output_path.with_suffix(".txt").write_text(capture.get())

    console.print(f"[green]Report saved to {output_path}[/green]")

def _generate_html_report(result: ScanResult, output_path: Path):
    """Generate HTML report."""
    # Implementation of HTML report generation
    pass

def main():
    """Main entry point."""
    app()

if __name__ == "__main__":
    main()
