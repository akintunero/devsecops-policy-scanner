#!/usr/bin/env python3
"""
Enhanced CLI Interface for DevSecOps Policy Scanner
Beautiful command-line interface with rich output and advanced features
"""

import typer
import asyncio
from pathlib import Path
from typing import List, Optional, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree
from rich import print as rprint
import json
import yaml

from enhanced_policy_engine import EnhancedPolicyEngine, Severity, ScanResult

app = typer.Typer(
    name="dsp-scanner",
    help="🚀 Enhanced DevSecOps Policy Scanner - Advanced Security Policy Compliance",
    add_completion=False,
    rich_markup_mode="rich"
)

console = Console()

@app.command()
def scan(
    path: str = typer.Argument(
        ...,
        help="Path to scan (file, directory, or configuration object)"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity level (critical, high, medium, low, info)"
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (authentication, encryption, network, etc.)"
    ),
    framework: Optional[str] = typer.Option(
        None,
        "--framework",
        "-f",
        help="Filter by framework (CIS, OWASP, NIST, etc.)"
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for the report"
    ),
    format: str = typer.Option(
        "text",
        "--format",
        help="Output format (text, json, html, csv)"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output"
    ),
):
    """
    🔍 Scan infrastructure code for security issues and compliance violations.
    
    Examples:
    - dsp-scanner scan ./kubernetes-manifests
    - dsp-scanner scan ./docker-compose.yml --severity critical
    - dsp-scanner scan ./terraform --framework CIS --output report.json
    """
    
    try:
        # Initialize policy engine
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Loading policies...", total=None)
            engine = EnhancedPolicyEngine()
            progress.update(task, description="✅ Policies loaded successfully")
        
        # Show scan configuration
        _display_scan_config(
            path=path,
            severity=severity,
            category=category,
            framework=framework,
            format=format
        )
        
        # Load configuration to scan
        config = _load_configuration(path)
        
        # Parse filters
        severity_filter = Severity(severity) if severity else None
        
        # Run the scan
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning configuration...", total=len(engine.policies))
            
            results = engine.scan(
                config=config,
                severity_filter=severity_filter,
                category_filter=category,
                framework_filter=framework
            )
            
            progress.update(task, completed=len(engine.policies), description="✅ Scan completed")
        
        # Display results
        _display_results(results, format, output, verbose)
        
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        raise typer.Exit(1)

@app.command()
def list_policies(
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category"
    ),
    framework: Optional[str] = typer.Option(
        None,
        "--framework",
        "-f",
        help="Filter by framework"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity"
    ),
):
    """
    📋 List all available security policies.
    
    Examples:
    - dsp-scanner list-policies
    - dsp-scanner list-policies --framework CIS
    - dsp-scanner list-policies --severity critical
    """
    
    engine = EnhancedPolicyEngine()
    
    # Apply filters
    policies = engine.policies
    if category:
        policies = [p for p in policies if p.category == category]
    if framework:
        policies = [p for p in policies if p.framework == framework]
    if severity:
        policies = [p for p in policies if p.severity.value == severity]
    
    # Create table
    table = Table(title="🔒 Available Security Policies")
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Category", style="green")
    table.add_column("Framework", style="blue")
    
    for policy in policies:
        severity_color = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "green",
            "info": "blue"
        }.get(policy.severity.value, "white")
        
        table.add_row(
            policy.key,
            policy.description,
            f"[{severity_color}]{policy.severity.value.upper()}[/{severity_color}]",
            policy.category,
            policy.framework or "GENERAL"
        )
    
    console.print(table)
    console.print(f"\n[green]Total policies: {len(policies)}[/green]")

@app.command()
def summary():
    """
    📊 Show policy engine summary and statistics.
    """
    
    engine = EnhancedPolicyEngine()
    summary_data = engine.get_summary()
    
    # Create summary panel
    summary_text = f"""
    [bold]Policy Engine Summary[/bold]
    
    📈 Total Policies: {summary_data['total_policies']}
    🏷️  Categories: {len(summary_data['categories'])}
    📚 Frameworks: {len(summary_data['frameworks'])}
    
    [bold]Severity Distribution:[/bold]
    """
    
    for severity, count in summary_data['severity_distribution'].items():
        if count > 0:
            summary_text += f"\n  • {severity.value.upper()}: {count}"
    
    summary_text += f"""
    
    [bold]Categories:[/bold]
    {', '.join(summary_data['categories'])}
    
    [bold]Frameworks:[/bold]
    {', '.join(summary_data['frameworks']) if summary_data['frameworks'] else 'None'}
    """
    
    panel = Panel(summary_text, title="📊 Policy Engine Statistics", border_style="blue")
    console.print(panel)

@app.command()
def export(
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Export format (json, yaml)"
    ),
    output: str = typer.Option(
        "policies_export",
        "--output",
        "-o",
        help="Output file path (without extension)"
    ),
):
    """
    📤 Export all policies to different formats.
    
    Examples:
    - dsp-scanner export --format json
    - dsp-scanner export --format yaml --output my_policies
    """
    
    engine = EnhancedPolicyEngine()
    
    try:
        if format.lower() == "json":
            output_file = f"{output}.json"
            json_output = engine.export_policies("json", output_file)
            console.print(f"[green]✅ Policies exported to {output_file}[/green]")
        elif format.lower() == "yaml":
            output_file = f"{output}.yaml"
            # Convert to YAML format
            policies_data = []
            for policy in engine.policies:
                policies_data.append({
                    "key": policy.key,
                    "value": policy.value,
                    "description": policy.description,
                    "severity": policy.severity.value,
                    "category": policy.category,
                    "framework": policy.framework,
                    "control_id": policy.control_id,
                    "remediation": policy.remediation,
                    "tags": policy.tags
                })
            
            with open(output_file, 'w') as f:
                yaml.dump(policies_data, f, default_flow_style=False, indent=2)
            console.print(f"[green]✅ Policies exported to {output_file}[/green]")
        else:
            console.print(f"[red]❌ Unsupported format: {format}[/red]")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"[red]Error exporting policies: {e}[/red]")
        raise typer.Exit(1)

def _load_configuration(path: str) -> Dict[str, Any]:
    """Load configuration from file or parse as JSON/YAML"""
    path_obj = Path(path)
    
    if path_obj.exists():
        if path_obj.is_file():
            # Load from file
            with open(path_obj, 'r') as f:
                content = f.read()
                
            if path_obj.suffix.lower() in ['.json']:
                return json.loads(content)
            elif path_obj.suffix.lower() in ['.yaml', '.yml']:
                return yaml.safe_load(content)
            else:
                # Try to parse as JSON or YAML
                try:
                    return json.loads(content)
                except:
                    try:
                        return yaml.safe_load(content)
                    except:
                        console.print(f"[yellow]Warning: Could not parse {path} as JSON or YAML[/yellow]")
                        return {}
    else:
        # Try to parse as JSON string
        try:
            return json.loads(path)
        except:
            console.print(f"[yellow]Warning: {path} is not a valid file path or JSON string[/yellow]")
            return {}

def _display_scan_config(
    path: str,
    severity: Optional[str],
    category: Optional[str],
    framework: Optional[str],
    format: str
):
    """Display scan configuration"""
    config_text = f"""
    [bold]🔍 Scan Configuration[/bold]
    
    📁 Path: {path}
    🎯 Severity Filter: {severity or 'All'}
    🏷️  Category Filter: {category or 'All'}
    📚 Framework Filter: {framework or 'All'}
    📄 Output Format: {format}
    """
    
    panel = Panel(config_text, title="⚙️ Scan Settings", border_style="green")
    console.print(panel)

def _display_results(
    results: List[ScanResult],
    format: str,
    output: Optional[str],
    verbose: bool
):
    """Display scan results"""
    
    if not results:
        console.print("[yellow]No policies matched the scan criteria[/yellow]")
        return
    
    # Calculate statistics
    total = len(results)
    compliant = sum(1 for r in results if r.compliant)
    non_compliant = total - compliant
    total_risk_score = sum(r.risk_score for r in results)
    
    # Display summary
    summary_text = f"""
    [bold]📊 Scan Results Summary[/bold]
    
    ✅ Compliant: {compliant}/{total} ({compliant/total*100:.1f}%)
    ❌ Non-Compliant: {non_compliant}/{total} ({non_compliant/total*100:.1f}%)
    🎯 Total Risk Score: {total_risk_score:.1f}
    """
    
    if total_risk_score > 0:
        summary_text += f"\n[red]⚠️  Security issues detected![/red]"
    else:
        summary_text += f"\n[green]🎉 All policies passed![/green]"
    
    summary_panel = Panel(summary_text, title="📈 Results Summary", border_style="blue")
    console.print(summary_panel)
    
    # Display detailed results
    if verbose or non_compliant > 0:
        table = Table(title="🔍 Detailed Scan Results")
        table.add_column("Status", style="bold")
        table.add_column("Severity", style="bold")
        table.add_column("Policy", style="cyan")
        table.add_column("Message", style="white")
        table.add_column("Risk Score", style="red")
        
        for result in results:
            status = "✅ PASS" if result.compliant else "❌ FAIL"
            status_style = "green" if result.compliant else "red"
            
            severity_color = {
                "critical": "red",
                "high": "orange",
                "medium": "yellow",
                "low": "green",
                "info": "blue"
            }.get(result.policy.severity.value, "white")
            
            table.add_row(
                f"[{status_style}]{status}[/{status_style}]",
                f"[{severity_color}]{result.policy.severity.value.upper()}[/{severity_color}]",
                result.policy.key,
                result.message,
                f"{result.risk_score:.1f}"
            )
        
        console.print(table)
    
    # Save to file if requested
    if output:
        _save_report(results, output, format)

def _save_report(results: List[ScanResult], output: str, format: str):
    """Save scan results to file"""
    try:
        if format.lower() == "json":
            output_file = f"{output}.json"
            data = []
            for result in results:
                data.append({
                    "policy_key": result.policy.key,
                    "compliant": result.compliant,
                    "actual_value": result.actual_value,
                    "message": result.message,
                    "risk_score": result.risk_score,
                    "severity": result.policy.severity.value,
                    "category": result.policy.category,
                    "framework": result.policy.framework
                })
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            console.print(f"[green]✅ Report saved to {output_file}[/green]")
        
        elif format.lower() == "html":
            output_file = f"{output}.html"
            _generate_html_report(results, output_file)
            console.print(f"[green]✅ HTML report saved to {output_file}[/green]")
        
        else:
            console.print(f"[yellow]Warning: Format {format} not supported for file output[/yellow]")
    
    except Exception as e:
        console.print(f"[red]Error saving report: {e}[/red]")

def _generate_html_report(results: List[ScanResult], output_file: str):
    """Generate HTML report"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DevSecOps Policy Scanner Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { text-align: center; color: #333; }
            .summary { background: #f5f5f5; padding: 20px; border-radius: 10px; margin: 20px 0; }
            .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            .table th, .table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            .table th { background-color: #f2f2f2; }
            .pass { color: green; }
            .fail { color: red; }
            .critical { background-color: #ffebee; }
            .high { background-color: #fff3e0; }
            .medium { background-color: #fff8e1; }
            .low { background-color: #f1f8e9; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔒 DevSecOps Policy Scanner Report</h1>
            <p>Security Policy Compliance Analysis</p>
        </div>
    """
    
    # Add summary
    total = len(results)
    compliant = sum(1 for r in results if r.compliant)
    non_compliant = total - compliant
    total_risk_score = sum(r.risk_score for r in results)
    
    html_content += f"""
        <div class="summary">
            <h2>📊 Summary</h2>
            <p><strong>Total Policies:</strong> {total}</p>
            <p><strong>Compliant:</strong> {compliant} ({compliant/total*100:.1f}%)</p>
            <p><strong>Non-Compliant:</strong> {non_compliant} ({non_compliant/total*100:.1f}%)</p>
            <p><strong>Total Risk Score:</strong> {total_risk_score:.1f}</p>
        </div>
        
        <h2>🔍 Detailed Results</h2>
        <table class="table">
            <tr>
                <th>Status</th>
                <th>Severity</th>
                <th>Policy</th>
                <th>Message</th>
                <th>Risk Score</th>
            </tr>
    """
    
    for result in results:
        status_class = "pass" if result.compliant else "fail"
        severity_class = result.policy.severity.value
        status_text = "✅ PASS" if result.compliant else "❌ FAIL"
        
        html_content += f"""
            <tr class="{severity_class}">
                <td class="{status_class}">{status_text}</td>
                <td>{result.policy.severity.value.upper()}</td>
                <td>{result.policy.key}</td>
                <td>{result.message}</td>
                <td>{result.risk_score:.1f}</td>
            </tr>
        """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open(output_file, 'w') as f:
        f.write(html_content)

def main():
    """Main entry point"""
    app()

if __name__ == "__main__":
    main() 