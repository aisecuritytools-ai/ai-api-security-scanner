"""CLI entry point for AI API Security Scanner."""

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from api_scanner.core.config import ScanConfig
from api_scanner.core.scanner import SecurityScanner
from api_scanner.ai.config import AIConfig, AIProvider
from api_scanner.reporters.json_reporter import export_json
from api_scanner.reporters.junit_reporter import export_junit
from api_scanner.reporters.html_reporter import export_html

app = typer.Typer(
    name="api-scanner",
    help="AI API Security Scanner — Automated API security compliance scanning for CI/CD.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to project directory to scan"),
    min_score: int = typer.Option(50, "--min-score", help="Minimum passing score (0-100)"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, junit, html"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    fail_on_issues: bool = typer.Option(False, "--fail-on-issues", help="Exit with code 1 if below threshold"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed scan progress"),
    ai_provider: str = typer.Option("none", "--ai", help="AI provider for enhanced analysis: none, bedrock, openai, ollama"),
    ai_model: str = typer.Option(None, "--ai-model", help="AI model ID (auto-detected if not set)"),
):
    """Scan a project directory for API security issues."""

    # Validate path
    if not path.exists():
        console.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(1)

    if not path.is_dir():
        console.print(f"[red]Error:[/red] Path is not a directory: {path}")
        raise typer.Exit(1)

    # Build config
    config = ScanConfig(
        project_path=path,
        min_score=min_score,
        fail_on_issues=fail_on_issues,
        verbose=verbose,
    )

    # Build AI config
    try:
        ai_config = AIConfig(
            provider=AIProvider(ai_provider),
            model_id=ai_model,
        )
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    # Display header
    ai_status = f" | AI: {ai_config.provider.value} ({ai_config.get_model_id()})" if ai_config.enabled else ""
    console.print(Panel.fit(
        f"[bold blue]AI API Security Scanner[/bold blue]\n"
        f"Scanning: {path.resolve()}{ai_status}",
        border_style="blue",
    ))

    # Run static scan
    scanner = SecurityScanner(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        disable=not verbose,
    ) as progress:
        task = progress.add_task("Running static security scan...", total=None)
        result = scanner.run()
        progress.update(task, description="Static scan complete!")

    # Run AI enhancement if enabled
    if ai_config.enabled:
        from api_scanner.ai.enhancer import AIEnhancer

        console.print("\n[cyan]🤖 Running AI-enhanced analysis...[/cyan]")
        enhancer = AIEnhancer(ai_config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("AI analyzing findings...", total=None)
            original_count = len(result.all_findings)
            result = enhancer.enhance_report(result, path)
            removed = original_count - len(result.all_findings)
            progress.update(task, description=f"AI analysis complete! ({removed} false positives removed)")

    # Display results
    console.print()

    # Score table
    table = Table(title="Scan Results", show_header=True)
    table.add_column("Scanner", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")

    for scanner_result in result.scanner_results:
        score_color = "green" if scanner_result.score >= 70 else "yellow" if scanner_result.score >= 50 else "red"
        table.add_row(
            scanner_result.name,
            f"[{score_color}]{scanner_result.score}/100[/{score_color}]",
            str(len(scanner_result.findings)),
        )

    console.print(table)

    # Overall score
    pass_fail = "[green]✓ PASS[/green]" if result.overall_score >= min_score else "[red]✗ FAIL[/red]"
    console.print(f"\n[bold]Overall Security Score: {result.overall_score}/100[/bold]  {pass_fail} (threshold: {min_score})")

    # Finding summary
    high = sum(1 for f in result.all_findings if f.severity == "HIGH")
    medium = sum(1 for f in result.all_findings if f.severity == "MEDIUM")
    low = sum(1 for f in result.all_findings if f.severity == "LOW")
    console.print(f"Findings: {len(result.all_findings)} total ({high} high, {medium} medium, {low} low)")

    if ai_config.enabled:
        console.print(f"[dim]AI enhanced: {removed} false positives filtered, remediation enriched[/dim]")

    # Export
    if output is None:
        ext_map = {"json": ".json", "junit": ".xml", "html": ".html"}
        output = Path(f"security-report{ext_map.get(format, '.json')}")

    if format == "junit":
        content = export_junit(result)
    elif format == "html":
        content = export_html(result)
    else:
        content = export_json(result)

    output.write_text(content)
    console.print(f"\n[green]✓[/green] Report saved to: {output}")

    # Exit code
    if fail_on_issues and result.overall_score < min_score:
        raise typer.Exit(1)


@app.command()
def version():
    """Show scanner version."""
    from api_scanner import __version__
    console.print(f"api-scanner v{__version__}")


if __name__ == "__main__":
    app()
