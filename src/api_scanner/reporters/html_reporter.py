"""HTML dashboard report generator."""

from api_scanner.core.models import ScanReport


def export_html(report: ScanReport) -> str:
    """Export scan report as HTML dashboard."""
    high_count = sum(1 for f in report.all_findings if f.severity == "HIGH")
    medium_count = sum(1 for f in report.all_findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in report.all_findings if f.severity == "LOW")

    findings_html = ""
    for finding in sorted(report.all_findings, key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.severity, 3)):
        severity_class = finding.severity.lower()
        findings_html += f"""
        <div class="finding {severity_class}">
            <div class="finding-header">
                <span class="badge {severity_class}">{finding.severity}</span>
                <strong>[{finding.rule_id}] {finding.title}</strong>
            </div>
            <p>{finding.description}</p>
            <div class="details">
                <p><strong>Category:</strong> {finding.category}</p>
                {"<p><strong>File:</strong> " + finding.file_path + "</p>" if finding.file_path else ""}
                <p><strong>Remediation:</strong> {finding.remediation}</p>
                {"<p><strong>OWASP:</strong> " + finding.owasp_ref + "</p>" if finding.owasp_ref else ""}
                {"<p><strong>CWE:</strong> " + finding.cwe_id + "</p>" if finding.cwe_id else ""}
            </div>
        </div>"""

    scanner_cards = ""
    for sr in report.scanner_results:
        score_class = "good" if sr.score >= 70 else "warning" if sr.score >= 50 else "critical"
        scanner_cards += f"""
        <div class="scanner-card">
            <h3>{sr.name}</h3>
            <div class="score {score_class}">{sr.score}/100</div>
            <p>{sr.checks_passed}/{sr.checks_total} checks passed | {len(sr.findings)} findings</p>
        </div>"""

    score_class = "good" if report.overall_score >= 70 else "warning" if report.overall_score >= 50 else "critical"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; padding: 2rem; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ margin-bottom: 0.5rem; }}
        .subtitle {{ color: #666; margin-bottom: 2rem; }}
        .overall-score {{ text-align: center; padding: 2rem; background: white; border-radius: 8px; margin-bottom: 2rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .overall-score .score {{ font-size: 3rem; font-weight: bold; }}
        .overall-score .score.good {{ color: #22c55e; }}
        .overall-score .score.warning {{ color: #f59e0b; }}
        .overall-score .score.critical {{ color: #ef4444; }}
        .scanners {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .scanner-card {{ background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .scanner-card .score {{ font-size: 1.5rem; font-weight: bold; margin: 0.5rem 0; }}
        .scanner-card .score.good {{ color: #22c55e; }}
        .scanner-card .score.warning {{ color: #f59e0b; }}
        .scanner-card .score.critical {{ color: #ef4444; }}
        .findings-section {{ background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding {{ border-left: 4px solid #ccc; padding: 1rem; margin: 1rem 0; background: #fafafa; border-radius: 0 4px 4px 0; }}
        .finding.high {{ border-color: #ef4444; }}
        .finding.medium {{ border-color: #f59e0b; }}
        .finding.low {{ border-color: #3b82f6; }}
        .finding-header {{ margin-bottom: 0.5rem; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; color: white; }}
        .badge.high {{ background: #ef4444; }}
        .badge.medium {{ background: #f59e0b; }}
        .badge.low {{ background: #3b82f6; }}
        .details {{ margin-top: 0.5rem; font-size: 0.9rem; color: #555; }}
        .summary {{ display: flex; gap: 1rem; justify-content: center; margin: 1rem 0; }}
        .summary-item {{ padding: 0.5rem 1rem; border-radius: 4px; background: #f0f0f0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>API Security Scan Report</h1>
        <p class="subtitle">Project: {report.project_path} | Generated: {report.timestamp}</p>

        <div class="overall-score">
            <div class="score {score_class}">{report.overall_score}/100</div>
            <p>Overall Security Score</p>
            <div class="summary">
                <span class="summary-item">🔴 High: {high_count}</span>
                <span class="summary-item">🟡 Medium: {medium_count}</span>
                <span class="summary-item">🔵 Low: {low_count}</span>
            </div>
        </div>

        <div class="scanners">{scanner_cards}</div>

        <div class="findings-section">
            <h2>Findings ({len(report.all_findings)})</h2>
            {findings_html if findings_html else "<p>No findings — all checks passed!</p>"}
        </div>
    </div>
</body>
</html>"""
