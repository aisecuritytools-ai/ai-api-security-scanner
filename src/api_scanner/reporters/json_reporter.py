"""JSON report generator."""

import json
from dataclasses import asdict
from api_scanner.core.models import ScanReport


def export_json(report: ScanReport) -> str:
    """Export scan report as formatted JSON."""
    data = asdict(report)
    return json.dumps(data, indent=2, default=str)
