"""Main scanner orchestrator — runs all sub-scanners and aggregates results."""

from api_scanner.core.config import ScanConfig
from api_scanner.core.models import ScanReport, ScannerResult
from api_scanner.scanners.api_security import APISecurityScanner
from api_scanner.scanners.code_compliance import CodeComplianceScanner
from api_scanner.scanners.vulnerability import VulnerabilityScanner


class SecurityScanner:
    """Orchestrates all security scanning engines.

    Runs three scanner engines sequentially:
    1. API Security — OpenAPI spec, security schemes, HTTPS, rate limiting
    2. Code Compliance — Auth, validation, secrets, CORS, error handling
    3. Vulnerability — Technology-specific code pattern scanning

    Calculates overall score as weighted average.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.scanners = [
            APISecurityScanner(config),
            CodeComplianceScanner(config),
            VulnerabilityScanner(config),
        ]

    def run(self) -> ScanReport:
        """Run all scanners and produce aggregated report."""
        results = []

        for scanner in self.scanners:
            result = scanner.scan()
            results.append(result)

        # Calculate overall score (average of all scanner scores)
        if results:
            overall_score = sum(r.score for r in results) // len(results)
        else:
            overall_score = 0

        return ScanReport(
            project_path=str(self.config.project_path),
            overall_score=overall_score,
            scanner_results=results,
        )
