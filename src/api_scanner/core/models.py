"""Data models for scan findings and reports."""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timezone


@dataclass
class Finding:
    """A single security finding."""

    rule_id: str
    title: str
    description: str
    severity: str  # HIGH, MEDIUM, LOW
    category: str  # e.g., "API Security", "Code Compliance", "Vulnerability"
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation: str = ""
    owasp_ref: Optional[str] = None  # e.g., "API1:2023 - Broken Object Level Authorization"
    cwe_id: Optional[str] = None


@dataclass
class ScannerResult:
    """Result from a single scanner engine."""

    name: str
    score: int  # 0-100
    findings: List[Finding] = field(default_factory=list)
    checks_passed: int = 0
    checks_total: int = 0


@dataclass
class ScanReport:
    """Complete scan report — output of the orchestrator."""

    project_path: str
    overall_score: int
    scanner_results: List[ScannerResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = "1.0.0"

    @property
    def all_findings(self) -> List[Finding]:
        """Get all findings across all scanners."""
        findings = []
        for sr in self.scanner_results:
            findings.extend(sr.findings)
        return findings

    @property
    def passed(self) -> bool:
        """Whether the scan passed the minimum score threshold."""
        return self.overall_score >= 50
