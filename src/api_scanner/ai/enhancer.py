"""AI Enhancement Engine — enriches static scan findings with LLM intelligence.

This module takes raw findings from the static scanners and enhances them with:
1. False positive detection — AI reads the code context and determines if the finding is real
2. Smart remediation — AI generates fix suggestions specific to the actual code
3. Risk prioritization — AI ranks findings by real-world exploitability
4. Attack scenario — AI describes how an attacker would exploit the issue
"""

from typing import List, Optional
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage

from api_scanner.ai.config import AIConfig
from api_scanner.ai.llm import create_llm
from api_scanner.core.models import Finding, ScanReport


SYSTEM_PROMPT = """You are an expert application security engineer reviewing static analysis findings.

For each finding, you will:
1. Determine if it's a TRUE POSITIVE or FALSE POSITIVE based on the code context
2. If true positive: provide a specific remediation with a code fix example
3. Assess real-world exploitability (Critical/High/Medium/Low)
4. Describe a brief attack scenario (1-2 sentences)

Be precise and actionable. Don't give generic advice — reference the actual code."""


class AIEnhancer:
    """Enhances static scan findings with AI-powered analysis.

    The enhancer is OPTIONAL — the scanner works without it.
    When enabled, it post-processes findings to:
    - Filter false positives
    - Generate context-aware remediation
    - Prioritize by real exploitability
    - Add attack scenarios
    """

    def __init__(self, config: AIConfig):
        self.config = config
        self.llm = create_llm(config)

    def enhance_report(self, report: ScanReport, project_path: Path) -> ScanReport:
        """Enhance all findings in a scan report with AI analysis.

        Args:
            report: Raw scan report from static scanners
            project_path: Path to project (for reading code context)

        Returns:
            Enhanced report with AI-enriched findings
        """
        for scanner_result in report.scanner_results:
            enhanced_findings = []
            for finding in scanner_result.findings:
                enhanced = self._enhance_finding(finding, project_path)
                if enhanced:  # None means AI determined it's a false positive
                    enhanced_findings.append(enhanced)

            # Update findings (false positives removed)
            removed_count = len(scanner_result.findings) - len(enhanced_findings)
            scanner_result.findings = enhanced_findings

            # Recalculate score (fewer findings = higher score)
            if scanner_result.checks_total > 0:
                failed = len(enhanced_findings)
                passed = scanner_result.checks_total - failed
                scanner_result.checks_passed = max(0, passed)
                scanner_result.score = int((scanner_result.checks_passed / scanner_result.checks_total) * 100)

        # Recalculate overall score
        if report.scanner_results:
            report.overall_score = sum(sr.score for sr in report.scanner_results) // len(report.scanner_results)

        return report

    def _enhance_finding(self, finding: Finding, project_path: Path) -> Optional[Finding]:
        """Enhance a single finding with AI analysis.

        Returns:
            Enhanced finding, or None if AI determines it's a false positive.
        """
        # Get code context if file path is available
        code_context = ""
        if finding.file_path:
            full_path = project_path / finding.file_path
            if full_path.exists():
                try:
                    content = full_path.read_text(encoding="utf-8", errors="ignore")
                    # Get surrounding lines if line number is known
                    if finding.line_number:
                        lines = content.split('\n')
                        start = max(0, finding.line_number - 5)
                        end = min(len(lines), finding.line_number + 10)
                        code_context = '\n'.join(lines[start:end])
                    else:
                        # Take first 2000 chars as context
                        code_context = content[:2000]
                except (OSError, PermissionError):
                    pass

        prompt = f"""Analyze this security finding:

**Rule:** {finding.rule_id}
**Title:** {finding.title}
**Severity:** {finding.severity}
**Description:** {finding.description}
**File:** {finding.file_path or 'N/A'}
**Line:** {finding.line_number or 'N/A'}

**Code Context:**
```
{code_context if code_context else '[No code context available]'}
```

Respond in this exact format:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
EXPLOITABILITY: Critical, High, Medium, or Low
ATTACK_SCENARIO: [1-2 sentence description of how this could be exploited]
REMEDIATION: [Specific fix for this code, with example if possible]"""

        try:
            messages = [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ]

            response = self.llm.invoke(messages)
            result_text = response.content

            # Parse response
            if "FALSE_POSITIVE" in result_text:
                return None  # AI says it's not a real issue

            # Extract enhanced fields
            enhanced_finding = Finding(
                rule_id=finding.rule_id,
                title=finding.title,
                description=finding.description,
                severity=self._extract_field(result_text, "EXPLOITABILITY", finding.severity),
                category=finding.category,
                file_path=finding.file_path,
                line_number=finding.line_number,
                remediation=self._extract_field(result_text, "REMEDIATION", finding.remediation),
                owasp_ref=finding.owasp_ref,
                cwe_id=finding.cwe_id,
            )

            # Add attack scenario to description
            attack = self._extract_field(result_text, "ATTACK_SCENARIO", "")
            if attack:
                enhanced_finding.description = f"{finding.description}\n\n**Attack Scenario:** {attack}"

            return enhanced_finding

        except Exception:
            # If AI fails, return original finding unchanged
            return finding

    def _extract_field(self, text: str, field_name: str, default: str) -> str:
        """Extract a field value from the LLM response."""
        for line in text.split('\n'):
            if line.strip().startswith(f"{field_name}:"):
                value = line.split(":", 1)[1].strip()
                return value if value else default
        return default
