"""API Security Scanner — checks OpenAPI specs, security schemes, HTTPS, rate limiting."""

import re
from pathlib import Path
from typing import List

from api_scanner.core.config import ScanConfig
from api_scanner.core.models import Finding, ScannerResult
from api_scanner.scanners.base import BaseScanner


class APISecurityScanner(BaseScanner):
    """Scans for API-level security issues.

    Checks:
    1. OpenAPI/Swagger specification exists
    2. Security schemes defined (Bearer, OAuth2, API Key)
    3. HTTPS enforcement (no http:// in specs)
    4. Input validation patterns (minLength, maxLength, pattern)
    5. Rate limiting configuration
    6. API versioning strategy
    """

    name = "API Security Audit"

    def scan(self) -> ScannerResult:
        findings = []
        checks_passed = 0
        checks_total = 6

        # Find relevant files
        yaml_files = self.find_files(("*.yml", "*.yaml", "*.json"))
        java_files = self.find_files(("*.java",))
        all_files = yaml_files + java_files

        # Check 1: OpenAPI specification exists
        if self._check_openapi_exists(yaml_files, java_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="API-001",
                title="Missing OpenAPI Specification",
                description="No OpenAPI/Swagger specification found. API documentation is essential for security review and client validation.",
                severity="MEDIUM",
                category="API Security",
                remediation="Create an openapi.yaml or swagger.json file documenting all API endpoints, request/response schemas, and security requirements.",
                owasp_ref="API9:2023 - Improper Inventory Management",
            ))

        # Check 2: Security schemes defined
        if self._check_security_schemes(yaml_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="API-002",
                title="Missing Security Scheme Definitions",
                description="No security schemes (Bearer, OAuth2, API Key) found in API specifications.",
                severity="HIGH",
                category="API Security",
                remediation="Define securitySchemes in your OpenAPI spec with bearerAuth, oauth2, or apiKey schemes and apply them to endpoints.",
                owasp_ref="API2:2023 - Broken Authentication",
                cwe_id="CWE-306",
            ))

        # Check 3: HTTPS enforcement
        if self._check_https_enforcement(all_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="API-003",
                title="Insecure HTTP Endpoints Detected",
                description="Found http:// URLs in configuration or API specs. All API communication must use HTTPS.",
                severity="HIGH",
                category="API Security",
                remediation="Replace all http:// URLs with https:// and configure TLS certificates. Add 'schemes: [https]' to OpenAPI spec.",
                owasp_ref="API8:2023 - Security Misconfiguration",
                cwe_id="CWE-319",
            ))

        # Check 4: Input validation
        if self._check_input_validation(all_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="API-004",
                title="Missing Input Validation Patterns",
                description="No input validation constraints (minLength, maxLength, pattern, @Valid) found in API definitions.",
                severity="MEDIUM",
                category="API Security",
                remediation="Add validation constraints to all request parameters: minLength, maxLength, pattern, minimum, maximum in OpenAPI spec or @Valid annotations in code.",
                owasp_ref="API3:2023 - Broken Object Property Level Authorization",
                cwe_id="CWE-20",
            ))

        # Check 5: Rate limiting
        if self._check_rate_limiting(all_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="API-005",
                title="No Rate Limiting Configuration",
                description="No rate limiting mechanism detected. APIs without rate limiting are vulnerable to abuse and denial of service.",
                severity="MEDIUM",
                category="API Security",
                remediation="Implement rate limiting using Bucket4j (Java), express-rate-limit (Node.js), or API Gateway throttling. Configure per-user and per-IP limits.",
                owasp_ref="API4:2023 - Unrestricted Resource Consumption",
                cwe_id="CWE-770",
            ))

        # Check 6: API versioning
        if self._check_api_versioning(all_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="API-006",
                title="Missing API Versioning Strategy",
                description="No API versioning pattern detected (/v1/, /v2/, version headers). Versioning enables safe deprecation of insecure endpoints.",
                severity="LOW",
                category="API Security",
                remediation="Implement URL-based versioning (/api/v1/) or header-based versioning (Accept: application/vnd.api.v1+json).",
                owasp_ref="API9:2023 - Improper Inventory Management",
            ))

        score = self.calculate_score(checks_passed, checks_total)

        return ScannerResult(
            name=self.name,
            score=score,
            findings=findings,
            checks_passed=checks_passed,
            checks_total=checks_total,
        )

    def _check_openapi_exists(self, yaml_files: List[Path], java_files: List[Path]) -> bool:
        """Check if OpenAPI/Swagger spec exists."""
        openapi_keywords = ["openapi", "swagger", "paths:", "info:"]

        for f in yaml_files:
            content = self.read_file_safe(f)
            if any(kw in content.lower() for kw in openapi_keywords):
                return True

        # Check for Java annotations
        for f in java_files:
            content = self.read_file_safe(f)
            if "@OpenAPIDefinition" in content or "@Api(" in content:
                return True

        return False

    def _check_security_schemes(self, yaml_files: List[Path]) -> bool:
        """Check if security schemes are defined."""
        scheme_keywords = ["securityschemes", "bearerauth", "oauth2", "apikey", "security:"]

        for f in yaml_files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in scheme_keywords):
                return True
        return False

    def _check_https_enforcement(self, files: List[Path]) -> bool:
        """Check that no insecure HTTP URLs are used in configs."""
        http_pattern = re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)')

        for f in files:
            content = self.read_file_safe(f)
            if http_pattern.search(content):
                return False
        return True

    def _check_input_validation(self, files: List[Path]) -> bool:
        """Check for input validation patterns."""
        validation_keywords = [
            "minlength", "maxlength", "pattern:", "@valid", "@pattern",
            "@size", "@notnull", "@notblank", "minimum:", "maximum:",
            "joi.string()", "zod.string()", "class-validator",
        ]

        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in validation_keywords):
                return True
        return False

    def _check_rate_limiting(self, files: List[Path]) -> bool:
        """Check for rate limiting configuration."""
        rate_keywords = [
            "bucket4j", "ratelimit", "rate-limit", "rate_limit",
            "throttle", "x-ratelimit", "express-rate-limit",
            "@ratelimited", "rateLimiter",
        ]

        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in rate_keywords):
                return True
        return False

    def _check_api_versioning(self, files: List[Path]) -> bool:
        """Check for API versioning patterns."""
        version_patterns = [r'/v\d+/', r'/api/v\d+', r'version.*header', r'api-version']

        for f in files:
            content = self.read_file_safe(f).lower()
            for pattern in version_patterns:
                if re.search(pattern, content):
                    return True
        return False
