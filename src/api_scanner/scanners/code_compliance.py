"""Code Compliance Scanner — checks auth, validation, secrets, CORS, error handling."""

import re
from pathlib import Path
from typing import List

from api_scanner.core.config import ScanConfig
from api_scanner.core.models import Finding, ScannerResult
from api_scanner.scanners.base import BaseScanner


# Patterns that indicate hardcoded secrets
SECRET_PATTERNS = [
    (r'password\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
    (r'api[_-]?key\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
    (r'secret\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret"),
    (r'token\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']', "Hardcoded token"),
    (r'(AKIA|ASIA)[A-Z0-9]{16}', "AWS Access Key"),
]


class CodeComplianceScanner(BaseScanner):
    """Scans for code-level security compliance issues.

    Checks:
    1. OAuth2/JWT configuration present
    2. Authorization annotations/middleware
    3. Input validation annotations
    4. No hardcoded secrets
    5. HTTPS/TLS enforcement
    6. CORS configuration
    7. Error handling (global exception handlers)
    8. Security logging configuration
    """

    name = "Code Compliance"

    def scan(self) -> ScannerResult:
        findings = []
        checks_passed = 0
        checks_total = 8

        # Gather all source files
        java_files = self.find_files(("*.java",))
        ts_files = self.find_files(("*.ts", "*.tsx", "*.js"))
        config_files = self.find_files(("*.yml", "*.yaml", "*.properties", "*.env"))
        all_source = java_files + ts_files
        all_files = all_source + config_files

        # Check 1: OAuth2/JWT configuration
        if self._check_auth_config(all_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="CC-001",
                title="Missing OAuth2/JWT Configuration",
                description="No OAuth2 or JWT authentication configuration found. APIs must authenticate requests.",
                severity="HIGH",
                category="Code Compliance",
                remediation="Configure Spring Security OAuth2 Resource Server or implement JWT validation middleware.",
                owasp_ref="API2:2023 - Broken Authentication",
                cwe_id="CWE-306",
            ))

        # Check 2: Authorization annotations
        if self._check_authorization(all_source):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="CC-002",
                title="Missing Authorization Controls",
                description="No authorization annotations or middleware found. Endpoints may be accessible without proper access control.",
                severity="HIGH",
                category="Code Compliance",
                remediation="Add @PreAuthorize, @Secured, or @RolesAllowed annotations (Java) or auth middleware (Node.js) to all endpoints.",
                owasp_ref="API1:2023 - Broken Object Level Authorization",
                cwe_id="CWE-862",
            ))

        # Check 3: Input validation
        if self._check_input_validation(all_source):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="CC-003",
                title="Missing Input Validation",
                description="No input validation annotations or middleware detected. User input must be validated before processing.",
                severity="MEDIUM",
                category="Code Compliance",
                remediation="Add @Valid, @Pattern, @Size annotations (Java) or Joi/Zod validation schemas (Node.js) to all request handlers.",
                owasp_ref="API3:2023 - Broken Object Property Level Authorization",
                cwe_id="CWE-20",
            ))

        # Check 4: No hardcoded secrets
        secret_findings = self._check_hardcoded_secrets(all_files)
        if not secret_findings:
            checks_passed += 1
        else:
            findings.extend(secret_findings)

        # Check 5: HTTPS/TLS enforcement
        if self._check_https_config(config_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="CC-005",
                title="Missing HTTPS/TLS Configuration",
                description="No SSL/TLS configuration found. All API traffic must be encrypted in transit.",
                severity="HIGH",
                category="Code Compliance",
                remediation="Configure server.ssl.enabled=true (Spring Boot) or use HTTPS termination at load balancer/reverse proxy.",
                owasp_ref="API8:2023 - Security Misconfiguration",
                cwe_id="CWE-319",
            ))

        # Check 6: CORS configuration
        if self._check_cors_config(all_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="CC-006",
                title="Missing CORS Configuration",
                description="No CORS configuration found. Without explicit CORS policy, browsers may block legitimate requests or allow unauthorized origins.",
                severity="MEDIUM",
                category="Code Compliance",
                remediation="Configure explicit CORS origins (never use '*' in production). Set allowed methods, headers, and credentials policy.",
                owasp_ref="API8:2023 - Security Misconfiguration",
                cwe_id="CWE-942",
            ))

        # Check 7: Error handling
        if self._check_error_handling(all_source):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="CC-007",
                title="Missing Global Error Handler",
                description="No global exception handler found. Unhandled errors may leak stack traces and internal details to clients.",
                severity="MEDIUM",
                category="Code Compliance",
                remediation="Implement @ControllerAdvice (Java) or global error middleware (Node.js) that returns sanitized error responses.",
                owasp_ref="API8:2023 - Security Misconfiguration",
                cwe_id="CWE-209",
            ))

        # Check 8: Logging configuration
        if self._check_logging(all_files):
            checks_passed += 1
        else:
            findings.append(Finding(
                rule_id="CC-008",
                title="Missing Security Logging",
                description="No security event logging configuration found. Security events must be logged for audit and incident response.",
                severity="LOW",
                category="Code Compliance",
                remediation="Configure structured logging for authentication events, authorization failures, and input validation errors.",
                owasp_ref="API9:2023 - Improper Inventory Management",
                cwe_id="CWE-778",
            ))

        score = self.calculate_score(checks_passed, checks_total)

        return ScannerResult(
            name=self.name,
            score=score,
            findings=findings,
            checks_passed=checks_passed,
            checks_total=checks_total,
        )

    def _check_auth_config(self, files: List[Path]) -> bool:
        auth_keywords = [
            "oauth2", "jwt", "spring.security", "bearer",
            "jsonwebtoken", "passport", "auth0", "keycloak",
            "cognito", "firebase.auth",
        ]
        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in auth_keywords):
                return True
        return False

    def _check_authorization(self, files: List[Path]) -> bool:
        auth_keywords = [
            "@preauthorize", "@secured", "@rolesallowed",
            "hasrole(", "hasauthority(", "middleware",
            "authorize", "canactivate", "guard",
        ]
        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in auth_keywords):
                return True
        return False

    def _check_input_validation(self, files: List[Path]) -> bool:
        validation_keywords = [
            "@valid", "@pattern", "@size", "@notnull",
            "@notblank", "@min", "@max", "joi.", "zod.",
            "class-validator", "express-validator",
        ]
        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in validation_keywords):
                return True
        return False

    def _check_hardcoded_secrets(self, files: List[Path]) -> List[Finding]:
        findings = []
        for f in files:
            # Skip test files and example files
            if "test" in str(f).lower() or "example" in str(f).lower():
                continue
            content = self.read_file_safe(f)
            for pattern, description in SECRET_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Calculate line number
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(Finding(
                        rule_id="CC-004",
                        title=f"Hardcoded Secret: {description}",
                        description=f"Potential hardcoded credential found. Secrets must be stored in environment variables or a secrets manager.",
                        severity="HIGH",
                        category="Code Compliance",
                        file_path=str(f.relative_to(self.config.project_path)),
                        line_number=line_num,
                        remediation="Move secrets to environment variables, AWS Secrets Manager, or HashiCorp Vault. Never commit secrets to source control.",
                        owasp_ref="API8:2023 - Security Misconfiguration",
                        cwe_id="CWE-798",
                    ))
        return findings

    def _check_https_config(self, files: List[Path]) -> bool:
        ssl_keywords = ["ssl", "tls", "https", "server.ssl.enabled", "force_ssl"]
        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in ssl_keywords):
                return True
        return False

    def _check_cors_config(self, files: List[Path]) -> bool:
        cors_keywords = ["cors", "access-control-allow-origin", "allowedorigins"]
        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in cors_keywords):
                return True
        return False

    def _check_error_handling(self, files: List[Path]) -> bool:
        error_keywords = [
            "@controlleradvice", "@exceptionhandler",
            "app.use(err", "errorhandler", "globalfilter",
            "catch(", "try {",
        ]
        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in error_keywords):
                return True
        return False

    def _check_logging(self, files: List[Path]) -> bool:
        log_keywords = [
            "logger", "logging", "log4j", "logback", "slf4j",
            "winston", "pino", "morgan", "bunyan",
        ]
        for f in files:
            content = self.read_file_safe(f).lower()
            if any(kw in content for kw in log_keywords):
                return True
        return False
