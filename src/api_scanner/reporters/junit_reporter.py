"""JUnit XML report generator — for CI/CD test result integration."""

from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString

from api_scanner.core.models import ScanReport


def export_junit(report: ScanReport) -> str:
    """Export scan report as JUnit XML."""
    testsuites = Element("testsuites")
    testsuites.set("name", "API Security Scan")
    testsuites.set("tests", str(len(report.all_findings)))
    testsuites.set("failures", str(sum(1 for f in report.all_findings if f.severity == "HIGH")))

    for scanner_result in report.scanner_results:
        testsuite = SubElement(testsuites, "testsuite")
        testsuite.set("name", scanner_result.name)
        testsuite.set("tests", str(scanner_result.checks_total))
        testsuite.set("failures", str(len(scanner_result.findings)))

        # Add passed checks
        for i in range(scanner_result.checks_passed):
            testcase = SubElement(testsuite, "testcase")
            testcase.set("name", f"{scanner_result.name} - Check {i + 1}")
            testcase.set("classname", scanner_result.name)

        # Add findings as failures
        for finding in scanner_result.findings:
            testcase = SubElement(testsuite, "testcase")
            testcase.set("name", f"[{finding.rule_id}] {finding.title}")
            testcase.set("classname", finding.category)

            if finding.severity == "HIGH":
                failure = SubElement(testcase, "failure")
            else:
                failure = SubElement(testcase, "error")

            failure.set("message", finding.title)
            failure.set("type", finding.severity)
            failure.text = (
                f"{finding.description}\n\n"
                f"Severity: {finding.severity}\n"
                f"File: {finding.file_path or 'N/A'}\n"
                f"Remediation: {finding.remediation}\n"
                f"OWASP: {finding.owasp_ref or 'N/A'}\n"
                f"CWE: {finding.cwe_id or 'N/A'}"
            )

    raw_xml = tostring(testsuites, encoding="unicode")
    return parseString(raw_xml).toprettyxml(indent="  ")
