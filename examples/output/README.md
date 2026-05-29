# Example Output

These files show what the AI API Security Scanner produces when scanning a typical microservices project.

## Files

| File | Format | Description |
|------|--------|-------------|
| `security-report.json` | JSON | Structured report for automation and CI/CD integration |
| `security-report.xml` | JUnit XML | Test result format for CI/CD dashboards |
| `security-report.html` | HTML | Visual dashboard for human review |

## How these were generated

```bash
api-scanner scan /path/to/microservices-project --format json --output security-report.json
api-scanner scan /path/to/microservices-project --format junit --output security-report.xml
api-scanner scan /path/to/microservices-project --format html --output security-report.html
```

## What to expect

- **Overall score:** 58/100
- **9 findings** across 3 scanner engines
- API Security: 3 findings (missing security schemes, rate limiting, versioning)
- Code Compliance: 6 findings (auth config, authorization, validation, CORS, error handling, logging)
- Vulnerability: 0 findings (no technology-specific issues in scanned project)
