# Getting Started

## Installation

```bash
git clone https://github.com/aisecuritytools-ai/ai-api-security-scanner.git
cd ai-api-security-scanner
pip install -e .
```

## First Scan

```bash
# Scan your project
api-scanner scan /path/to/your/project

# Scan with HTML report
api-scanner scan . --format html --output report.html

# Scan with strict threshold
api-scanner scan . --min-score 70 --fail-on-issues
```

## Docker Usage

```bash
# Build
docker build -t api-scanner .

# Scan a project
docker run -v /path/to/project:/project api-scanner scan /project
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install ai-api-security-scanner
      - run: api-scanner scan . --min-score 60 --fail-on-issues --format junit --output results.xml
      - uses: dorny/test-reporter@v1
        if: always()
        with:
          name: Security Findings
          path: results.xml
          reporter: java-junit
```

### GitLab CI

```yaml
security-scan:
  image: python:3.12-alpine
  script:
    - pip install ai-api-security-scanner
    - api-scanner scan . --min-score 60 --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```
