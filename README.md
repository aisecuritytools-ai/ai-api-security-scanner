<p align="center">
  <img src="https://img.shields.io/badge/🔒_AI-API_Security_Scanner-00C853?style=for-the-badge&labelColor=000000" alt="AI API Security Scanner"/>
</p>

<p align="center">
  <strong>Automated API security compliance scanning for CI/CD pipelines — zero config required</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/OWASP-API_Top_10-EE0000?style=flat-square&logo=owasp&logoColor=white" alt="OWASP"/>
  <img src="https://img.shields.io/badge/Java-Spring_Boot-6DB33F?style=flat-square&logo=spring&logoColor=white" alt="Java"/>
  <img src="https://img.shields.io/badge/Node.js-Express-339933?style=flat-square&logo=nodedotjs&logoColor=white" alt="Node"/>
  <img src="https://img.shields.io/badge/GraphQL-Schema-E10098?style=flat-square&logo=graphql&logoColor=white" alt="GraphQL"/>
  <img src="https://img.shields.io/badge/K8s-Manifests-326CE5?style=flat-square&logo=kubernetes&logoColor=white" alt="K8s"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
</p>

<p align="center">
  <a href="docs/getting-started.md">Getting Started</a> •
  <a href="docs/supported-technologies.md">Supported Technologies</a> •
  <a href="examples/output/">Example Reports</a> •
  <a href="#-enterprise-edition">Enterprise</a>
</p>

---

> 💡 **Free & open-source.** For the enterprise edition with advanced compliance features, contact **ai.security.tools@gmail.com**

---

## What does it do?

Point it at your codebase. It finds API security issues across **6 technologies**, maps them to **OWASP API Top 10**, and generates reports for your CI/CD pipeline.

```bash
api-scanner scan /path/to/your/project
```

```
┌─────────────────────────────────────────────────┐
│  AI API Security Scanner                        │
│  Scanning: /path/to/your/project                │
└─────────────────────────────────────────────────┘

┌──────────────────────┬───────┬──────────┐
│ Scanner              │ Score │ Findings │
├──────────────────────┼───────┼──────────┤
│ API Security Audit   │ 72    │ 3        │
│ Code Compliance      │ 85    │ 2        │
│ Vulnerability Scan   │ 80    │ 2        │
└──────────────────────┴───────┴──────────┘

Overall Security Score: 79/100  ✓ PASS (threshold: 50)
Findings: 7 total (2 high, 3 medium, 2 low)

✓ Report saved to: security-report.json
```

**No API keys. No cloud accounts. No external tools. Just Python.**

---

## ⚡ Quick Start

```bash
# Install
git clone https://github.com/aisecuritytools-ai/ai-api-security-scanner.git
cd ai-api-security-scanner
pip install -e .

# Scan your project
api-scanner scan .

# With HTML dashboard
api-scanner scan . --format html --output report.html

# Fail pipeline if score too low
api-scanner scan . --min-score 70 --fail-on-issues
```

### With AI Enhancement (optional — smarter analysis)

```bash
# Install AI dependencies
pip install -e ".[ai]"

# Ollama (free, local)
ollama pull llama3.1
api-scanner scan . --ai ollama

# OpenAI (best quality)
export OPENAI_API_KEY=sk-...
api-scanner scan . --ai openai

# Amazon Bedrock
api-scanner scan . --ai bedrock
```

AI adds: **false positive filtering**, **context-aware remediation**, **attack scenarios**, **risk re-prioritization**.

---

## 🔍 What It Scans

### Three scanning engines run in parallel:

<table>
<tr>
<td width="33%">

**🔐 API Security Audit**
- OpenAPI spec validation
- Security scheme definitions
- HTTPS enforcement
- Input validation patterns
- Rate limiting config
- API versioning

</td>
<td width="33%">

**📋 Code Compliance**
- OAuth2/JWT configuration
- Authorization controls
- Input validation
- Hardcoded secrets
- CORS configuration
- Error handling
- Security logging

</td>
<td width="33%">

**⚠️ Vulnerability Scan**
- Java/Spring Boot
- TypeScript/Express
- GraphQL schemas
- Kubernetes manifests
- Gradle dependencies
- npm packages

</td>
</tr>
</table>

Every finding includes: **severity**, **OWASP API Top 10 reference**, **CWE ID**, and **specific remediation steps**.

---

## 📋 Usage

```
api-scanner scan [OPTIONS] PATH

Arguments:
  PATH                    Project directory to scan

Options:
  --min-score INTEGER     Minimum passing score, 0-100 (default: 50)
  --format TEXT           Output: json, junit, html (default: json)
  --output PATH           Output file path
  --ai TEXT               AI provider: none, bedrock, openai, ollama (default: none)
  --ai-model TEXT         AI model ID (auto-detected if not set)
  --fail-on-issues        Exit code 1 if below threshold
  --verbose               Detailed scan progress
```

---

## 🔌 CI/CD Integration

<details>
<summary><strong>GitHub Actions</strong></summary>

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
      - run: api-scanner scan . --min-score 60 --fail-on-issues --format junit -o results.xml
      - uses: dorny/test-reporter@v1
        if: always()
        with:
          name: Security Findings
          path: results.xml
          reporter: java-junit
```

</details>

<details>
<summary><strong>GitLab CI</strong></summary>

```yaml
security-scan:
  image: python:3.12-alpine
  script:
    - pip install ai-api-security-scanner
    - api-scanner scan . --min-score 60 --format json -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

</details>

<details>
<summary><strong>Docker</strong></summary>

```bash
docker build -t api-scanner .
docker run -v $(pwd):/project api-scanner scan /project
```

</details>

---

## 🏗️ Architecture

```
src/api_scanner/
├── cli.py                  # CLI (Typer + Rich)
├── core/
│   ├── config.py           # Scan configuration
│   ├── models.py           # Finding/Report models
│   └── scanner.py          # Orchestrator
├── scanners/
│   ├── base.py             # Shared utilities
│   ├── api_security.py     # API audit (6 checks)
│   ├── code_compliance.py  # Compliance (8 checks)
│   └── vulnerability.py    # Tech-specific (6 technologies)
├── ai/
│   ├── config.py           # AI provider config
│   ├── llm.py              # LLM abstraction
│   └── enhancer.py         # AI post-processing
└── reporters/
    ├── json_reporter.py
    ├── junit_reporter.py
    └── html_reporter.py
```

### How AI Enhancement Works

```
Static Scan (always)              AI Enhancement (optional)
┌───────────────────┐            ┌─────────────────────────┐
│ Pattern matching  │            │ For each finding:       │
│ across 6 techs   │───────────▶│ • Read code context     │
│ 20 rules total   │            │ • True positive or FP?  │
└───────────────────┘            │ • Smart remediation     │
        │                        │ • Attack scenario       │
        ▼                        └─────────────────────────┘
  Raw: 20 findings                         │
                                           ▼
                               Enhanced: 14 findings
                               (6 false positives removed)
```

---

## 📊 Report Formats

| Format | Use Case | Command |
|--------|----------|---------|
| **JSON** | CI/CD automation, APIs | `--format json` |
| **JUnit XML** | Test dashboards (Jenkins, GitHub) | `--format junit` |
| **HTML** | Human review, sharing | `--format html` |

📁 See example reports: [`examples/output/`](examples/output/)

---

## 🗺️ Roadmap

- [x] Multi-technology static scanning (6 techs, 20 rules)
- [x] OWASP API Top 10 mapping
- [x] Multiple report formats (JSON, JUnit, HTML)
- [x] AI-enhanced analysis (Bedrock/OpenAI/Ollama)
- [x] Docker support
- [x] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] SARIF output format
- [ ] Custom rule definitions (YAML)
- [ ] Auto-fix suggestions with code patches
- [ ] VS Code extension
- [ ] Historical trend tracking

---

## 💼 Enterprise Edition

The open-source version provides **core static scanning + optional AI enhancement**. The Enterprise Edition adds:

| | Open Source | Enterprise |
|---|:---:|:---:|
| Static scanning (20 rules) | ✅ | ✅ |
| OWASP API Top 10 mapping | ✅ | ✅ |
| JSON / JUnit / HTML reports | ✅ | ✅ |
| AI false-positive filtering | ✅ | ✅ |
| Docker + CI/CD ready | ✅ | ✅ |
| Custom compliance standards (40+ rules) | — | ✅ |
| Unified Security Layer (USL) | — | ✅ |
| 42Crunch methodology integration | — | ✅ |
| Native GitLab SAST dashboard | — | ✅ |
| AI auto-remediation (code patches) | — | ✅ |
| Policy-as-Code (YAML rules) | — | ✅ |
| Historical trending & regression detection | — | ✅ |
| Team dashboard (multi-repo) | — | ✅ |
| Slack/Teams notifications | — | ✅ |
| Custom technology rules | — | ✅ |
| On-premise deployment | — | ✅ |
| Priority support & SLA | — | ✅ |

<p align="center">
  <br/>
  📧 <strong>ai.security.tools@gmail.com</strong><br/>
  Custom rules • On-premise • Volume licensing • Integration consulting
</p>

---

<p align="center">
  <sub>MIT License • Zero dependencies on external services • Works offline</sub>
</p>
