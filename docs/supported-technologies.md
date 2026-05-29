# Supported Technologies

## Java / Spring Boot

| Rule ID | Check | Severity |
|---------|-------|----------|
| VULN-JAVA-001 | REST endpoint without @PreAuthorize/@Secured | HIGH |
| VULN-JAVA-002 | @RequestBody without @Valid | MEDIUM |
| VULN-JAVA-003 | @CrossOrigin with wildcard (*) | MEDIUM |

**Files scanned:** `*.java`

---

## TypeScript / Node.js (Express)

| Rule ID | Check | Severity |
|---------|-------|----------|
| VULN-TS-001 | Express route without auth middleware | HIGH |
| VULN-TS-002 | CORS with origin: '*' | MEDIUM |

**Files scanned:** `*.ts`, `*.tsx`, `*.js`

---

## GraphQL

| Rule ID | Check | Severity |
|---------|-------|----------|
| VULN-GQL-001 | Schema without @auth directive | HIGH |

**Files scanned:** `*.graphql`, `*.gql`

---

## Kubernetes

| Rule ID | Check | Severity |
|---------|-------|----------|
| VULN-K8S-001 | Ingress without TLS | HIGH |
| VULN-K8S-002 | Missing NetworkPolicy | MEDIUM |

**Files scanned:** `*.yml`, `*.yaml` (with `kind:` and `apiVersion:`)

---

## Gradle

| Rule ID | Check | Severity |
|---------|-------|----------|
| VULN-GRADLE-001 | Spring Boot without Spring Security | HIGH |

**Files scanned:** `build.gradle`, `build.gradle.kts`

---

## package.json (Node.js)

| Rule ID | Check | Severity |
|---------|-------|----------|
| VULN-NPM-001 | Express without helmet | MEDIUM |
| VULN-NPM-002 | Express without rate limiting | MEDIUM |

**Files scanned:** `package.json`

---

## API Security (Cross-technology)

| Rule ID | Check | Severity |
|---------|-------|----------|
| API-001 | Missing OpenAPI specification | MEDIUM |
| API-002 | Missing security scheme definitions | HIGH |
| API-003 | Insecure HTTP endpoints | HIGH |
| API-004 | Missing input validation patterns | MEDIUM |
| API-005 | No rate limiting configuration | MEDIUM |
| API-006 | Missing API versioning | LOW |

---

## Code Compliance (Cross-technology)

| Rule ID | Check | Severity |
|---------|-------|----------|
| CC-001 | Missing OAuth2/JWT configuration | HIGH |
| CC-002 | Missing authorization controls | HIGH |
| CC-003 | Missing input validation | MEDIUM |
| CC-004 | Hardcoded secrets | HIGH |
| CC-005 | Missing HTTPS/TLS configuration | HIGH |
| CC-006 | Missing CORS configuration | MEDIUM |
| CC-007 | Missing global error handler | MEDIUM |
| CC-008 | Missing security logging | LOW |
