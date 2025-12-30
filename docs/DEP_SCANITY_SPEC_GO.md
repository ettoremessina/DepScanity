# DepScanity — Smart Dependency & Vulnerability Scanner (Go Edition)

## 1. Purpose
DepScanity is a CLI-first Software Composition Analysis (SCA) tool written in Go.

It automatically detects technology stacks in a given folder, runs the appropriate dependency and vulnerability scanners, normalizes results, and produces a unified report with deterministic exit codes suitable for CI/CD.

Key goals:
- single static binary
- deterministic and auditable
- no runtime dependencies
- enterprise / CI-friendly

---

## 2. Non-Goals
- No vulnerability discovery logic
- No AI / LLM usage
- No web UI
- No hosted services

DepScanity orchestrates scanners; it does not replace them.

---

## 3. Supported Ecosystems (v1)

### .NET / NuGet
Detection:
- *.sln
- *.csproj

Scanner:
- dotnet list package --vulnerable --include-transitive

### JavaScript / npm
Detection:
- package-lock.json

Scanner:
- npm audit --json

### JavaScript / Bun
Detection:
- bun.lock

Scanner:
- bun audit --json

### Containers (Docker)
Detection:
- Dockerfile
- docker-compose.yml / compose.yml

Scanner:
- trivy image --format json

### OSV (Optional)
Scanner:
- osv-scanner -r <path> --json

---

## 4. Architecture

cmd/depscanity
internal/
  detect
  exec
  scanners
  normalize
  aggregate
  report
  model

---

## 5. CLI

Usage:
depscanity scan <path> [flags]

Flags:
--out
--fail-on
--timeout
--no-osv
--no-container
--image
--docker-build

---

## 6. Unified Finding Model

source | ecosystem | package | installed_version | fixed_version | vulnerability_id | severity | title | url | location | metadata

Severity levels:
low | medium | high | critical

---

## 7. Reporting

Output:
depscanity_out/
  raw/
  report.json
  report.md

Exit codes:
0 = OK
1 = internal error
2 = threshold exceeded

---

## Philosophy
DepScanity turns dependency chaos into a single, deterministic truth.
