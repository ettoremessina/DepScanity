# DepScanity

**DepScanity** is a lightweight, CLI-first **Software Composition Analysis (SCA)** orchestrator written in Go. It turns dependency security into a deterministic, CI-friendly process by auto-detecting technology stacks and running native scanners under a unified interface.

> "DepScanity turns dependency chaos into a single, deterministic truth."

---

## 🤖 AI Attribution
This project was written using **Gemini 3** inside the **Antigravity** IDE.

---

## 🚀 Features

- **Auto-Detection**: Automatically identifies projects found in the directory tree:
  - **.NET** (`.sln`, `.csproj`)
  - **Node.js / NPM** (`package-lock.json`)
  - **Bun** (`bun.lock`)
  - **Containers** (`Dockerfile`, `docker-compose.yml`)
- **Unified Reporting**: Normalizes findings from diverse tools into a single standard format (JSON & Markdown).
- **CI/CD Ready**: Deterministic exit codes (`0`, `2`, `3`) for reliable pipeline integration.
- **Robust Execution**: Handles timeouts, captures outputs safely, and isolates external tool failures.

## 🛠️ Supported Ecosystems

| Ecosystem | Detected File | Underlying Scanner |
|-----------|---------------|-------------------|
| **.NET / NuGet** | `*.sln`, `*.csproj` | `dotnet list package --vulnerable` |
| **Node.js** | `package-lock.json` | `npm audit` |
| **Bun** | `bun.lock` | `bun audit` |
| **Containers** | `Dockerfile` | `trivy image` |

## 📦 Installation

### Prerequisites
DepScanity orchestrates external tools. Ensure the following are installed and in your `PATH` for the scanners you intend to use:
- **Go 1.21+** (to build)
- **.NET SDK** (for .NET scanning)
- **Node.js / npm** (for NPM scanning)
- **Bun** (for Bun scanning)
- **Docker** & **Trivy** (for container scanning)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-username/depscanity.git
cd depscanity

# Build the binary
go build -o depscanity cmd/depscanity/main.go

# (Optional) Move binary to path
mv depscanity /usr/local/bin/
```

## 💻 Usage

Run a scan on a target directory:

```bash
depscanity scan <path> [flags]
```

### Examples

**Basic Scan** (scans current directory):
```bash
depscanity scan .
```

**Scan specific image** without building:
```bash
depscanity scan . --image my-app:latest
```

**Build Docker image and scan**:
```bash
depscanity scan . --docker-build
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | `depscanity_out` | Output directory for reports |
| `--fail-on` | `high` | Severity threshold to trigger failure (`low`, `medium`, `high`, `critical`) |
| `--timeout` | `600` | Global timeout in seconds |
| `--no-container` | `false` | Disable container/docker scanning |
| `--no-osv` | `false` | Disable OSV scanner (future) |
| `--image` | `""` | Scan a specific existing docker image |
| `--docker-build` | `false` | Build `depscanity:local` from root Dockerfile before scanning |

## 📊 Reporting

DepScanity generates artifacts in the output directory:

- **`report.md`**: A human-readable summary of findings, suitable for PR comments or dashboards.
- **`report.json`**: Full machine-readable data for integration with other tools.
- **`raw/`**: The exact raw output from the underlying tools (useful for debugging).

### Exit Codes

- **0**: Success (No vulnerabilities found above threshold).
- **1**: Critical Application Error (Invalid arguments, etc).
- **2**: **Vulnerability Threshold Exceeded** (Pipeline should fail).
- **3**: **Scanner Error** (A tool failed to run, e.g., Docker build failed).

## � Testing

DepScanity includes unit tests for its core logic (detection, parsing, aggregation).

To run all tests:
```bash
go test ./...
```

To run with verbose output:
```bash
go test -v ./...
```

## �🤝 Contributing

Contributions are welcome! Please submit a Pull Request or open an Issue to discuss new features or scanners.

## 📄 License

[MIT](LICENSE)
