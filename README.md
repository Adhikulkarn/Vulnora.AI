# Vulnora AI - Backend Service

> **Branch-Aware CLI Security Guard with Tiered Auto-Remediation, Remote Open-Weight AI Inference, and Local Issue Memory**

---

## 1. Project Overview

**Vulnora AI** is an installable command-line security guard (`vulnora`) and orchestration platform that intercepts pushes targeting protected branches (such as `main` or `production`), runs local open-source security scanners (Gitleaks, Semgrep, Bandit, OSV-Scanner), consults local/cloud issue memory for solved patterns, and routes complex vulnerabilities to a dedicated remote AI inference server running open-weight coding models (such as Qwen3-Coder or Devstral via Ollama).

This repository houses the **Django REST Framework (DRF) backend service**, providing:
- **Central API & Health Probes:** Health probes and system status endpoints for CLI and infrastructure.
- **Projects & Branch Protection Policies:** Multi-repository configuration, branch gatekeeping rules, and write-permission modes.
- **Scan Aggregation:** Ingestion and normalization of security findings from multiple static and secret scanners.
- **Remediation & Issue Memory:** Storage and synchronization of resolved issues, root causes, and verified patches.
- **AI Engine Gateway:** Orchestration with remote Ollama inference instances for contextual reasoning and automated diff generation.
- **Interactive OpenAPI/Swagger Documentation:** Auto-generated API documentation via `drf-spectacular`.

---

## 2. Directory Structure

```text
vulnora-backend/
├── .env.example              # Sample environment configuration template
├── .env                      # Local environment configuration (git-ignored)
├── .gitignore                # Production gitignore rules
├── manage.py                 # Django management CLI utility
├── requirements.txt          # Python dependencies
├── README.md                 # Project documentation
├── vulnora/                  # Project configuration root
│   ├── __init__.py
│   ├── asgi.py               # ASGI application entry point
│   ├── wsgi.py               # WSGI application entry point
│   ├── urls.py               # Global routing & documentation URLs
│   └── settings/             # Environment-specific settings
│       ├── __init__.py
│       ├── base.py           # Shared settings, apps, middleware, databases
│       ├── development.py    # Local development settings
│       └── production.py     # Hardened production settings
└── apps/                     # Modular Django applications
    ├── __init__.py
    ├── core/                 # Health checks, system status, API root, base models
    │   ├── apps.py
    │   ├── models.py         # TimeStampedModel abstract base
    │   ├── serializers.py
    │   ├── views.py          # ApiRootView, HealthCheckView, SystemStatusView
    │   └── urls.py
    ├── projects/             # Repository settings & branch protection policies
    │   ├── apps.py
    │   ├── models.py
    │   ├── serializers.py
    │   ├── views.py
    │   └── urls.py
    ├── scans/                # Security scanner orchestrator & findings
    │   ├── apps.py
    │   ├── models.py
    │   ├── serializers.py
    │   ├── views.py
    │   └── urls.py
    ├── remediation/          # Issue memory, root causes, and patch workflows
    │   ├── apps.py
    │   ├── models.py
    │   ├── serializers.py
    │   ├── views.py
    │   └── urls.py
    └── ai_engine/            # Remote AI inference integration (Ollama / Qwen)
        ├── apps.py
        ├── models.py
        ├── serializers.py
        ├── views.py
        └── urls.py
```

---

## 3. Getting Started

### 3.1 Prerequisites
- Python 3.12+ (or 3.13)
- Virtual environment (`venv`)

### 3.2 Environment Setup

1. **Activate the virtual environment:**
   ```powershell
   # Windows PowerShell:
   .venv\Scripts\Activate.ps1
   ```

2. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Configure environment variables:**
   Copy `.env.example` to `.env` and adjust as needed:
   ```powershell
   Copy-Item .env.example .env
   ```

4. **Apply database migrations:**
   ```powershell
   python manage.py migrate
   ```

5. **Start the development server:**
   ```powershell
   python manage.py runserver
   ```

---

## 4. Vulnora AI CLI Foundation

Vulnora includes an installable command-line interface (`vulnora`) built with **Typer** and styled with **Rich** terminal UI, featuring the Vulnora Sentinel Mascot split-pane interface.

### 4.1 CLI Installation

Install the package locally in editable development mode:

```powershell
pip install -e .
```

Verify installation:
```powershell
vulnora --version
vulnora --help
```

### 4.2 CLI Commands

#### 1. `vulnora init`
Initializes Vulnora AI in the target Git repository:
- Validates the current directory is a Git repository.
- Generates the `.vulnora/` workspace.
- Creates `.vulnora/config.yaml` with protected branch configurations (`main`, `production`).
- Creates `.vulnora/memory.json` for issue-memory and patch state tracking.
- Updates `.gitignore` to protect cache, memory, and local configuration files.
- Installs the Git **pre-push hook** (`.git/hooks/pre-push`) with non-destructive chaining of existing hooks (`.pre-vulnora`).

```powershell
vulnora init
# Or initialize a specific directory:
vulnora init --path "C:\path\to\project"
```

#### 2. `vulnora guard`
Evaluates branch protection policies based on your current checked-out Git branch or Git pre-push hook input:
- Receives ref updates streamed by Git on `git push` (`<local_ref> <local_sha> <remote_ref> <remote_sha>`).
- Detects whether push targets protected destination branches (`main`, `production`).
- Bypasses security checks safely for branch deletions and tag pushes.
- Displays the live Rich split-pane terminal interface with the Sentinel Mascot.

```powershell
vulnora guard
# Or test a specific branch policy manually:
vulnora guard --branch feature/login-auth
```

### 4.3 Git Pre-Push Hook & Protected Branch Configuration

Vulnora intercepts pushes targeting protected branches defined in `.vulnora/config.yaml`:

```yaml
version: "1.0"
git:
  protected_branches:
    - main
    - production
  pre_push_hook:
    enabled: true
  enforce_pre_push: true
  block_on_critical: true
```

- **Protected Pushes:** When pushing commits to `main` or `production`, Vulnora intercepts the push, displays the Sentinel Alert Mascot, and runs security checks.
- **Feature Branches:** Pushing to non-protected branches (e.g. `develop`, `feature/xyz`) bypasses security checks to maintain fast developer iteration.
- **Hook Chaining:** If your repository already has a custom pre-push hook, `vulnora init` backs it up to `.git/hooks/pre-push.pre-vulnora` and executes both safely.


#### 3. `vulnora scan`
Prepares and executes the multi-scanner security analysis pipeline across files, dependencies, and target URLs:

```powershell
vulnora scan
# Scan a specific directory or URL:
vulnora scan --path "C:\path\to\code" --target-url "http://127.0.0.1:8000"
# Run specific scanners:
vulnora scan --scanner bandit --scanner trivy
```

---

## 5. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/docs/` | Interactive Swagger UI (OpenAPI 3.0) |
| `GET` | `/api/redoc/` | ReDoc API Documentation |
| `GET` | `/api/schema/` | Raw OpenAPI Schema JSON/YAML |
| `GET` | `/api/v1/` | API Root Navigation |
| `GET` | `/api/v1/health/` | Lightweight health check probe (for CLI & uptime checks) |
| `GET` | `/api/v1/status/` | System status (DB readiness, active policies, environment) |
| `GET` | `/api/v1/projects/` | Projects & Branch Protection Module status |
| `GET` | `/api/v1/scans/` | Scans & Scanner Orchestrator status |
| `GET` | `/api/v1/remediation/` | Remediation & Issue Memory Module status |
| `GET` | `/api/v1/ai/` | Remote AI Inference Gateway status |

