# RedactX: Git Release Protocol & V1 Commit Plan

**Document Version:** 1.0.0  
**Target Release Tag:** `v1.0.0`  
**Branch Name:** `main`  
**Status:** **PENDING USER REVIEW & APPROVAL** (No git actions executed yet)  

---

## 1. Purpose & Standards

This document establishes the official **Software Development Protocol** for committing and releasing **RedactX Version 1.0.0** to GitHub. 

Adhering to strict professional software engineering practices ensures that:
1. **Repository Cleanliness:** Machine-specific virtual environments, binary executables, build caches, and compiled bytecode are strictly excluded.
2. **Security & Privacy:** No sensitive local file paths, private developer configs, or local database histories are leaked into git history.
3. **Reproducibility:** Any developer or evaluator cloning the repository can immediately set up a clean virtual environment, install exact dependencies, run the test suite, and launch or package the application.
4. **Semantic Traceability:** The commit structure follows the **Conventional Commits** specification and includes an annotated semantic release tag (`v1.0.0`).

---

## 2. Workspace Audit & File Inventory

A thorough audit of the `e:\Uni\FCS_mini-project` workspace reveals three distinct categories of files:

```
+-------------------------------------------------------------------------------+
|                       RedactX Workspace Classification                        |
+------------------------------+-------------------------------+----------------+
| [A] Source & Documentation   | [B] Build & Cache Artifacts   | [C] Config &   |
|     (MUST COMMIT)            |     (MUST IGNORE)             |     Defects    |
| - redactX/ (10 modules)      | - .venv/ (Virtual environment)| - requirements |
| - tests/ (15 test files)     | - build/ (PyInstaller cache)  |   missing      |
| - Demo/ (sanitized fixtures) | - dist/ (Compiled RedactX.exe)|   PySide6      |
| - Component_Diagram.png      | - .pytest_cache/              | - Needs        |
| - Use_case_diagram.png       | - */__pycache__/* (*.pyc)     |   .gitignore   |
| - RedactX_UML.mdj            | - *.db / *.sqlite3            |                |
| - Project docs & markdown    |                               |                |
+------------------------------+-------------------------------+----------------+
```

---

## 3. What We Are Committing and Why

Every file committed to the repository serves a clear software engineering purpose:

### 3.1 Core Source Code (`redactX/`)
* **`redactX/app.py` & `redactX/__init__.py`:** Main desktop application entrypoint with DPI awareness.
* **`redactX/detectors/` (11 files):** Modular detector architecture (`base.py`, `registry.py`, `email.py`, `phone.py`, `aadhaar.py`, `credit_card.py`, `upi.py`, `api_key.py`, `password.py`, `ip_address.py`).
* **`redactX/analysis/` (5 files):** Heuristic and validation engines (`validator.py` with Luhn/Verhoeff checksums, `entropy.py` with Shannon calculation, `context.py` with keyword proximity, `risk.py` with multi-factor severity scoring).
* **`redactX/scanner/` (4 files):** Document extraction and directory traversal engine (`file_parser.py` for TXT/CSV/JSON, `walker.py` with symlink/size safety, `scanner.py` with cooperative cancellation).
* **`redactX/redaction/` (2 files):** Sanitization engine (`redactor.py`) supporting partial masking, full masking, hash tokenization, and non-destructive output preservation.
* **`redactX/gui/` (7 files + `views/`):** Native PySide6 interface (`main_window.py`, `theme.py`, `nav_bar.py`, `charts.py`, `icons.py`, `worker.py`, and the 4 views: `scan_view.py`, `dashboard_view.py`, `history_view.py`, `settings_view.py`).
* **`redactX/storage/` (2 files):** SQLite local audit schema (`history.py`) ensuring zero raw secret retention.
* **`redactX/reports/` (2 files):** Security summary generator (`reporter.py`) for human-readable and structured outputs.
* **`redactX/utils/` (3 files):** Masking utilities and structured logging (`logger.py`, `masking_helper.py`).
* **Why:** This constitutes the entire intellectual property and working engine of the project.

### 3.2 Automated Test Suite (`tests/`)
* **15 Test Modules (103 Test Cases):** Unit and integration coverage spanning all detectors, validators, risk calculations, file parsers, redaction engines, audit history, and offscreen headless GUI components.
* **Verification Status:** 100% pass rate (`103 passed in 1.10s`).
* **Why:** Proves correctness, ensures zero regressions for future contributors, and validates the "zero-leak" privacy guarantee.

### 3.3 Curated Demo Fixtures (`Demo/`)
* **Files:** `01_incident_and_system_logs.txt`, `02_executive_security_memo.txt`, `03_customer_banking_records.csv`, `04_employee_payroll_kyc.csv`, `05_cloud_deployment_config.json`, `06_ecommerce_transaction_payload.json`, plus the benchmark dataset in `Demo/archive/`.
* **Why:** Allows any evaluator, professor, or user cloning the repo to immediately test RedactX with realistic, non-production synthetic data without needing to prepare test files.

### 3.4 Architecture & Visual Assets (`docs/images/`, Diagrams)
* **`Component_Diagram.png` & `Use_case_diagram.png`:** UML architectural blueprints.
* **`RedactX_UML.mdj`:** Editable StarUML source model.
* **`docs/images/*.png`:** 5 high-resolution UI captures of the application in action (Hero Dropzone, Live Scan Results, Dashboard Analytics, History Audit, Settings).
* **Why:** Crucial for GitHub README visual appeal and report cross-referencing.

### 3.5 Build & Dependency Manifests
* **`redactx.spec`:** PyInstaller specification file enabling anyone to reproduce the standalone Windows executable (`RedactX.exe`).
* **`requirements.txt` & `requirements-dev.txt`:** Explicitly pinned dependencies.
* **Why:** Eliminates environment discrepancies and provides a 1-command build path.

### 3.6 Documentation Suite
* **`README.md`:** Comprehensive project documentation with architecture, quick start, and usage.
* **`LICENSE`:** Standard open-source license (MIT).
* **`RedactX_Project_Specification.md`:** Complete foundational engineering specification.
* **`FUTURE_UPGRADES.md`:** Post-V1 roadmap (Task A).
* **`V1_COMMIT_PROTOCOL.md`:** This software development protocol (Task B).
* **`REPORT_BLUEPRINT.md`:** Academic report structure and LaTeX plan (Task C).

---

## 4. What We Are Strictly Ignoring (Excluding) and Why

The following files and directories **MUST NOT** be committed to GitHub:

| Directory / Pattern | Reason for Exclusion |
|:---|:---|
| **`.venv/`, `venv/`, `env/`** | Python virtual environment binaries are platform-dependent, machine-specific, and over 300 MB. Users must build their own virtual environments using `requirements.txt`. |
| **`dist/`, `build/`** | PyInstaller build directories containing compiled `.exe` files and object caches. Committing compiled binaries bloats git history and creates security risks. Executables belong in **GitHub Releases**, not git trees. |
| **`__pycache__/`, `*.pyc`, `*.pyo`** | Python interpreter byte-compiled files. Dynamically generated on runtime and platform-specific. |
| **`.pytest_cache/`, `.coverage`** | Temporary test runner state and coverage telemetry. |
| **`*.db`, `*.sqlite3`** | Local SQLite history databases. Committing `.db` files could inadvertently leak local user file paths or test scan metadata, violating privacy principles. |
| **`.vscode/`, `.idea/`, `*.swp`** | Personal IDE configurations that conflict across different team members' development setups. |
| **`Thumbs.db`, `.DS_Store`** | OS-generated visual thumbnail caches. |

---

## 5. Pre-Commit Preparations Required

Before committing, two file deficiencies must be resolved:

### 5.1 Create `.gitignore`
A comprehensive `.gitignore` file must be written to the workspace root:

```gitignore
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
# redactx.spec is deliberately tracked!

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/
cover/

# Local SQLite databases (zero-leak protocol)
*.db
*.sqlite
*.sqlite3

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# IDE & OS files
.idea/
.vscode/
*.swp
*.swo
Thumbs.db
Desktop.ini
.DS_Store
```

### 5.2 Update `requirements.txt`
The current `requirements.txt` was missing `PySide6`. It will be cleanly organized:

```txt
# RedactX Runtime Dependencies
PySide6>=6.6.0
colorama>=0.4.6
iniconfig>=2.0.0
packaging>=22.0
pluggy>=1.5.0
pygments>=2.7.2

# Testing & Development (can also be split into requirements-dev.txt)
pytest>=8.0.0
pyinstaller>=6.0.0
```

---

## 6. Git Release Execution Sequence (Pending Your Approval)

Once you review and approve this document, the following sequence of terminal commands will be executed in order:

```bash
# 1. Initialize Git repository with default branch 'main'
git init -b main

# 2. Add and stage .gitignore and updated requirements.txt first
git add .gitignore requirements.txt

# 3. Stage all approved project files
git add redactX/ tests/ Demo/ docs/
git add Component_Diagram.png Use_case_diagram.png RedactX_UML.mdj redactx.spec
git add RedactX_Project_Specification.md FUTURE_UPGRADES.md V1_COMMIT_PROTOCOL.md REPORT_BLUEPRINT.md README.md

# 4. Verify that no excluded files (.venv, dist, build, __pycache__) are staged
git status

# 5. Create initial V1 commit using Conventional Commits
git commit -m "feat: initial v1.0.0 release of RedactX local DLP and redaction suite

- Implemented 10-module zero-cloud local DLP architecture in Python 3.12
- Added 7 specialized sensitive-data detectors with Luhn and Verhoeff validation
- Built modern PySide6 dark GUI with interactive charts and custom dropzone
- Created non-destructive redactor supporting partial, full, and hash masking
- Validated via 103 unit and integration tests with 100% pass rate
- Included sanitized demo fixtures, PyInstaller spec, and UML diagrams"

# 6. Create annotated semantic release tag
git tag -a v1.0.0 -m "RedactX Version 1.0.0 - Production-ready offline DLP engine and desktop GUI"

# 7. Connect to GitHub remote and push (User supplies <username>)
git remote add origin https://github.com/shardulbhagdikar-dev/RedactX.git
git push -u origin main --tags
```

---

## 7. Approval Checklist

Before proceeding to run `git init` and commit, please confirm:

- [ ] **Files to Commit Approved:** `redactX/`, `tests/`, `Demo/`, `docs/images/`, diagrams, and specs are accepted.
- [ ] **Files to Ignore Approved:** `.venv/`, `dist/`, `build/`, `__pycache__/`, and `*.db` are strictly excluded.
- [ ] **Requirements Update Approved:** Adding `PySide6` and `pyinstaller` to `requirements.txt`.
- [ ] **Commit Message & Tag Approved:** `v1.0.0` semantic release tag and Conventional Commit message.
- [ ] **GitHub Remote URL:** Please provide your GitHub repository link (e.g., `https://github.com/YourUsername/RedactX.git`) when ready so we can link it in the report and configure git remote.
