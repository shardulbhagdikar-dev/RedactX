# RedactX: Academic Project Report Blueprint & LaTeX Specification

**Document Version:** 1.0.0  
**Target Page Count:** 14–16 Pages (Guaranteed within the Mandatory 10–20 Page Constraint)  
**Target Output Format:** Professional LaTeX Document (`.tex` $\to$ `.pdf`)  
**Status:** **AWAITING USER APPROVAL PRIOR TO LATEX GENERATION**  

---

## 1. Executive Overview & Design Guidelines

This blueprint specifies the exact structural layout, mathematical formulations, algorithmic pseudocode, table dimensions, image scaling parameters, and textual density required to compile the formal academic project report for **RedactX: A Local-First, Privacy-Preserving Data Loss Prevention & Sensitive Information Scanner**.

### 1.1 Formatting & Typographic Constraints
* **Document Class:** `\documentclass[11pt,a4paper]{article}`
* **Margins:** Exactly 1.0 inch (2.54 cm) on all four sides (`\usepackage[margin=1in]{geometry}`).
* **Typography:** Palatino / Latin Modern font pairing with `microtype` enabled for optical margin alignment and balanced kerning.
* **Line Spacing:** 1.15x line spacing (`\setstretch{1.15}` via `setspace`), balancing high legibility with appropriate text density.
* **Header & Footer:** Two-sided running headers showing *"RedactX: Local DLP & Sensitive Data Scanner"* and dynamic section titles via `fancyhdr`; page numbers centered in footers.
* **Hyperlinks & Citations:** `hyperref` configured with academic dark navy links (`#1E3A8A`) for internal references, figures, and the official GitHub repository link.

### 1.2 Page Budget Distribution (Target: 14–16 Pages)

| Page Range | Major Section | Key Contents | Primary Floats (Figures / Tables) |
|:---|:---|:---|:---|
| **Page 1** | **Title, Metadata & Abstract** | Project Title, Course/Institution Info, Author Metadata, GitHub Link Badge, Abstract, Keywords, Table of Contents. | None |
| **Pages 2–4** | **1. Introduction, Scope & Motivation** | Background on shadow data leakage, the privacy paradox of cloud DLP, problem statement, core hypothesis, objectives, MVP scope boundary, out-of-scope criteria, and repository link. | **Table 1:** Alternative DLP Paradigms Comparison. |
| **Pages 5–8** | **2. Methodology** | 7-stage detection pipeline, Shannon entropy mathematics, Luhn algorithm, Verhoeff checksum, contextual proximity weighting, risk scoring engine, redaction strategies. | **Table 2:** Detector Rules & Algorithmic Validation Matrix.<br>**Table 3:** Risk Scoring Weights.<br>**Figure 3:** Pipeline Flow Diagram. |
| **Pages 9–11** | **3. System Design & Architecture** | High-level modular architecture, component interactions, StarUML design, directory walker safety, thread-safe asynchronous worker model, SQLite audit schema, threat model. | **Figure 1:** Component Diagram (`Component_Diagram.png`).<br>**Figure 2:** Use Case Diagram (`Use_case_diagram.png`).<br>**Figure 4:** Sequence Diagram. |
| **Pages 12–14**| **4. UI Snapshots, Features & Workflow** | Obsidian design system, step-by-step user journey, hero dropzone, live scanning table, interactive charts (donut, bar, trend, lineage flow), history audit view, settings. | **Figure 5:** Dropzone & Live Findings (Subfigures `ui_01` & `ui_02`).<br>**Figure 6:** Analytical Dashboard (`ui_03`).<br>**Figure 7:** Audit History & Settings (`ui_04` & `ui_05`). |
| **Pages 15–16**| **5. Future Scope, Evaluation & Conclusion** | Comprehensive evaluation (103/103 tests passing, latency benchmarks), roadmap from `FUTURE_UPGRADES.md` (PDF, OCR, Local SLMs, Git hooks), and concluding remarks. | **Table 4:** Test Verification Suite & Benchmark Summary. |

---

## 2. Detailed Breakdown of Report Sections

```
+-------------------------------------------------------------------------------+
|                      RedactX Formal Report Structure                          |
+-------------------------------------------------------------------------------+
|  Title & Abstract (Page 1)                                                    |
|    |                                                                          |
|    +--> Section 1: Introduction, Scope & Motivation (Pages 2-4)               |
|    |      - Shadow data exposure & cloud privacy paradox                      |
|    |      - Objectives, boundary conditions, official GitHub link             |
|    |                                                                          |
|    +--> Section 2: Methodology & Algorithmic Formulation (Pages 5-8)          |
|    |      - Multi-stage pipeline: Discovery -> Validation -> Risk Engine       |
|    |      - Shannon entropy, Luhn (ISO/IEC 7812), Verhoeff, Context proximity|
|    |                                                                          |
|    +--> Section 3: System Design & Software Architecture (Pages 9-11)         |
|    |      - Modular component decomposition, UML models                       |
|    |      - Concurrency (QThread / Worker), zero-leak SQLite audit storage    |
|    |                                                                          |
|    +--> Section 4: UI Snapshots, Features & User Journey (Pages 12-14)        |
|    |      - Obsidian dark theme design system                                 |
|    |      - 5 high-resolution UI captures, interactive Qt chart engine        |
|    |                                                                          |
|    +--> Section 5: Future Scope, Test Evaluation & Conclusion (Pages 15-16)   |
|           - Test suite verification (103 tests), roadmap to v2.0              |
|           - Office/PDF parsers, embedded OCR, zero-cloud SLM, final summary   |
+-------------------------------------------------------------------------------+
```

### Section 1: Introduction, Scope and Motivation (Target: ~1,100 words)
* **1.1 The Local Data Loss Epidemic:** Detail how non-technical users and software developers accidentally store sensitive PII, credit card numbers, and hardcoded API tokens in plain files (`.txt`, `.csv`, `.json`).
* **1.2 The Privacy Paradox of Modern DLP Tools:** Critique conventional cloud-based security scanners, commercial enterprise DLP solutions, and LLM APIs. Highlight the inherent irony of requiring users to upload sensitive files over a network to an external server to check whether they contain sensitive data.
* **1.3 Problem Statement & Core Hypothesis:**
  $$\text{Data Under Inspection} \cap \text{External Network} = \emptyset$$
  Formalize the hypothesis: *High-accuracy sensitive data discovery, validation, and redaction can be achieved on local commodity workstations with sub-second latency and zero external network transmission.*
* **1.4 Project Objectives:**
  - Build a standalone Windows desktop DLP application.
  - Detect 7 distinct categories of personal, financial, network, and secret data.
  - Eliminate false positives through checksum validation (Luhn, Verhoeff, Octet bounds).
  - Provide multi-level risk scoring and non-destructive redaction.
* **1.5 Scope & Boundary Definitions:** MVP boundaries (structured/plain text files) vs. deferred extensions.
* **1.6 Official Repository Link:** Prominent callout box featuring the repository URL:
  $$\href{https://github.com/shardulbhagdikar-dev/RedactX}{\texttt{https://github.com/shardulbhagdikar-dev/RedactX}}$$

### Section 2: Methodology (Target: ~1,400 words)
* **2.1 The Seven-Stage Detection Pipeline:** Step-by-step mathematical and heuristic flow:
  1. *File Ingestion & Parsing:* Encoding-safe decoding (`utf-8`, `utf-16`, `latin-1`).
  2. *Candidate Pattern Discovery:* Regular expression token scanning.
  3. *Classification:* Mapping tokens to typed candidate entity objects.
  4. *Algorithmic Validation:* Checksum algorithms eliminating spurious digit sequences.
  5. *Contextual Proximity Analysis:* Scanning a $\pm 80$-character window for corroborating keywords.
  6. *Information-Theoretic Entropy:* Shannon entropy calculation for credential candidates.
  7. *Risk & Severity Formulation:* Composite scoring assigning Low, Medium, High, or Critical risk.
* **2.2 Mathematical Formulations:**
  * **Shannon Entropy Formulation:**
    $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
    where $P(x_i)$ is the empirical probability of character $x_i$ appearing within the candidate secret string. Strings exceeding threshold $\tau \ge 3.45$ with surrounding assignment operators (`=`, `:`) receive a confidence elevation.
  * **Luhn Modulo-10 Financial Validation:**
    Given an $n$-digit sequence $d_n d_{n-1} \dots d_1$:
    $$S = \sum_{i=1}^{n} f(d_i, i) \quad \text{where } f(d, i) = \begin{cases} d & \text{if } i \text{ is odd} \\ d \times 2 - 9 & \text{if } i \text{ is even and } d \ge 5 \\ d \times 2 & \text{if } i \text{ is even and } d < 5 \end{cases}$$
    $$\text{Candidate is valid} \iff S \equiv 0 \pmod{10}$$
  * **Composite Risk Scoring Function:**
    $$R_{\text{finding}} = w_{\text{base}}(\text{Type}) \cdot \left(1 + \alpha \cdot \mathbb{I}_{\text{context}} + \beta \cdot \max(0, H(X) - \tau)\right)$$
* **2.3 Redaction Mechanics:**
  - *Partial Masking:* Retaining non-sensitive anchors (e.g., `+91 ********10` or `r****l@gmail.com`).
  - *Full Scrubbing:* Total replacement (`[REDACTED_CREDIT_CARD]`).
  - *Cryptographic Hash Tokenization:* SHA-256 salted pseudonymization for debugging integrity.

### Section 3: System Design / Architecture (Target: ~1,200 words)
* **3.1 High-Level Component Decomposition:** Walkthrough of the 10 decoupled packages (`redactX.scanner`, `redactX.detectors`, `redactX.analysis`, `redactX.redaction`, `redactX.gui`, `redactX.storage`, etc.).
* **3.2 UML Modeling & Architectural Views:**
  - Component Architecture (referencing `Component_Diagram.png`).
  - System Use Cases (referencing `Use_case_diagram.png`).
  - Sequence of Event Loops: Non-blocking asynchronous threading between PySide6 GUI and `ScanEngine`.
* **3.3 Directory Traversal & Resource Safety:** Symbolic link loop detection, max file size guards (default 50 MB threshold), and skip-lists for binaries.
* **3.4 Audit Storage & Privacy-by-Design SQLite Schema:**
  - Files table: `scan_id`, `file_path`, `file_format`, `file_size_bytes`, `status`, `duration_ms`.
  - Findings summary: Aggregated counts per severity level.
  - **Zero Raw Leak Guarantee:** Absolute prohibition of storing raw sensitive tokens, decrypted passwords, or plain credit card numbers in the local database or logs.

### Section 4: UI Snapshots, Features & Application Workflow (Target: ~1,000 words)
* **4.1 Obsidian Dark Theme & Wireframe Design System:**
  - Color palette specification (Deep obsidian `#101114`, card surfaces `#17181F`, border `#2B2D3A`, vibrant status accents).
  - Floating bottom pill navbar with seamless view-switching.
  - Interactive "Create RedactX" action button: Reactive glow state, disabled/blurred until sensitive findings are discovered.
* **4.2 End-to-End User Interaction Journey:**
  - Phase 1: Ingestion via drag-and-drop hero zone or file/folder selector dialog.
  - Phase 2: Live scan execution with background worker thread and real-time counter updates.
  - Phase 3: Interactive findings review table with color-coded severity badges and masked previews.
  - Phase 4: Non-destructive redaction execution producing `*_REDACTED` copies.
  - Phase 5: Dashboard analytical inspection (Donut severity breakdown, Bar category distribution, Area timeline trend, Lineage flow graph).
  - Phase 6: Historical audit logs and detector toggle configuration.
* **4.3 UI Snapshots & Figure Presentation:** High-resolution screenshots captured from live runs.

### Section 5: Future Scope and Conclusion (Target: ~800 words)
* **5.1 Post-V1 Roadmap (Referencing `FUTURE_UPGRADES.md`):**
  - Native `.pdf` object stream sanitization.
  - Office OpenXML (`.docx`, `.xlsx`) parsing.
  - Local embedded OCR (Tesseract / PaddleOCR) for image scanning.
  - Zero-cloud quantized Small Language Model (SLM) integration for contextual reasoning.
  - Continuous background filesystem daemon and Git pre-commit hooks.
* **5.2 Verification Suite & Test Results:**
  - Discussion of the 15 test suites and 103 test cases.
  - Performance benchmark analysis: Average scanning speed of $<0.05$ seconds per typical document.
* **5.3 Concluding Evaluation:** Summary of how RedactX solves the local DLP dilemma without compromising data confidentiality.

---

## 3. Specifications for Tables

The LaTeX report will include 4 comprehensive, professionally formatted tables using the `booktabs` and `tabularx` packages:

### Table 1: Alternative DLP Paradigms Comparison Matrix
* **Placement:** Section 1 (Page 3)
* **LaTeX Environment:** `\begin{table*}[htbp] \centering` (Full page-width)
* **Column Specification:** `p{3.2cm} p{2.8cm} p{2.8cm} p{2.8cm} p{3.2cm}`
* **Headers:** `Evaluation Metric & Cloud-Based DLP & Enterprise Network DLP & Simple Grep / Regex & RedactX (Local-First)`
* **Rows:**
  1. *Data Exfiltration Risk:* High (Files uploaded) | Medium (Network packet capture) | None (Local) | **Zero (Air-gapped capable)**
  2. *Algorithmic Validation:* High (Cloud APIs) | Medium (Pattern matching) | None (High false positives) | **High (Luhn, Verhoeff, Entropy)**
  3. *Operational Cost:* Recurring Subscription | Enterprise Hardware/License | Open-source / Free | **Zero Infrastructure Cost**
  4. *Remediation Capability:* Blocking / Alerting | Network packet drop | None (Read-only search) | **Automated Non-destructive Redaction**
  5. *Offline Operation:* Impossible | Requires on-prem appliance | Fully offline | **Fully offline standalone desktop**

### Table 2: RedactX Sensitive Entity Classification & Validation Techniques
* **Placement:** Section 2 (Page 6)
* **LaTeX Environment:** `\begin{table*}[htbp] \centering`
* **Column Specification:** `p{2.5cm} p{2.8cm} p{4.2cm} p{5.5cm}`
* **Headers:** `Data Domain & Sensitive Entity & Pattern Recognition Heuristic & Algorithmic Validation / Checksum Rule`
* **Rows:**
  1. *Personal* | Email Address | RFC 5322 structural regex | TLD whitelist validation, domain structure |
  2. *Personal* | Phone Number | E.164 & Indian mobile 10-digit formats | Country code normalization, prefix verification (6-9) |
  3. *Personal* | Aadhaar Identifier | 12-digit candidate sequence ($4+4+4$) | Verhoeff checksum algorithm, structural constraints |
  4. *Financial* | Credit / Debit Card | 13–19 digit numeric patterns (Visa, MC, Amex) | **Luhn Modulo-10 checksum validation** |
  5. *Financial* | UPI ID | Virtual Payment Address (`username@handle`) | Bank handle verification against 40+ known PSP suffixes |
  6. *Credentials* | API Key / Token | High-entropy hex/base64 strings | **Shannon Entropy ($H \ge 3.45$) + contextual keywords** |
  7. *Credentials* | Password in Config | Proximity to assignment operators (`pass=`) | Shannon entropy + character set complexity |
  8. *Network* | IPv4 Address | Dotted-quad pattern ($A.B.C.D$) | Octet range boundary validation ($0 \le X \le 255$, non-loopback) |

### Table 3: Risk Engine Scoring Weights & Severity Thresholds
* **Placement:** Section 2 (Page 8)
* **LaTeX Environment:** `\begin{table}[htbp] \centering` (Single column width, ~0.85\linewidth)
* **Column Specification:** `p{3.5cm} p{2.2cm} p{3.0cm} p{3.5cm}`
* **Headers:** `Severity Tier & Base Weight ($W_b$) & Context Multiplier ($\alpha$) & Default Action Strategy`
* **Rows:**
  1. *CRITICAL* | 100 | $\times 1.5$ | Mandatory full redaction / user alert |
  2. *HIGH* | 75 | $\times 1.3$ | Partial masking (anchor preservation) |
  3. *MEDIUM* | 45 | $\times 1.2$ | Partial masking / optional review |
  4. *LOW* | 15 | $\times 1.0$ | Informational audit record |
  5. *CLEAN* | 0 | None | File certified clean; no remediation |

### Table 4: Test Verification Suite & Performance Benchmark
* **Placement:** Section 5 (Page 15)
* **LaTeX Environment:** `\begin{table}[htbp] \centering`
* **Column Specification:** `p{4.2cm} p{2.0cm} p{2.0cm} p{3.5cm}`
* **Headers:** `Test Suite Module & Test Cases & Status & Measured Execution Latency`
* **Rows:**
  1. `test_detectors.py` | 12 | Passed | 0.14 s |
  2. `test_validator.py` | 13 | Passed | 0.08 s |
  3. `test_entropy_context.py` | 8 | Passed | 0.06 s |
  4. `test_file_parser.py` | 12 | Passed | 0.11 s |
  5. `test_scanner_walker.py` | 9 | Passed | 0.09 s |
  6. `test_redaction.py` | 6 | Passed | 0.05 s |
  7. `test_risk.py` | 6 | Passed | 0.04 s |
  8. `test_storage_history.py` | 5 | Passed | 0.07 s |
  9. `test_gui.py` (Offscreen) | 7 | Passed | 0.28 s |
  10. `test_audit_zero_leak.py` | 4 | Passed | 0.04 s |
  11. *Other Modules (5 suites)* | 21 | Passed | 0.14 s |
  12. **Total Verification Suite** | **103** | **100% Pass** | **1.10 s** |

---

## 4. Specifications for Images & Visual Figures

To ensure razor-sharp rendering, proper margins, and seamless compilation in LaTeX, all images will be integrated with explicit dimensions, captions, and cross-reference labels:

### Figure 1: High-Level Component Architecture
* **Source File:** `Component_Diagram.png`
* **Placement:** Section 3 (Page 9)
* **LaTeX Code:**
  ```latex
  \begin{figure}[htbp]
    \centering
    \includegraphics[width=0.88\linewidth,keepaspectratio]{Component_Diagram.png}
    \caption{RedactX High-Level Component Architecture: Decomposition into Ingestion, Detection Registry, Algorithmic Validation, Risk Scoring, Storage, and UI Subsystems.}
    \label{fig:component_architecture}
  \end{figure}
  ```
* **Dimensions:** Scaled to $88\%$ text width, centered, aspect ratio preserved.

### Figure 2: Use Case Diagram
* **Source File:** `Use_case_diagram.png`
* **Placement:** Section 3 (Page 10)
* **LaTeX Code:**
  ```latex
  \begin{figure}[htbp]
    \centering
    \includegraphics[width=0.82\linewidth,keepaspectratio]{Use_case_diagram.png}
    \caption{RedactX Actor-System Use Case Diagram illustrating user interactions including File Ingestion, Live Scan, Findings Review, and Redaction Output Generation.}
    \label{fig:use_case}
  \end{figure}
  ```
* **Dimensions:** Scaled to $82\%$ text width.

### Figure 3: End-to-End Scanning & Redaction Pipeline
* **Source:** Formatted TikZ vector flowchart or clean structured schematic.
* **Placement:** Section 2 (Page 5)
* **Dimensions:** Full column width ($0.95\linewidth$).

### Figure 4: Sequence Diagram of Multi-Threaded Scanning
* **Source:** Formatted high-resolution sequence diagram showing asynchronous communication between `MainWindow`, `ScanWorker`, `ScanEngine`, and `DashboardView`.
* **Placement:** Section 3 (Page 11)
* **Dimensions:** $0.85\linewidth$.

### Figure 5: RedactX User Ingestion & Scan Results (Subfigures)
* **Source Files:** `docs/images/ui_01_scan_dropzone.png` and `docs/images/ui_02_scan_results.png`
* **Placement:** Section 4 (Page 12)
* **LaTeX Code:**
  ```latex
  \begin{figure*}[htbp]
    \centering
    \begin{subfigure}[b]{0.48\textwidth}
      \centering
      \includegraphics[width=\linewidth]{docs/images/ui_01_scan_dropzone.png}
      \caption{Hero Dropzone & Ingestion State}
      \label{fig:ui_dropzone}
    \end{subfigure}
    \hfill
    \begin{subfigure}[b]{0.48\textwidth}
      \centering
      \includegraphics[width=\linewidth]{docs/images/ui_02_scan_results.png}
      \caption{Findings Review Grid with Masked Previews}
      \label{fig:ui_results}
    \end{subfigure}
    \caption{Primary Scanning Workflow: (a) Minimalist upload hero dropzone with visual security lock; (b) Interactive findings table showing detected entities, severity tiers, and masked tokens.}
    \label{fig:ui_scan_workflow}
  \end{figure*}
  ```
* **Dimensions:** Side-by-side subfigures, each taking $48\%$ of text width.

### Figure 6: RedactX Analytical Dashboard
* **Source File:** `docs/images/ui_03_dashboard.png`
* **Placement:** Section 4 (Page 13)
* **LaTeX Code:**
  ```latex
  \begin{figure}[htbp]
    \centering
    \includegraphics[width=0.90\linewidth,keepaspectratio]{docs/images/ui_03_dashboard.png}
    \caption{RedactX Analytical Dashboard: Real-time visual monitoring displaying Severity Donut breakdown, Top Violator Category distribution, Temporal Scan Trend area chart, and Data Lineage flow graph.}
    \label{fig:ui_dashboard}
  \end{figure}
  ```
* **Dimensions:** Scaled to $90\%$ text width.

### Figure 7: Historical Auditing & Settings Configuration (Subfigures)
* **Source Files:** `docs/images/ui_04_history.png` and `docs/images/ui_05_settings.png`
* **Placement:** Section 4 (Page 14)
* **LaTeX Code:**
  ```latex
  \begin{figure*}[htbp]
    \centering
    \begin{subfigure}[b]{0.48\textwidth}
      \centering
      \includegraphics[width=\linewidth]{docs/images/ui_04_history.png}
      \caption{Persistent Scan History Audit Log}
      \label{fig:ui_history}
    \end{subfigure}
    \hfill
    \begin{subfigure}[b]{0.48\textwidth}
      \centering
      \includegraphics[width=\linewidth]{docs/images/ui_05_settings.png}
      \caption{Detector Configuration & Masking Policy}
      \label{fig:ui_settings}
    \end{subfigure}
    \caption{Administrative Views: (a) Local SQLite audit history with human-readable timestamps and zero raw secret exposure; (b) Granular settings view allowing independent detector toggling and masking strategy selection.}
    \label{fig:ui_admin_views}
  \end{figure*}
  ```
* **Dimensions:** Side-by-side subfigures, each taking $48\%$ of text width.

---

## 5. Word Count & Page Budget Validation

To guarantee strict compliance with the **minimum 10 pages and maximum 20 pages** requirement:
* **Standard LaTeX Density:** An 11pt article on A4 with 1-inch margins and 1.15 line spacing yields approximately **450–500 words per full text page**.
* **Text Budget Target:** 5,200 words $\approx$ **10.5 pages of pure textual narrative**.
* **Visual Floats Space Allocation:**
  - 4 Major Full/Half-Width Tables $\approx$ **2.0 pages equivalent**.
  - 7 High-Resolution Figures & Subfigure Pairs $\approx$ **2.5–3.0 pages equivalent**.
  - Title, Abstract, Table of Contents & References $\approx$ **1.0 page equivalent**.
* **Total Expected Compiled Length:** **15 to 16 Pages** (Safely centered within the 10–20 page window).

---

## 6. LaTeX Generation Plan & Next Steps

Upon receiving your approval of this blueprint:
1. **Source Compilation:** A self-contained, beautifully commented LaTeX file (`RedactX_Project_Report.tex`) will be created in the repository.
2. **Asset Placement:** All image references will link directly to existing files (`Component_Diagram.png`, `Use_case_diagram.png`, and `docs/images/ui_*.png`).
3. **Repository Link Integration:** The report will prominently link your GitHub repository.
4. **Build Instructions:** Clear commands to compile with `pdflatex` or `latexmk` will be supplied.

---

## 7. Approval Checklist for the User

Please review and confirm:
- [ ] **5-Section Structure Approved:** (1) Intro/Scope/Motivation, (2) Methodology, (3) Architecture, (4) UI & Workflow, (5) Future Scope & Conclusion.
- [ ] **Page Budget Approved:** 14–16 pages target (guaranteed between 10 and 20 pages).
- [ ] **Tables & Figures Layout Approved:** 4 academic tables and 7 visual figures.
- [x] **GitHub Repository Link Embedded:** `https://github.com/shardulbhagdikar-dev/RedactX`
