# RedactX: Architectural Evolution & Future Upgrades Roadmap

**Document Version:** 1.0.0  
**Status:** Approved for Post-V1 Architecture Planning  
**Target Platform:** Windows 11 / Multi-Platform Desktop (Offline-First)  

---

## Executive Summary

**RedactX** was conceived and implemented as a privacy-preserving, zero-telemetry local Data Loss Prevention (DLP) utility. While Version 1.0 (MVP) successfully delivers a native PySide6 desktop interface, 7 specialized sensitive-data detectors, algorithmic validators (such as Luhn and Verhoeff), Shannon entropy calculation, contextual proximity weighting, and structured file redaction for `.txt`, `.csv`, and `.json`, significant opportunities exist to expand RedactX into an enterprise-grade endpoint privacy framework.

This document outlines the systematic engineering roadmap for future upgrades across four core pillars:
1. **File Format & Parser Expansion**
2. **Advanced Detection & Cryptographic Intelligence**
3. **Proactive System-Level Protection & DevSecOps Workflows**
4. **Crispy & High-Fidelity UI/UX Enhancements**

---

## 1. Next-Generation File Format & Parsing Ingestion

The initial MVP deliberately constrained parsing to flat text, CSV, and JSON to isolate and validate the core DLP heuristic pipeline without the baggage of complex container extraction. Future versions will incorporate native, zero-cloud parsers for mainstream enterprise document formats:

```
+-------------------------------------------------------------------------+
|                        RedactX File Ingestion Layer                     |
+--------------------+--------------------+-------------------------------+
| Structured Data    | Compound Documents | Unstructured Media            |
| - .json / .jsonl   | - .docx (OpenXML)  | - .png, .jpg, .tiff (OCR)     |
| - .csv / .tsv      | - .xlsx (Spread)   | - Scanned ID / Invoices       |
| - .yaml / .toml    | - .pdf (MuPDF/pypdf| - Screen Captures             |
| - .sql / .sqlite   | - .pptx (Slides)   | - Ephemeral Memory Sandboxes  |
+--------------------+--------------------+-------------------------------+
```

### 1.1 Portable Document Format (`.pdf`)
* **Vector Text Stream Extraction:** Integrate `PyMuPDF` (MuPDF) or `pypdf` for fast, local vector text extraction, maintaining exact bounding box coordinates $(x_0, y_0, x_1, y_1)$ for every character glyph.
* **True Structural Redaction:** Unlike amateur tools that merely superimpose black rectangle annotations over text (which can easily be selected, copied, or removed), RedactX v2.0 will sanitize the underlying `/Contents` stream and font glyph definitions. Sensitive text will be physically purged from the PDF object stream before writing out the sanitized document.
* **Metadata & Attachment Scrubbing:** Automatic inspection and deletion of sensitive PDF metadata (`/Author`, `/CreationDate`, `/Producer`, and hidden XML metadata packets).

### 1.2 Office OpenXML Documents (`.docx`, `.xlsx`, `.pptx`)
* **Word Processing (`.docx`):** Integration with `python-docx` to inspect and redact body paragraphs, nested tables, header/footer zones, footnotes, endnotes, and revision history comments.
* **Spreadsheet Audit (`.xlsx`, `.xlsm`):** Integration with `openpyxl` / `et_xmlfile` supporting streaming cell evaluation. Detectors will inspect cell values, hidden rows/columns, formula definitions (e.g., hardcoded credentials in `=WEBSERVICE()` formulas), and detached worksheet tabs.
* **Presentations (`.pptx`):** Extracting slide text, speaker notes, and embedded vector shapes.

### 1.3 Embedded Offline Optical Character Recognition (OCR)
* **Problem:** Critical PII (such as Aadhaar card photocopies, credit card photographs, PAN cards, hospital discharge slips, and IT screenshots) resides in raster images (`.png`, `.jpg`, `.jpeg`, `.tiff`, `.bmp`).
* **Offline Solution:** Bundle an optimized, local-only OCR pipeline utilizing `pytesseract` (bundling a self-contained Tesseract OCR binary) or an ONNX-quantized PaddleOCR model executing locally on CPU or DirectML.
* **Visual Bounding Box Masking:** Detected sensitive text regions on images will be pixel-blurred (Gaussian blur) or burned with solid black redaction blocks at the pixel matrix level.

### 1.4 Code Repositories & Structured Configurations
* **Source Code Parsers:** Syntax-aware tokenizers for `.py`, `.js`, `.ts`, `.java`, `.go`, `.c`, `.rs`, `.php`, and `.sql`.
* **Abstract Syntax Tree (AST) Disambiguation:** Differentiating between code comments, string literals, and variable identifiers. This prevents false alarms on variable names like `card_number` while flagging actual string values like `"4532015112830366"`.
* **Configuration Files:** First-class parsing for `.yaml`, `.yml`, `.toml`, `.xml`, `.ini`, and `.env` files.

### 1.5 Recursive Archive Inspection
* **Decompression Sandbox:** Deep, in-memory inspection of compressed archives (`.zip`, `.tar.gz`, `.tar.bz2`, `.7z`, `.rar`) without saving unredacted intermediate contents to physical persistent storage.
* **Zip Bomb Protection:** Hard ceilings on recursive decompression depth (max 3 levels) and extracted size quotas to prevent denial-of-service via resource exhaustion.

---

## 2. Advanced Detection & Cryptographic Intelligence

While regex combined with algorithmic checksums (Luhn, Verhoeff) covers deterministic identifiers, unstructured and obfuscated data leaks require deeper heuristic models.

### 2.1 Zero-Cloud Small Language Model (SLM) Integration
* **Motivation:** Human-written leaks (e.g., *"Our AWS cluster root password for production is Summer2024!"* or confidential intellectual property clauses) lack standardized regular expressions.
* **Architecture:** Integrate a quantized 4-bit local Small Language Model (e.g., **Phi-3-mini-4k-instruct**, **Gemma-2-2B-IT**, or fine-tuned **ModernBERT / RoBERTa-NER**) running entirely on local device hardware via `llama-cpp-python` or ONNX Runtime.
* **Privacy Guarantee:** The model executes completely in system RAM/VRAM without outbound socket connections or API keys, preserving RedactX's zero-cloud ethos while offering semantic understanding.

### 2.2 Custom YARA & User-Defined Rules Engine
* **YARA Rule Support:** Allow security engineers and compliance auditors to import standard `.yar` rules for organization-specific sensitive patterns (e.g., internal project codenames, secret header signatures, proprietary file headers).
* **Hot-Reloadable JSON/YAML Rulepacks:** End-users can add custom regex patterns, contextual keywords, and validator scripts into a user config folder (`~/.redactx/rules/`) without rebuilding the Python binary.

### 2.3 International Identifier Expansion
Version 1.0 focused on standard universal entities (Email, IPv4, Phone, Credit Card, API Keys, Passwords) and India-specific identifiers (Aadhaar, UPI). Future updates will add:
* **United States:** Social Security Numbers (SSN with SSA randomization validation rules), Employer Identification Numbers (EIN), Routing Transit Numbers (ABA checksum).
* **European Union:** International Bank Account Numbers (IBAN with mod-97 checksum validation), National Insurance numbers (UK), Tax Identification Numbers (TIN).
* **Healthcare & Life Sciences:** HIPAA-protected health identifiers (Medical Record Numbers, DEA numbers, ICD-10 diagnostic codes).

### 2.4 Obfuscation, Entropy & Decoding Pipelines
* **Pre-Decoding Engine:** Detectors will automatically decode Base64, Hex, URL-encoded, and ROT13 substrings prior to running regex and entropy scans.
* **JWT / Token Introspection:** Structural parsing of JSON Web Tokens (`eyJ...`) to extract claims and verify whether expired, staging, or production credentials are being leaked.
* **Statistical N-Gram Entropy:** Upgrade simple Shannon entropy to Bigram/Trigram Markov transition probability models to distinguish natural high-entropy English text (e.g., medical jargon) from pseudo-random API keys.

---

## 3. Proactive Protection & DevSecOps Workflows

Version 1.0 functions as a reactive, on-demand scanner. The next evolution introduces continuous, proactive protection.

### 3.1 Background Filesystem Daemon (Continuous Guard)
* **OS-Level Directory Watching:** Utilizing the Windows `ReadDirectoryChangesW` API (via `watchdog`), RedactX can run as a minimized system tray daemon.
* **Monitored Hotspots:** Monitor high-risk exfiltration paths:
  - `C:\Users\<User>\Downloads`
  - `C:\Users\<User>\Desktop`
  - Removable USB mass storage mounts
* **Toast Interventions:** Instant native Windows notifications warning the user immediately when a newly downloaded or staged file contains unredacted credentials or PII.

### 3.2 Git Pre-Commit Hook & CLI Mode
* **Headless CLI Command:** Provide a lightweight CLI entrypoint:
  ```bash
  redactx scan --target ./src --fail-on CRITICAL --format json --output report.json
  ```
* **One-Click Pre-Commit Installer:** Enable developers to install RedactX as a local `.git/hooks/pre-commit` script to block accidental commits of `.env` files, API keys, or private keys before pushing to remote repositories.

### 3.3 Clipboard Scrubbing & Ephemeral Memory Shield
* **Clipboard Watcher:** Optional background utility monitoring Windows clipboard text changes. If a user accidentally copies a raw private key, credit card number, or connection string, RedactX prompts with a 1-click option to mask the clipboard buffer before pasting into Slack, Teams, or web forms.

### 3.4 Synthetic Data Generation for Test Environments
* **Beyond Masking:** Instead of simply placing asterisks (`***`) or tokens (`[REDACTED_CREDIT_CARD]`), provide an option to replace detected sensitive entries with statistically valid, synthetic mock data (using local generators like `Faker`).
* **Use Case:** Software developers can sanitize production database dumps for local development while preserving valid data types, string lengths, and schema integrity.

---

## 4. Crispy & High-Fidelity UI/UX Enhancements

While the RedactX V1 interface establishes a clean obsidian dark aesthetic, future versions will deliver a state-of-the-art workstation experience.

### 4.1 Side-by-Side Visual Diff Redaction Studio
* **Interactive Split-Screen View:** Left pane displays the original document with syntax highlighting; right pane displays the live redacted version.
* **Synchronized Kinetic Scrolling:** Scrolling one pane synchronously glides the other.
* **Granular Redaction Toggles:** Users can click individual sensitive spans to toggle between *Masked*, *Full Redaction*, *Hash Token*, or *Exempt (False Positive)*.

```
+------------------------------------+------------------------------------+
| ORIGINAL: employees.csv            | SANITIZED PREVIEW: employees_clean |
+------------------------------------+------------------------------------+
| 1 | Alice Smith, 9876543210        | 1 | Alice Smith, +91 ********10    |
| 2 | Bob Jones, 4532015112830366    | 2 | Bob Jones, ****-****-****-0366 |
| 3 | Admin, secret_token_9x#A1!     | 3 | Admin, [REDACTED_CREDENTIAL]   |
+------------------------------------+------------------------------------+
| [Select All]  [Exempt Selected]    | [Save Redacted Copy]  [Export Diff]|
+------------------------------------+------------------------------------+
```

### 4.2 Modern Glassmorphism & GPU Easing
* **Aero/Mica & Acrylic Styling:** Implement Windows 11 native Mica/Acrylic material backing with subtle blur and depth.
* **Fluid Transition Physics:** Integrate `QEasingCurve.OutCubic` animations for accordion cards, tab switching, and modal popups.
* **Custom Typography Suite:** Bundle high-readability modern typography (Inter for UI labels, JetBrains Mono for hex/code previews, and Outfit for bold branding titles).

### 4.3 Interactive Data Lineage & Topology Visualizer
* **Force-Directed Graph View:** Upgrade the current static flow graph to a fully interactive Qt Graphics Scene.
* **Visual Clustering:** Nodes represent scanned folders, files, entity types, and severity levels. Users can visually pinch-to-zoom, drag clusters, and isolate high-risk nodes (e.g., highlighting files that contain both credentials AND PII).

### 4.4 Global Command Palette (`Ctrl + K` / `Ctrl + P`)
* **Keyboard-First Workstation:** Introduce a fuzzy-search spotlight modal:
  - Quickly jump to specific scan results
  - Toggle specific detectors on/off with one keystroke
  - Execute batch export operations without navigating menus

### 4.5 Multi-Theme Engine & Accessibility
* **Theme Palettes:**
  - *Obsidian Dark (Default):* Pitch-black #101114 background with cyan/crimson neon accents.
  - *Nordic Minimalist:* Slate grey and cool frosted glass highlights.
  - *Paper White (High Contrast):* Clean light mode tailored for academic demonstrations, laboratory projectors, and high-visibility printing.
* **Colorblind Modes:** Protanopia, Deuteranopia, and Tritanopia-friendly palette mappings for severity badges.

---

## 5. Phased Release Roadmap

| Release | Focus Area | Key Deliverables | Estimated Milestone |
|:---|:---|:---|:---|
| **v1.1** | Office & PDF Core | Native `.pdf` text extraction; `.docx` and `.xlsx` parsing; export to CSV/JSON report. | Q1 |
| **v1.2** | Visual Redaction & Diff | Side-by-side diff UI; true PDF object stream redaction; custom regex rule loader. | Q2 |
| **v1.3** | OCR & Image Scanning | Embedded offline Tesseract / PaddleOCR; image bounding box redaction; international IDs. | Q3 |
| **v1.5** | DevSecOps & CLI | Headless CLI; git pre-commit hook; synthetic test data generation engine. | Q4 |
| **v2.0** | Semantic SLM & Daemon | 100% offline quantized SLM integration; background folder daemon; Mica glass UI. | Next Major Cycle |

---

## Summary

The architectural trajectory of RedactX preserves its foundational promise: **The data being protected should never leave the machine to be inspected.** By methodically expanding file format support, deepening heuristic and algorithmic detection, and introducing a professional workstation UI, RedactX bridges the gap between lightweight regex scripts and bloated enterprise cloud DLP vendors.
