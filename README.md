# ForensiX

ForensiX is an automated digital forensics and incident triage platform developed as a cybersecurity learning and portfolio project.

The goal of ForensiX is to automate and streamline the initial phases of digital forensic investigations, starting from raw evidence ingestion to structured analysis reporting, while adhering strictly to fundamental forensic integrity principles.

The current **V1 (Evidence Foundation)** release establishes a reliable, non-destructive evidence triage workflow:

```text
Evidence File
     ↓
Evidence Registration
     ↓
File Identification
     ↓
Metadata Extraction
     ↓
Cryptographic Hashing (MD5 + SHA-256)
     ↓
Unified Forensic Analysis Result
     ↓
JSON Forensic Report
     ↓
Terminal Summary
```

---

## Features

ForensiX V1 implements the following foundational capabilities:

- **Evidence Registration**: Registers evidence targets, validates paths, and assigns a unique identifier (`EV-<UUIDv4>`) with a UTC timestamp without modifying the evidence file.
- **Filesystem Metadata Extraction**: Reads file size, POSIX permissions (octal format, e.g. `0644`), and ISO 8601 UTC timestamps (`mtime`, `atime`, `btime` when available).
- **File Identification Hints**: Identifies filename, extension, and basic MIME type using Python standard-library mappings.
- **Cryptographic Hashing**: Computes dual cryptographic digests (MD5 and SHA-256) in a single streaming pass using fixed 64 KB memory buffers.
- **Unified Forensic Analysis Result**: Binds all analysis data into strongly typed, immutable dataclass structures (`ForensicAnalysisResult`).
- **JSON Reporting**: Automatically exports structured, human-readable forensic reports formatted in UTF-8 into the isolated `reports/` directory.
- **Command-Line Interface (CLI)**: Enables simple execution via `python3 -m forensix <evidence_file>` with clean, traceback-free error messages.
- **Automated Validation**: Includes a 63-test regression suite covering edge cases, directory traversal prevention, and evidence immutability.
- **Evidence Immutability Checks**: Analyzes evidence strictly in binary read-only mode (`rb`) to ensure raw bytes and timestamps remain unaltered.

---

## Current Scope

**V1 Scope**: ForensiX V1 processes **one evidence file per CLI execution**. It focuses strictly on initial evidence intake, file identification, metadata extraction, cryptographic integrity verification, and JSON report generation.

**Future Work (Not Implemented in V1)**:
The following advanced features are part of the long-term vision and are **NOT** present in V1:
- Host artifact extraction (Windows Registry, EVTX, syslog, shell histories)
- Timeline reconstruction and event sequencing
- Event correlation and rule-based detection (Sigma, YARA, IOCs)
- Network forensics and PCAP packet analysis
- Memory dump forensics (Volatility integrations)
- Web browser forensics and SQLite database extraction
- Threat intelligence lookups
- Web dashboards and graphical user interfaces
- Non-JSON report formats (HTML, PDF, CSV)
- Automated multi-file case management

---

## Project Structure

```text
ForensiX/
├── docs/                      # Documentation and technical review files
│   └── V1_REVIEW.md           # Final V1 implementation and scope review
├── evidence/                  # Working directory for raw evidence files (gitignored)
│   └── .gitkeep
├── reports/                   # Destination for generated JSON reports (gitignored)
├── src/
│   └── forensix/              # Core ForensiX application package
│       ├── __init__.py        # Package exports and version metadata
│       ├── __main__.py        # Entry point for 'python3 -m forensix'
│       ├── main.py            # CLI argument parsing, execution, and terminal summary
│       ├── hasher.py          # Dual streaming MD5 and SHA-256 hashing engine
│       ├── analyzer.py        # Metadata extraction and unified data structures
│       ├── evidence.py        # Evidence registration and EvidenceRecord dataclass
│       └── reporter.py        # JSON report generator and filename sanitizer
├── tests/                     # Automated unit and integration test suite
│   ├── __init__.py
│   ├── test_hasher.py         # Hashing engine unit tests
│   ├── test_analyzer.py       # Metadata and identification tests
│   ├── test_evidence.py       # Evidence registration tests
│   ├── test_unified_result.py # Unified data model tests
│   ├── test_reporter.py       # JSON report generation tests
│   ├── test_cli.py            # CLI integration tests
│   └── test_end_to_end.py     # End-to-end pipeline and immutability tests
├── README.md                  # Project documentation
└── .gitignore                 # Excludes evidence, reports, and caches from Git
```

- `docs/`: Holds project documentation and milestone reviews.
- `evidence/`: Holds raw evidence samples for local testing; evidence contents are ignored by Git.
- `reports/`: Stores generated JSON analysis reports; separated strictly from evidence.
- `src/forensix/`: Modular source code separated by responsibilities (hashing, analysis, registration, reporting, CLI).
- `tests/`: Automated unit and end-to-end integration tests.

---

## Installation

ForensiX V1 is built entirely using the **Python standard library**. No third-party packages, virtual environments, or compilation tools are required.

### Requirements
- **Python**: Version 3.9 or higher (tested on Python 3.14 on Linux).
- **Operating System**: Linux (Ubuntu, Debian, Fedora, Arch, etc.), macOS, or POSIX-compliant environments.

### Setup
Clone the repository and verify your Python version:

```bash
git clone https://github.com/adnannkc/ForensiX.git
cd ForensiX
python3 --version
```

---

## Running ForensiX

Run ForensiX as a module by passing an evidence file path:

```bash
PYTHONPATH=src python3 -m forensix <evidence_file>
```

*(Note: Adding `PYTHONPATH=src` ensures Python locates the `forensix` package when running directly from the repository source).*

### Example Run

Create a sample evidence file:

```bash
echo "Unauthorized access detected in auth.log" > sample_evidence.txt
PYTHONPATH=src python3 -m forensix sample_evidence.txt
```

### Expected Terminal Output

```text
==================================================
ForensiX Analysis Complete
==================================================
Evidence ID : EV-387d74e8-af84-4205-9199-76d03c3c9f32
File        : sample_evidence.txt
Size        : 41 bytes
Type        : text/plain
MD5         : c98d3632cfba9828d13b4c1001eeac37
SHA-256     : 4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754
Report      : /home/adnan/ForensiX/reports/EV-387d74e8-af84-4205-9199-76d03c3c9f32.json
==================================================
```

### Command-Line Options

```text
usage: python3 -m forensix [-h] [-o OUTPUT_DIR] [-v] evidence_file

positional arguments:
  evidence_file         Path to the forensic evidence file to analyze.

options:
  -h, --help            show this help message and exit
  -o, --output-dir OUTPUT_DIR
                        Directory to store generated JSON reports (default: reports/).
  -v, --version         show program's version number and exit
```

---

## JSON Reports

When an analysis succeeds, ForensiX generates an isolated, indented JSON report:
- **Location**: Written to `reports/` by default (or a custom directory specified via `-o`).
- **Filename**: Named deterministically after the evidence ID (`<evidence_id>.json`) with path-traversal sanitization.
- **Isolation**: Reports are derived artifacts; raw evidence files are never copied or moved into `reports/`.
- **Format**: JSON is currently the sole supported reporting format for V1.

### Example JSON Report

```json
{
    "evidence": {
        "evidence_id": "EV-387d74e8-af84-4205-9199-76d03c3c9f32",
        "original_path": "/home/adnan/ForensiX/sample_evidence.txt",
        "registered_at": "2026-09-29T17:51:36.309708+00:00"
    },
    "file": {
        "filename": "sample_evidence.txt",
        "size": 41,
        "extension": ".txt",
        "type": "text/plain"
    },
    "metadata": {
        "permissions": "0664",
        "modified": "2026-09-29T17:51:36.209397+00:00",
        "accessed": "2026-09-29T17:51:36.206684+00:00",
        "created": null
    },
    "hashes": {
        "md5": "c98d3632cfba9828d13b4c1001eeac37",
        "sha256": "4402a77918a55e2d1d3a54d52fecefe3b86e088fef27b4b1a29c9a622f6fa754"
    }
}
```

---

## Testing

Run the automated test suite using Python's standard `unittest` discovery runner:

```bash
PYTHONPATH=src python3 -m unittest discover -v -s tests
```

### Current Validation Status
**63 tests passing** (0 failures, 0 errors).

The automated test suite verifies:
- Hashing accuracy against known NIST test vectors and cross-boundary chunk streaming.
- Filesystem metadata extraction, POSIX permissions, and ISO 8601 formatting.
- Evidence registration and UUID generation.
- Immutability of unified `ForensicAnalysisResult` dataclasses.
- JSON serialization, indentation, and path-traversal protection.
- CLI argument parsing, help messaging, and non-zero exit codes for invalid inputs.
- End-to-end pipeline robustness across normal text, empty files, binary streams, Unicode filenames, deep subdirectories, read-only files, and pre/post bitstream immutability checks.

---

## Evidence Safety

ForensiX is designed to handle evidence with forensic care:
- **Read-Only Access**: Files are opened strictly in binary read-only mode (`mode="rb"`).
- **Streaming Buffers**: Reads data in fixed 64 KB chunks, preventing process memory exhaustion on large images.
- **No Evidence Modifications**: ForensiX does not modify file contents, file names, or permissions.
- **Read-Only Filesystem Support**: Works seamlessly on write-protected or read-only files (`chmod 0444`).

---

## Forensic Limitations

To maintain forensic rigor, the following technical limitations must be understood:

1. **Hashes as Integrity Checks**: MD5 and SHA-256 digests act strictly as integrity-checking mechanisms. A matching hash confirms whether bitstreams match a known reference; it does **not** by itself establish authorship, origin, ownership, or legal authenticity.
2. **Identification Hints**: Extension parsing and MIME type detection are heuristic hints based on standard filename tables (`mimetypes`); they do not inspect file headers (magic bytes) and do not provide definitive proof of true file format.
3. **Registration vs. Chain of Custody**: Evidence registration assigns an internal tracking handle; it does **not** constitute a formal legal chain-of-custody log (which requires physical custody transfers and authorized signatures).
4. **Linux Birth Timestamps**: Standard Linux `os.stat` does not universally expose file creation timestamps (`btime`). ForensiX records this as `null` rather than substituting inode status change time (`ctime`), which would be forensically inaccurate.
5. **Access Time (`atime`) Side Effect**: Reading raw bytes during cryptographic hashing can update `atime` on filesystems mounted with default `relatime` or `strictatime`. Live forensic investigations should always be performed on write-blocked hardware or read-only volume mounts (`mount -o ro`).
6. **Testing vs. Legal Admissibility**: Passing automated test suites demonstrates that software functions in accordance with its specifications; it does not establish formal forensic tool certification (e.g., NIST CFTT) or guarantee universal legal admissibility in court.

---

## Development Roadmap

- [x] **V1 — Evidence foundation — COMPLETE**
  - [x] Milestone 1: Hashing Engine
  - [x] Milestone 2: File Metadata and Identification
  - [x] Milestone 3: Evidence Registration
  - [x] Milestone 4: Unified Analysis Result Structure
  - [x] Milestone 5: JSON Reporting
  - [x] Milestone 6: CLI Integration
  - [x] Milestone 7: End-to-End Automated Tests
  - [x] Milestone 8: Documentation Polish & Review
- [ ] **V2 — Host artifacts — Planned**
- [ ] **V3 — Timeline reconstruction — Planned**
- [ ] **V4 — Event correlation and rule-based detection — Planned**
- [ ] **V5 — Network forensics — Planned**
- [ ] **V6 — Memory forensics — Planned**
- [ ] **V7 — Investigation dashboard — Planned**
- [ ] **V8 — Extended reporting and audit trail — Planned**
- [ ] **V9 — Automation — Planned**
