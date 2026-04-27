# PE Binary Obfuscation Detector

**Static heuristic analysis engine for detecting packers, crypters, and obfuscation in Windows PE files.**

Author: **Adrian S. Obungu**

Version: 0.1.0  |  License: MIT

---

## Overview

`pedetect`  is a pure–Python static analysis tool that ingests a Portable Executable (PE) file and determines whether it has been packed, crypted, or otherwise obfuscated. It uses **six independent heuristic detectors** fused via a weighted scoring engine to produce a verdict: **CLEAN**, **SUSPICIOUS**, or **PACKED** – backed by a full evidence trail.

Designed for malware triage, incident response, and reverse engineering workflows. Zero reliance on execution — **static analysis only.**

---

## Features

- **6 Heuristic Engines**
  - Header integrity (MZ/PE magic, EntryPoint validation, RWX sections)
  - Section anomalies (packer‑specific names, size discrepancies)
  - Import table forensics (scarcity, suspicious API combinations, TLS correlation)
  - Entropy analysis (Shannon entropy per–section and whole–file, crypter pattern)
  - EP byte signatures (PEID–style wildcard matching, JSON database, 8 signatures)
  - String cross–reference (fake import detection)
- **Weighted scoring** via `weights.json` — tune signal importance without code changes
- **Extensible signature database** — add new packer stubs via JSON
- **CLI*� with verbose, JSON, and file–output modes
- **Single dependency** — `pefile` (pure Python, no C extensions)
- **Codespaces / iPad / minimal–env ready**

---

## Installation

```bash
git clone https://github.com/Adrian-Obungu/pe-obfuscation-detector.git
cd pe-obfuscation-detector
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic analysis (text output)
python -m pedetect.cli sample.exe

# Verbose (show all evidence)
python -m pedetect.cli sample.exe -v

# JSON output (for integration with other tools)
python -m pedetect.cli sample.exe -o json

# Save to file
python -m pedetect.cli sample.exe -o json -f result.json

# Custom signature database
python -m pedetect.cli sample.exe --sigdb my_signatures.json
```

---

## Example Output

```
File: /tmp/test_packed.exe
MD5:  8e9ced5ffcd8861871f72f8d8b8adc76
SHA256: 50562d359ba519aac8eac0c72b91e36d168562b6a98a801808a4518f01906ddd
Size: 864 bytes
Verdict: PACKED (87.50%)

Evidence:
  • EP signature match: UPX 2.90+ — UPX standard prologue (confidence: 0.95)
  • Minimal imports: 0 functions from 0 DLL
  • Import table stripped (non-DLL)
  • High entropy section: .text (7.41) — above threshold 7.0
  • RWX section found: .text
  • Suspicious section name: UPX0
```

---

## Heuristic Weight Configuration

Edit `pedetect/weights.json` to tune sensitivity:

```json
{
  "heuristics": {
    "header_integrity": 0.8,
    "section_anomalies": 0.7,
    "import_table": 0.9,
    "entropy": 0.7,
    "ep_signature": 0.9,
    "strings": 0.4
  }
}
```

---

## Signature Database

`pedetect/signatures.json` contains 8 known packer signatures (UPX, ASPack, FSG, MPress, PECompact, NSPack, generic crypter stubs). Add new entries by following the schema:

```json
{
  "name": "MyPacker",
  "pattern": "AA BB CC ?? DD DE",
  "ep_offset": 0,
  "min_ep_length": 6,
  "confidence": 0.85,
  "description": "MyPacker prologue"
}
```

---

## Project Structure

```
pe-obfuscation-detector/
│ ━─ pedetect/
│   ┄─ cli.py              # CLI entry point
│   ┄─ core.py             # Orchestrator / scoring engine
│   ┄─ signatures.json     # EP byte signature database
│   ┄─ weights.json        # Heuristic weight configuration
│   ├── heuristics/
│       ├─ header.py      # Header integrity checks
│       ├─ sections.py     # Section anomaly detection
│       ├─ imports.py      # Import table forensics
│       ├─ entropy.py      # Shannon entropy analysis
│       ├─ signatures.py    # EP byte pattern matcher
│       └─ strings_.py     # String cross-reference
├─ requirements.txt
├─ README.md
┄─ LICENSE
```

---

## Dependencies

- Python 3.8+
+- [pefile](https://github.com/erocarrera/pefile) ≥ 2023.2.7 (pure Python, pip-installable)

---

## Roadmap

- [ ] Add ELF and Mach-O support
- [ ] YARA rule export from evidence
- [ ] ML–based classification module (optional)
- [ ] Web frontend / REST API
- [ ] Real-time filesystem monitoring integration

---

## Author

**Adrian S. Obungu**
- GitHub: [@Adrian-Obungu](https://github.com/Adrian-Obungu)
- LinkedIn: [Adrian Obungu](https://www.linkedin.com/in/adrian-o-9b4856260/)

---

## License

MIT License. See `LICENSE` for details.
