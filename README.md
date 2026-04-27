# 🛡️ PE Obfuscation Detector
### *Advanced Static Forensic Engine for Binary Anomaly Detection*

[![Forensic Quality](https://img.shields.io/badge/Forensics-Grade-blueviolet?style=for-the-badge&logo=spyderide)](https://github.com/Adrian-Obungu/pe-obfuscation-detector)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Environment: Minimal](https://img.shields.io/badge/Environment-Minimal_Ready-success?style=for-the-badge&logo=iphone)](https://github.com/Adrian-Obungu/pe-obfuscation-detector)

---

## 🔬 Overview
**PE Obfuscation Detector** is a high-fidelity static analysis engine designed to strip away the layers of binary protection. Developed with a "Build Slow, Build Sure" philosophy, it focuses on deep-tissue forensic auditing of Portable Executable (PE) files to identify packing, crypting, and anti-analysis patterns.

Unlike legacy tools that rely solely on brittle signatures, this engine employs a **Multi-Vector Scoring System** that correlates evidence across entropy variance, import table forensics, and structural integrity checks.

---

## 🚀 Core Forensic Vectors

| Vector | Description | Forensic Value |
| :--- | :--- | :--- |
| **Entropy Variance** | Shannon entropy analysis across discrete sections. | Detects high-density encrypted payloads and packed stubs. |
| **Import Forensics** | Analysis of IAT patterns and suspicious API combinations. | Identifies dynamic resolution loops and process hollowing stubs. |
| **Structural Integrity** | Validation of PE headers, EP location, and section characteristics. | Flags RWX sections and non-standard Entry Point placements. |
| **EP Signatures** | Regex-based matching of known packer stubs at the Entry Point. | Provides high-confidence identification of common protectors (UPX, ASPack, etc.). |
| **String Cross-Ref** | Correlation between imported APIs and binary string constants. | Detects "fake" imports used to mislead basic static scanners. |

---

## 📊 Visual Intelligence
The engine doesn't just give you a verdict; it provides a **Visual Forensic Map**:

- **Interactive Heatmaps**: Visualize section-level entropy to pinpoint where the payload is hidden.
- **Weighted Scoring Tables**: Understand the *why* behind every verdict with a transparent contribution breakdown.
- **D3.js Interactive Reports**: (Coming Soon) High-end web-based forensics for deep-dive analysis.

---

## 🛠️ Installation & Usage

### Minimal Environment Setup
Designed to run flawlessly on mobile-first environments (Codespaces, Termux) and standard workstations.

```bash
# Clone the Forensic Engine
gh repo clone Adrian-Obungu/pe-obfuscation-detector
cd pe-obfuscation-detector

# Initialize Environment
pip install -r requirements.txt
```

### Execution
```bash
# Basic Analysis
python -m pedetect.cli target_binary.exe

# High-Fidelity Forensic Audit (Verbose + Heatmap)
python -m pedetect.cli target_binary.exe -vv --heatmap
```

---

## 🗺️ Enhancement Roadmap
- [ ] **Rich Header Forensics**: MSVC metadata auditing for toolchain identification.
- [ ] **IAT Redline Analysis**: Detecting hooked or redirected Import Address Tables.
- [ ] **Verdict Narrative Engine**: AI-driven natural language explanations of detection evidence.
- [ ] **D3.js Export**: Full interactive HTML forensic reports.

---

## ⚖️ License & Ethics
Distributed under the **MIT License**. This tool is intended for security researchers, malware analysts, and students. Use it to build, learn, and defend.

**Built with 🧠 and 💻 by [Adrian Obungu](https://github.com/Adrian-Obungu)**
