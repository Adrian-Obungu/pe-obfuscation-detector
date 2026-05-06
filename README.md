<div align="center">
  <img src="https://files.manuscdn.com/user_upload_by_module/session_file/95436842/UzLPtjwGGCdGflng.png" width="100%" alt="PE Obfuscation Detector Banner">
  <br>
  <h1>🛡️ PE Obfuscation Detector</h1>
  <p><i>Advanced Static Forensic Engine for Binary Anomaly Detection</i></p>

  [![Forensic Quality](https://img.shields.io/badge/Forensics-Grade-blueviolet?style=for-the-badge&logo=spyderide)](https://github.com/Adrian-Obungu/pe-obfuscation-detector)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
  [![Environment: Minimal](https://img.shields.io/badge/Environment-Minimal_Ready-success?style=for-the-badge&logo=iphone)](https://github.com/Adrian-Obungu/pe-obfuscation-detector)
</div>

---

## 🔬 Overview
**PE Obfuscation Detector** is a high-fidelity static analysis engine designed to strip away the layers of binary protection. Developed with a "Build Slow, Build Sure" philosophy, it focuses on deep-tissue forensic auditing of Portable Executable (PE) files to identify packing, crypting, and anti-analysis patterns.

Unlike legacy tools that rely solely on brittle signatures, this engine employs a **Multi-Vector Scoring System** that correlates evidence across entropy variance, import table forensics, and structural integrity checks.

---

## 🚀 Core Forensic Vectors

<table align="center">
  <tr>
    <th>Vector</th>
    <th>Description</th>
    <th>Forensic Value</th>
  </tr>
  <tr>
    <td><b>Entropy Variance</b></td>
    <td>Shannon entropy analysis across discrete sections.</td>
    <td>Detects high-density encrypted payloads and packed stubs.</td>
  </tr>
  <tr>
    <td><b>Import Forensics</b></td>
    <td>Analysis of IAT patterns and suspicious API combinations.</td>
    <td>Identifies dynamic resolution loops and process hollowing stubs.</td>
  </tr>
  <tr>
    <td><b>Structural Integrity</b></td>
    <td>Validation of PE headers, EP location, and section characteristics.</td>
    <td>Flags RWX sections and non-standard Entry Point placements.</td>
  </tr>
  <tr>
    <td><b>EP Signatures</b></td>
    <td>Regex-based matching of known packer stubs at the Entry Point.</td>
    <td>Provides high-confidence identification of common protectors.</td>
  </tr>
  <tr>
    <td><b>String Cross-Ref</b></td>
    <td>Correlation between imported APIs and binary string constants.</td>
    <td>Detects "fake" imports used to mislead basic static scanners.</td>
  </tr>
</table>

---

## 📊 Visual Intelligence
The engine provides a **Visual Forensic Map** to interpret binary data at a glance:

- **Interactive Heatmaps**: Visualize section-level entropy to pinpoint where the payload is hidden.
- **Weighted Scoring Tables**: Understand the *why* behind every verdict with a transparent contribution breakdown.
- **D3.js Interactive Reports**: High-end web-based forensics for deep-dive analysis.

<div align="center">
  <img src="https://files.manuscdn.com/user_upload_by_module/session_file/95436842/wczLpnlpvihFOOmZ.png" width="200" alt="Logo">
</div>

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

# Export Evidence as YARA Rule (v0.3.0)
python -m pedetect.cli target_binary.exe --yara
```

---

## 🗺️ Enhancement Roadmap
- [x] **Rich Header Forensics**: MSVC metadata auditing for toolchain identification.
- [x] **IAT Redline Analysis**: Detecting hooked or redirected Import Address Tables.
- [x] **Verdict Narrative Engine**: AI-driven natural language explanations of detection evidence.
- [x] **D3.js Export**: Full interactive HTML forensic reports.
- [ ] **YARA Signature Generation**: Automatic conversion of forensic evidence into scan-ready rules. (Phase 2)
- [ ] **CI/CD Integration**: Automated scan workflows for release artifact validation.

---

## ⚖️ License & Ethics
Distributed under the **MIT License**. This tool is intended for security researchers, malware analysts, and students. Use it to build, learn, and defend.

**Built with 🧠 and 💻 by [Adrian Obungu](https://github.com/Adrian-Obungu)**
