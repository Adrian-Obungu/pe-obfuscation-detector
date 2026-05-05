# Real-World Validation Methodology

This document outlines the procedure for validating the `pe-obfuscation-detector` against real-world binaries to ensure forensic accuracy and minimize false positives.

## A. Corpus Curation

To build a professional-grade validation set, curate 20-30 PE files from the following sources:

1.  **Legitimate System Files**:
    - `C:\Windows\System32\notepad.exe`
    - `C:\Windows\System32\calc.exe`
    - `C:\Windows\System32\cmd.exe`
2.  **Known-Clean Installers**:
    - Python Windows Installer
    - Git for Windows Installer
    - VS Code Setup
3.  **Synthetic Packed Samples**:
    - Compress the legitimate system files above using `UPX` (`upx -9 notepad.exe`).
    - Compress using `ASPack` or `MPRESS` if available.

## B. Benchmarking with `tools/benchmark.py`

Use the provided benchmarking script to compare `pedetect` results against **Detect It Easy (DiE)**, which serves as the industry baseline.

### Usage
```bash
python tools/benchmark.py --dir ./my_corpus --output results.csv
```

### Metrics
The script computes:
- **Precision**: Accuracy of `PACKED` verdicts.
- **Recall**: Ability to catch all packed samples.
- **F1-Score**: Harmonic mean of precision and recall.

## C. Weight Calibration Methodology

If the benchmark reveals high False Positives (FP) or False Negatives (FN), follow this tuning process:

1.  **Identify the Culprit**: Look at the `evidence_chain` in the JSON output for FP samples.
2.  **Adjust `weights.json`**:
    - If a specific heuristic (e.g., `section_anomalies`) is over-triggering on clean files, reduce its weight (e.g., from `0.7` to `0.5`).
    - If packed files are being missed, increase the weight of the heuristics that *should* have caught them (e.g., `entropy` or `ep_signature`).
3.  **Re-run Benchmark**: Ensure the changes improve overall F1-score without regressing on other samples.
