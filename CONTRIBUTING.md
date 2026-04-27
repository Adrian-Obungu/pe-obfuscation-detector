# Contributing to PE Obfuscation Detector

First off, thank you for considering contributing to this forensic engine. It's people like you that make this tool better for the entire cybersecurity community.

## Our Philosophy
We build **slow but sure**. We value:
- **Accuracy over Speed**: Low false-positive rates are our priority.
- **Visual Clarity**: Data is useless if it's not interpretable.
- **Minimalism**: The tool must remain functional in minimal environments (like mobile/codespaces).

## How to Contribute

### 1. Adding Heuristics
- Create a new file in `pedetect/heuristics/`.
- Implement a function that accepts a `pefile.PE` object and returns a `(score, evidence_list)` tuple.
- Register your heuristic in `pedetect/core.py`.
- Update `weights.json` with a balanced weight for your new metric.

### 2. Design & UX
- We use D3.js for interactive reports.
- If you're modifying the CLI, use `rich` or standard ANSI for high-contrast visibility.

### 3. Pull Request Process
1. Fork the repo and create your branch from `main`.
2. Ensure the `Forensic Benchmarking` workflow passes.
3. Update the `README.md` if you're adding a new capability.
4. Submit your PR with a detailed description of the "Forensic Value" of your changes.

## Code of Conduct
Be professional, be technical, and be helpful. We are all here to learn and build better security tools.
