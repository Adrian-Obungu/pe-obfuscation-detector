# Forensic Deep-Dive: Shannon Entropy in PE Files

## Theoretical Foundation
In the context of binary analysis, **Shannon Entropy** measures the "randomness" or "uncertainty" of a data stream. For a Portable Executable, entropy values typically range from 0 to 8 bits per byte.

### The "Magic Number": 7.0
- **< 6.0**: Generally indicates structured code or text data.
- **6.0 - 7.0**: Often found in compressed data or complex instruction streams.
- **> 7.0**: High probability of **encryption** or **packing**.

## Forensic Implications
High entropy in a section named `.text` is a massive red flag. Standard compiler-generated code has a predictable structure and therefore lower entropy. When a packer compresses the code, it destroys these patterns, driving entropy toward the maximum of 8.0.

### Uniform vs. Localized Entropy
- **Localized High Entropy**: Usually indicates an encrypted resource or a small packed stub.
- **Uniform High Entropy**: Suggests the entire file is wrapped in a crypter, where even the headers might be obfuscated.

## How our Engine Detects This
Our engine calculates entropy per-section to find "islands of randomness" and computes **Entropy Variance**. Low variance across multiple high-entropy sections is a signature of modern "uniformly packed" binaries.
