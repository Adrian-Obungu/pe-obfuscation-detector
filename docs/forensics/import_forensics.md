# Forensic Deep-Dive: Import Address Table (IAT) Anomalies

## The "Scarcity" Principle
Legitimate Windows applications typically import dozens, if not hundreds, of functions from various system DLLs (`kernel32.dll`, `user32.dll`, `advapi32.dll`, etc.). 

**Packed binaries** often exhibit "Import Scarcity." They may only import two functions:
1. `LoadLibrary`
2. `GetProcAddress`

This is because the packer's "Unpacking Stub" needs these to manually resolve the original program's imports at runtime, keeping the static IAT as small as possible to evade detection.

## Suspicious API Chains
Our engine monitors for specific chains of execution that are characteristic of malware injection:
- **Process Hollowing**: `CreateProcess` -> `NtUnmapViewOfSection` -> `WriteProcessMemory` -> `ResumeThread`.
- **Dynamic Allocation**: `VirtualAlloc` -> `VirtualProtect` (changing memory from RW to RX).

## Fake Import Detection
Advanced obfuscators include "Fake Imports"—calls to legitimate-looking APIs that are never actually executed—just to fool static analysis tools. Our engine correlates imported APIs with the actual strings present in the binary. If an API is imported but no related strings or calls exist, it flags a **Possible Fake Import**.
