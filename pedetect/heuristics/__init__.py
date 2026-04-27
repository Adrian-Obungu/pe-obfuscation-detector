# pedetect/heuristics/__init__.py
"""
Heuristic modules for PE obfuscation detection.
Imports are guarded; missing modules are logged and set to None.
"""
import sys

_MISSING = []

try:
    from .header import check_header_integrity
except ImportError as e:
    _MISSING.append(f"header: {e}")
    check_header_integrity = None

try:
    from .sections import check_section_anomalies
except ImportError as e:
    _MISSING.append(f"sections: {e}")
    check_section_anomalies = None

try:
    from .imports import check_import_table
except ImportError as e:
    _MISSING.append(f"imports: {e}")
    check_import_table = None

try:
    from .entropy import check_entropy, compute_entropy
except ImportError as e:
    _MISSING.append(f"entropy: {e}")
    check_entropy = compute_entropy = None

try:
    from .signatures import check_ep_signatures, EPSignatureMatcher
except ImportError as e:
    _MISSING.append(f"signatures: {e}")
    check_ep_signatures = EPSignatureMatcher = None

try:
    from .strings_ import check_strings
except ImportError as e:
    _MISSING.append(f"strings_: {e}")
    check_strings = None

if _MISSING:
    print("[WARNING] Heuristic imports failed:", file=sys.stderr)
    for msg in _MISSING:
        print(f"  - {msg}", file=sys.stderr)
    print("  The tool will run with limited detection capability.", file=sys.stderr)

__all__ = [
    "check_header_integrity",
    "check_section_anomalies",
    "check_import_table",
    "check_entropy",
    "compute_entropy",
    "check_ep_signatures",
    "EPSignatureMatcher",
    "check_strings",
]