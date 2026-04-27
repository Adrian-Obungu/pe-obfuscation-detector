# pedetect/heuristics/__init__.py
"""
Heuristic modules for PE obfuscation detection.
"""
try:
    from .header import check_header_integrity
except ImportError:
    check_header_integrity = None
try:
    from .sections import check_section_anomalies
except ImportError:
    check_section_anomalies = None
try:
    from .imports import check_import_table
except ImportError:
    check_import_table = None
try:
    from .entropy import check_entropy, compute_entropy
except ImportError:
    check_entropy = compute_entropy = None
try:
    from .signatures import check_ep_signatures, EPSignatureMatcher
except ImportError:
    check_ep_signatures = EPSignatureMatcher = None
try:
    from .strings_ import check_strings
except ImportError:
    check_strings = None

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