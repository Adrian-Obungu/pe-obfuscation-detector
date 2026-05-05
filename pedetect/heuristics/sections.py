# pedetect/heuristics/sections.py
"""Heuristic 2: Section table anomalies detection."""
import pefile
from pedetect.config_loader import _load_config

CONFIG = _load_config().get("sections", {})
SUSPICIOUS_SECTION_NAMES = set(CONFIG.get("suspicious_names", []))
MIN_NORMAL_COUNT = CONFIG.get("min_normal_count", 3)
MAX_NORMAL_COUNT = CONFIG.get("max_normal_count", 8)
RATIO_HIGH = CONFIG.get("raw_virtual_ratio_high", 5.0)
RATIO_LOW = CONFIG.get("raw_virtual_ratio_low", 0.2)

def check_section_anomalies(pe: pefile.PE) -> tuple:
    """Check for section anomalies including suspicious names and sizes."""
    evidence = []
    scores = []

    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
        name_lower = name.lower().lstrip('.')
        for sus in SUSPICIOUS_SECTION_NAMES:
            sus_clean = sus.lower().lstrip('.')
            if name_lower == sus_clean:
                evidence.append(f'Suspicious section name: {name}')
                scores.append(0.8)
                break

    section_count = len(pe.sections)
    if section_count < MIN_NORMAL_COUNT:
        evidence.append(f'Low section count: {section_count}')
        scores.append(0.4)
    elif section_count > MAX_NORMAL_COUNT:
        evidence.append(f'High section count: {section_count}')
        scores.append(0.3)

    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
        if name in ('.text', '.code', 'CODE'):
            is_write = section.Characteristics & 0x80000000
            if is_write:
                evidence.append(f'Writable code section: {name} has MEM_WRITE')
                scores.append(0.9)
            break

    for section in pe.sections:
        raw_size = section.SizeOfRawData
        virtual_size = section.Misc_VirtualSize
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
        if raw_size == 0 and virtual_size > 0:
            evidence.append(f'Section {name} has zero raw size but virtual size 0x{virtual_size:X}')
            scores.append(0.6)
            continue
        if raw_size == 0 or virtual_size == 0:
            continue
        ratio = raw_size / virtual_size
        if ratio > RATIO_HIGH:
            evidence.append(f'Section {name}: RawSize/VirtualSize ratio = {ratio:.1f}')
            scores.append(0.5)
        elif ratio < RATIO_LOW:
            evidence.append(f'Section {name}: RawSize/VirtualSize ratio = {ratio:.2f}')
            scores.append(0.6)

    score = sum(scores) / max(len(scores), 1) if scores else 0.0
    return (min(score, 1.0), evidence)
