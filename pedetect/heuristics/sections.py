# pedetect/heuristics/sections.py
"""Heuristic 2: Section table anomalies detection."""
import pefile

SUSPICIOUS_SECTION_NAMES = {
    'UPX0', 'UPX1', 'UPX2',
    '.aspack', '.adata',
    '.MPRESS1', '.MPRESS2',
    '.petite',
    '.winapi',
    'pec1', 'pec2', 'pec',
    '.nsp0', '.nsp1', '.nsp2',
    '.yP', '.y0da',
    '.enigma',
    '.vmp0', '.vmp1',
    '.themida',
    '.sforce',
    '.safedisc',
    '.securom',
    '.ndrv',
}

def check_section_anomalies(pe: pefile.PE) -> tuple:
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
    if section_count < 3:
        evidence.append(f'Low section count: {section_count}')
        scores.append(0.4)
    elif section_count > 8:
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
        if ratio > 5.0:
            evidence.append(f'Section {name}: RawSize/VirtualSize ratio = {ratio:.1f}')
            scores.append(0.5)
        elif ratio < 0.2:
            evidence.append(f'Section {name}: RawSize/VirtualSize ratio = {ratio:.2f}')
            scores.append(0.6)

    score = sum(scores) / max(len(scores), 1) if scores else 0.0
    return (min(score, 1.0), evidence)
