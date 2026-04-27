# pedetect/heuristics/header.py
"""Heuristic 1: PE header integrity checks."""
import pefile

# Raw section characteristics flags (independent of pefile constant names)
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE   = 0x80000000

def check_header_integrity(pe: pefile.PE) -> tuple:
    evidence = []
    scores = []
    if pe.DOS_HEADER.e_magic != 0x5A4D:
        evidence.append('Invalid DOS magic — not MZ')
        scores.append(1.0)
    if pe.NT_HEADERS.Signature != 0x00004550:
        evidence.append('Invalid PE signature — not PE\\0\\0')
        scores.append(1.0)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_in_section = False
    for section in pe.sections:
        va_start = section.VirtualAddress
        va_end = va_start + section.Misc_VirtualSize
        if va_start <= ep < va_end:
            ep_in_section = True
            break
    if not ep_in_section:
        evidence.append(f'EntryPoint (0x{ep:08X}) not within any section bounds')
        scores.append(0.8)
    max_va = max(s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections)
    expected_size = max_va + 0x1000
    if pe.OPTIONAL_HEADER.SizeOfImage > expected_size * 2:
        evidence.append(
            f'SizeOfImage ({pe.OPTIONAL_HEADER.SizeOfImage:#x}) '
            f'much larger than section extent ({expected_size:#x})'
        )
        scores.append(0.4)
    rwx_count = 0
    for section in pe.sections:
        characteristics = section.Characteristics
        is_exec = characteristics & IMAGE_SCN_MEM_EXECUTE
        is_write = characteristics & IMAGE_SCN_MEM_WRITE
        if is_exec and is_write:
            rwx_count += 1
            evidence.append(f'RWX section found: {section.Name.decode().rstrip(chr(0))}')
    if rwx_count > 0:
        scores.append(0.7 * min(rwx_count, 1))
    for section in pe.sections:
        va_start = section.VirtualAddress
        va_end = va_start + section.Misc_VirtualSize
        if va_start <= ep < va_end:
            section_name = section.Name.decode().rstrip(chr(0))
            if section_name not in ('.text', '.code', 'CODE', 'INIT'):
                evidence.append(f'EntryPoint in non-standard section: {section_name}')
                scores.append(0.5)
            break
    score = sum(scores) / max(len(scores), 1) if scores else 0.0
    return (min(score, 1.0), evidence)
