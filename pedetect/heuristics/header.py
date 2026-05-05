# pedetect/heuristics/header.py
"""Heuristic 1: PE header integrity checks."""
import pefile
from pedetect.config_loader import _load_config

CONFIG = _load_config().get("header", {})
IMAGE_SCN_MEM_EXECUTE = getattr(pefile, 'IMAGE_SCN_MEM_EXECUTE', 0x20000000)
IMAGE_SCN_MEM_WRITE  = getattr(pefile, 'IMAGE_SCN_MEM_WRITE', 0x80000000)

def check_header_integrity(pe: pefile.PE) -> tuple:
    """Validate PE header structure and flag anomalies."""
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
        
    # Check for Rich Header (Microsoft Visual C++ artifact)
    if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER:
        evidence.append("Rich Header found (indicates standard MSVC toolchain)")
        # Rich header is a negative indicator of obfuscation (common in clean files)
        scores.append(-0.2)
    else:
        evidence.append("No Rich Header detected (common in packed or non-MSVC binaries)")
        scores.append(0.3)
        
    rwx_count = 0
    for section in pe.sections:
        characteristics = section.Characteristics
        is_exec = characteristics & IMAGE_SCN_MEM_EXECUTE
        is_write = characteristics & IMAGE_SCN_MEM_WRITE
        if is_exec and is_write:
            rwx_count += 1
            sec_name = section.Name.decode('utf-8', errors='replace').rstrip(chr(0))
            evidence.append(f'RWX section found: {sec_name}')
            
    if rwx_count > 0:
        scores.append(0.7)
        
    for section in pe.sections:
        va_start = section.VirtualAddress
        va_end = va_start + section.Misc_VirtualSize
        if va_start <= ep < va_end:
            section_name = section.Name.decode('utf-8', errors='replace').rstrip(chr(0))
            if section_name not in ('.text', '.code', 'CODE', 'INIT'):
                evidence.append(f'EntryPoint in non-standard section: {section_name}')
                scores.append(0.5)
            break
            
    # Critical integrity failures should return max score immediately
    if any("Invalid DOS magic" in e or "Invalid PE signature" in e for e in evidence):
        return (1.0, evidence)
        
    # High-severity issues should not be averaged down too much
    if any("not within any section bounds" in e for e in evidence):
        return (max(0.8, sum(scores)/len(scores)), evidence)
        
    score = sum(scores) / max(len(scores), 1) if scores else 0.0
    return (max(0.0, min(score, 1.0)), evidence)
