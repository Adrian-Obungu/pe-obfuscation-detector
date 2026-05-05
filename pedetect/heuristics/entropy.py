# pedetect/heuristics/entropy.py
"""Heuristic 4: Entropy analysis for packing and encryption detection."""
import math
from collections import Counter
import pefile
from pedetect.config_loader import _load_config

CONFIG = _load_config().get("entropy", {})
HIGH_ENTROPY_THRESHOLD = CONFIG.get("high_entropy_threshold", 7.0)
WHOLE_FILE_THRESHOLD = CONFIG.get("whole_file_threshold", 6.8)
LOW_ENTROPY_THRESHOLD = CONFIG.get("low_entropy_threshold", 5.5)
HIGH_RSRC_THRESHOLD = CONFIG.get("high_rsrc_threshold", 7.0)
LOW_VARIANCE_THRESHOLD = CONFIG.get("low_variance_threshold", 0.3)
CHUNK_SIZE = CONFIG.get("chunk_size", 65536)

def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy for a byte sequence."""
    if not data:
        return 0.0
    total = len(data)
    frequencies = Counter(data)
    entropy = 0.0
    for count in frequencies.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy

def compute_entropy_chunked(filepath: str) -> float:
    """Compute Shannon entropy using chunked reading for large files."""
    frequencies = Counter()
    total_bytes = 0
    try:
        with open(filepath, 'rb') as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                frequencies.update(chunk)
                total_bytes += len(chunk)
    except Exception:
        return 0.0
    
    if total_bytes == 0:
        return 0.0
    
    entropy = 0.0
    for count in frequencies.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    return entropy

def check_entropy(pe: pefile.PE) -> tuple:
    """Check per-section and whole-file entropy for packing indicators."""
    evidence = []
    scores = []
    section_entropies = []
    for section in pe.sections:
        sec_entropy = section.get_entropy()
        name = section.Name.decode('utf-8', errors='replace').rstrip(chr(0)).strip()
        section_entropies.append(sec_entropy)
        if sec_entropy > HIGH_ENTROPY_THRESHOLD:
            evidence.append(
                f'High entropy section: {name} ({sec_entropy:.2f}) — '
                f'above threshold {HIGH_ENTROPY_THRESHOLD}'
            )
            excess = min(sec_entropy - HIGH_ENTROPY_THRESHOLD, 0.8)
            scores.append(0.5 + excess * 0.5)
        elif sec_entropy > (HIGH_ENTROPY_THRESHOLD - 0.5):
            evidence.append(f'Medium-high entropy: {name} ({sec_entropy:.2f})')
            scores.append(0.3)
    
    try:
        whole_entropy = compute_entropy_chunked(pe.filename)
        if whole_entropy > WHOLE_FILE_THRESHOLD:
            evidence.append(
                f'Whole-file entropy high: {whole_entropy:.2f} — '
                f'above threshold {WHOLE_FILE_THRESHOLD}'
            )
            scores.append(0.7)
    except (AttributeError, FileNotFoundError):
        pass
        
    if len(section_entropies) >= 2:
        mean = sum(section_entropies) / len(section_entropies)
        variance = sum((e - mean) ** 2 for e in section_entropies) / len(section_entropies)
        if variance < LOW_VARIANCE_THRESHOLD and all(e > HIGH_ENTROPY_THRESHOLD for e in section_entropies):
            evidence.append(f'Low entropy variance ({variance:.3f}) across all sections — uniformly packed')
            scores.append(0.9)
            
    rsrc_entropy = None
    code_entropy = None
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip(chr(0)).strip().lower()
        if 'rsrc' in name:
            rsrc_entropy = section.get_entropy()
        if name in ('.text', '.code', 'code'):
            code_entropy = section.get_entropy()
            
    if rsrc_entropy and code_entropy:
        if rsrc_entropy > HIGH_RSRC_THRESHOLD and code_entropy < LOW_ENTROPY_THRESHOLD:
            evidence.append(
                f'Crypter pattern detected: low-entropy code section '
                f'({code_entropy:.2f}) + high-entropy resource ({rsrc_entropy:.2f})'
            )
            scores.append(0.85)
            
    score = sum(scores) / max(len(scores), 1) if scores else 0.0
    return (min(score, 1.0), evidence)
