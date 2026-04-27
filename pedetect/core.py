# pedetect/core.py
import hashlib
import datetime
import json
import os
import sys
import pefile
from pedetect.heuristics import (header, sections, imports, entropy, signatures, strings_)

# Maximum file size for full in‑memory read (100 MB)
MAX_MEMORY_READ = 100 * 1024 * 1024

def analyze_file(filepath, weights_path=None, sig_db=None):
    result = {
        'file': {'path': filepath, 'md5': '', 'sha256': '', 'size': 0},
        'heuristics': {},
        'verdict': 'SKELETON',
        'confidence': 0.0,
        'evidence_chain': [],
        'metadata': {'timestamp': datetime.datetime.utcnow().isoformat() + 'Z', 'version': '0.1.0', 'pefile_version': pefile.__version__},
    }

    # Memory‑safe file reading: warn on large files
    file_size = os.path.getsize(filepath)
    if file_size > MAX_MEMORY_READ:
        print(f"[WARNING] File exceeds {MAX_MEMORY_READ // (1024*1024)}MB — may cause memory pressure in minimal environments.", file=sys.stderr)
    result['file']['size'] = file_size

    # Compute hashes using chunked reading for large files
    chunk_size = 8192
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    with open(filepath, 'rb') as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    result['file']['md5'] = md5_hash.hexdigest()
    result['file']['sha256'] = sha256_hash.hexdigest()

    # Parse PE
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError as e:
        result['verdict'] = 'ERROR'
        result['evidence_chain'].append(f'PE parsing failed: {e}')
        return result

    # Load weight config
    weights_path = weights_path or os.path.join(os.path.dirname(__file__), 'weights.json')
    try:
        with open(weights_path) as f:
            w = json.load(f)
        weights = w.get('heuristics', {})
    except:
        weights = {'header_integrity': 0.8, 'section_anomalies': 0.7, 'import_table': 0.9, 'entropy': 0.7, 'ep_signature': 0.9, 'strings': 0.4}

    # Validate weights: clamp to [0.0, 2.0], flag anomalies
    validated_weights = {}
    for k, v in weights.items():
        if not isinstance(v, (int, float)) or v < 0:
            print(f"[WARNING] Invalid weight for '{k}': {v}. Using 0.5.", file=sys.stderr)
            validated_weights[k] = 0.5
        elif v > 2.0:
            print(f"[WARNING] Weight for '{k}' clamped from {v} to 2.0.", file=sys.stderr)
            validated_weights[k] = 2.0
        else:
            validated_weights[k] = v
    weights = validated_weights

    # Run heuristics
    heuristic_runner = [
        ('header_integrity', header.check_header_integrity),
        ('section_anomalies', sections.check_section_anomalies),
        ('import_table', imports.check_import_table),
        ('entropy', entropy.check_entropy),
        ('ep_signature', lambda p: signatures.check_ep_signatures(p, sig_db)),
        ('strings', strings_.check_strings),
    ]
    total_weight = 0.0
    weighted_sum = 0.0
    for name, func in heuristic_runner:
        try:
            score, evidence = func(pe)
        except Exception as e:
            score = 0.0
            evidence = [f'Heuristic {name} error: {str(e)}']
        w_val = weights.get(name, 0.5)
        result['heuristics'][name] = {'score': score, 'weight': w_val, 'evidence': evidence}
        result['evidence_chain'].extend(evidence)
        total_weight += w_val
        weighted_sum += score * w_val

    # Collect per‑section entropy for heatmap
    section_entropy = []
    for sec in pe.sections:
        sec_name = sec.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
        sec_ent = sec.get_entropy()
        section_entropy.append({'name': sec_name, 'entropy': round(sec_ent, 2)})
    result['section_entropy'] = section_entropy

    # Final scoring with zero‑weight guard
    if total_weight == 0:
        print("[WARNING] All heuristic weights are zero — check weights.json. Defaulting to CLEAN.", file=sys.stderr)
        final_score = 0.0
    else:
        final_score = weighted_sum / total_weight
    final_score = max(0.0, min(1.0, final_score))

    if final_score < 0.3:
        verdict = 'CLEAN'
    elif final_score < 0.6:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'PACKED'
    result['verdict'] = verdict
    result['confidence'] = round(final_score, 4)
    result['total_weight'] = round(total_weight, 4)
    result['weighted_sum'] = round(weighted_sum, 4)
    return result


def format_scoring_table(result):
    lines = []
    lines.append('## Weighted Scoring Table')
    lines.append('')
    lines.append('| Heuristic | Raw Score | Weight | Contribution |')
    lines.append('|:----------|:---------:|:------:|:------------:|')
    for name, h in result['heuristics'].items():
        score = h['score']
        weight = h.get('weight', 0.5)
        contribution = score * weight
        name_display = name.replace('_', ' ').title()
        lines.append(f'| {name_display} | {score:.2f} | {weight} | {contribution:.3f} |')
    lines.append('')
    tw = result.get('total_weight', 1)
    lines.append(f'| **Total** |  | **{tw}** | **{result["confidence"]:.4f}** |')
    lines.append('')
    lines.append(f'**Formula:** confidence = \u03a3(Score \u00d7 Weight) / \u03a3(Weights)')
    return '\n'.join(lines)


def format_heatmap(result):
    lines = []
    lines.append('## Visual Heatmap')
    lines.append('')
    lines.append('### Score Contribution Bars (filled = % of max possible)')
    lines.append('')
    bar_width = 36
    for name, h in result['heuristics'].items():
        score = h['score']
        weight = h.get('weight', 0.5)
        contribution = score * weight
        max_contrib = weight
        ratio = contribution / max_contrib if max_contrib > 0 else 0
        filled = int(ratio * bar_width)
        bar = '\u2588' * filled + '\u2591' * (bar_width - filled)
        name_display = name.replace('_', ' ').title()
        lines.append(f'  {name_display:<20} [{bar}] {contribution:.3f}/{max_contrib}')
    lines.append('')
    lines.append('### Entropy Heatmap (per section)')
    lines.append('')
    lines.append('  Scale: \u2591 0-3  \u2592 3-5  \u2593 5-7  \u2588 7-8')
    lines.append('')
    sections = result.get('section_entropy', [])

    # Add entropy variance summary (Fix 7)
    if sections:
        entropies = [s['entropy'] for s in sections]
        if len(entropies) >= 2:
            mean = sum(entropies) / len(entropies)
            variance = sum((e - mean) ** 2 for e in entropies) / len(entropies)
            if variance < 0.1:
                var_label = 'CRITICAL — uniformly packed'
            elif variance < 1.0:
                var_label = 'HIGH — likely packed'
            elif variance < 3.0:
                var_label = 'MEDIUM — mixed content'
            else:
                var_label = 'NORMAL — varied content'
            lines.append(f'  Entropy Variance: {variance:.4f} ({var_label})')
            lines.append('')
        else:
            lines.append('  Entropy Variance: (need at least 2 sections)')
            lines.append('')

    if sections:
        for sec in sections:
            ent = sec['entropy']
            if ent < 3:
                char = '\u2591'
            elif ent < 5:
                char = '\u2592'
            elif ent < 7:
                char = '\u2593'
            else:
                char = '\u2588'
            filled_blocks = int(ent / 8 * 40)
            bar = char * filled_blocks
            label = 'HIGH' if ent > 7 else ('MED' if ent > 5 else ('LOW' if ent > 3 else 'NONE'))
            lines.append(f'  {sec["name"]:<10} [{bar:<40}] {ent:.2f} {label}')
    else:
        lines.append('  (No section data available)')
    lines.append('')
    return '\n'.join(lines)