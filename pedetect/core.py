# pedetect/core.py
import hashlib
import datetime
import json
import os
import pefile
from pedetect.heuristics.header import check_header_integrity
from pedetect.heuristics.sections import check_section_anomalies
from pedetect.heuristics.imports import check_import_table
from pedetect.heuristics.entropy import check_entropy
from pedetect.heuristics.signatures import check_ep_signatures
from pedetect.heuristics.strings_ import check_strings

def analyze_file(filepath, weights_path=None, sig_db=None):
    result = {
        'file': {'path': filepath, 'md5': '', 'sha256': '', 'size': 0},
        'heuristics': {},
        'verdict': 'SKELETON',
        'confidence': 0.0,
        'evidence_chain': [],
        'metadata': {'timestamp': datetime.datetime.utcnow().isoformat() + 'Z', 'version': '0.1.0', 'pefile_version': pefile.__version__},
    }
    with open(filepath, 'rb') as fh:
        data = fh.read()
    result['file']['md5'] = hashlib.md5(data).hexdigest()
    result['file']['sha256'] = hashlib.sha256(data).hexdigest()
    result['file']['size'] = len(data)
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError as e:
        result['verdict'] = 'ERROR'
        result['evidence_chain'].append(f'PE parsing failed: {e}')
        return result

    # Load weights from json (with fallback)
    weights_path = weights_path or os.path.join(os.path.dirname(__file__), 'weights.json')
    try:
        with open(weights_path) as f:
            w = json.load(f)
        weights = w.get('heuristics', {})
    except:
        weights = {'header_integrity': 0.8, 'section_anomalies': 0.7, 'import_table': 0.9, 'entropy': 0.7, 'ep_signature': 0.9, 'strings': 0.4}
    # Run heuristics with weights
    heuristic_runner = [
        ('header_integrity', check_header_integrity),
        ('section_anomalies', check_section_anomalies),
        ('import_table', check_import_table),
        ('entropy', check_entropy),
        ('ep_signature', lambda p: check_ep_signatures(p, sig_db)),
        ('strings', check_strings),
    ]
    total_weight = 0.0
    weighted_sum = 0.0
    for name, func in heuristic_runner:
        try:
            score, evidence = func(pe)
        except Exception as e:
            score = 0.0
            evidence = [f'Heuristic {name} error: {str(e)}']
        result['heuristics'][name] = {'score': score, 'evidence': evidence}
        result['evidence_chain'].extend(evidence)
        w = weights.get(name, 0.5)
        total_weight += w
        weighted_sum += score * w
    final_score = weighted_sum / total_weight if total_weight > 0 else 0.0
    final_score = max(0.0, min(1.0, final_score))
    if final_score < 0.3:
        verdict = 'CLEAN'
    elif final_score < 0.6:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'PACKED'
    result['verdict'] = verdict
    result['confidence'] = round(final_score, 4)
    return result