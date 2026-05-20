# pedetect/core.py
import hashlib
import datetime
import json
import os
import sys
import pefile
from pedetect.heuristics import (header, sections, imports, entropy as ent_module, signatures, strings_)
from pedetect.config_loader import _load_config

# Load centralized configuration
CONFIG = _load_config()
VERDICT_CFG = CONFIG.get("verdict", {})
CLEAN_THRESHOLD = VERDICT_CFG.get("clean_threshold", 0.3)
SUSPICIOUS_THRESHOLD = VERDICT_CFG.get("suspicious_threshold", 0.6)
MAX_MEMORY_READ = 100 * 1024 * 1024

def analyze_file(filepath, weights_path=None, sig_db=None):
    """Perform a complete forensic analysis of a PE file."""
    result = {
        'file': {'path': filepath, 'md5': '', 'sha256': '', 'size': 0, 'first_64_bytes': ''},
        'heuristics': {},
        'verdict': 'SKELETON',
        'confidence': 0.0,
        'evidence_chain': [],
        'metadata': {
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
            'version': '0.3.0',
            'pefile_version': pefile.__version__
        },
    }

    # Memory‑safe chunked reading
    file_size = os.path.getsize(filepath)
    if file_size > MAX_MEMORY_READ:
        print(f"[WARNING] File exceeds {MAX_MEMORY_READ // (1024*1024)}MB — may cause memory pressure in minimal environments.", file=sys.stderr)
    result['file']['size'] = file_size

    chunk_size = 8192
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    with open(filepath, 'rb') as fh:
        first_64 = fh.read(64)
        result['file']['first_64_bytes'] = first_64.hex()
        fh.seek(0)
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

    # ----- Overlay Detection -----
    expected_end = pe.OPTIONAL_HEADER.SizeOfHeaders
    for sec in pe.sections:
        section_end = sec.PointerToRawData + sec.SizeOfRawData
        if section_end > expected_end:
            expected_end = section_end
    overlay_size = file_size - expected_end
    overlay_entropy_val = 0.0
    if overlay_size > 0:
        with open(filepath, 'rb') as fh:
            fh.seek(expected_end)
            overlay_data = fh.read(min(overlay_size, 1024 * 1024))
        overlay_entropy_val = ent_module.compute_entropy(overlay_data)
        if overlay_size > 512:
            result['evidence_chain'].append(
                f'Overlay detected: {overlay_size} bytes past EOF (entropy: {overlay_entropy_val:.2f})'
            )
        else:
            result['evidence_chain'].append(f'Small overlay detected: {overlay_size} bytes past EOF')
    result['overlay'] = {'size': overlay_size, 'entropy': round(overlay_entropy_val, 2)}

    # ----- Load weight config -----
    weights_path = weights_path or os.path.join(os.path.dirname(__file__), 'weights.json')
    try:
        with open(weights_path) as f:
            w = json.load(f)
        weights = w.get('heuristics', {})
    except:
        weights = {
            'header_integrity': 0.8, 'section_anomalies': 0.7, 'import_table': 0.9,
            'entropy': 0.7, 'ep_signature': 0.9, 'strings': 0.4
        }

    # Validate weights
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

    # ----- Plugin discovery -----
    import importlib.util, glob
    plugin_dir = os.path.join(os.path.dirname(__file__), 'plugins')
    plugins = []
    if os.path.isdir(plugin_dir):
        for plugin_file in sorted(glob.glob(os.path.join(plugin_dir, '*.py'))):
            if os.path.basename(plugin_file).startswith('_'):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f'pedetect_plugin_{os.path.basename(plugin_file)[:-3]}', plugin_file
                )
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, 'analyze') and callable(mod.analyze):
                    plugin_name = os.path.basename(plugin_file)[:-3]
                    plugins.append((f'plugin:{plugin_name}', mod.analyze))
            except Exception as e:
                print(f"[WARNING] Failed to load plugin {plugin_file}: {e}", file=sys.stderr)

    # ----- Run heuristics + plugins -----
    heuristic_runner = [
        ('header_integrity', header.check_header_integrity),
        ('section_anomalies', sections.check_section_anomalies),
        ('import_table', imports.check_import_table),
        ('entropy', ent_module.check_entropy),
        ('ep_signature', lambda p: signatures.check_ep_signatures(p, sig_db)),
        ('strings', strings_.check_strings),
    ] + plugins

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
        # Contextual anomaly detection
        is_anomaly = False
        anomaly_reason = ""
        sec_chars = sec.Characteristics
        is_rwx = (sec_chars & 0x20000000) and (sec_chars & 0x40000000) and (sec_chars & 0x80000000)
        if sec_ent > 7.0:
            if sec_name.lower() in ('.text', '.code', 'code'):
                is_anomaly = True
                anomaly_reason = "High entropy in executable section — likely encrypted payload"
            elif sec_name.lower() in ('.rsrc', '.rdata'):
                is_anomaly = True
                anomaly_reason = "High entropy in resource/data section — possible hidden payload"
            else:
                is_anomaly = True
                anomaly_reason = "High entropy detected — potential obfuscation"
        if is_rwx:
            is_anomaly = True
            anomaly_reason = (anomaly_reason + "; " if anomaly_reason else "") + "RWX permissions — self-modifying code"
        section_entropy.append({
            'name': sec_name,
            'entropy': round(sec_ent, 2),
            'anomaly': is_anomaly,
            'anomaly_reason': anomaly_reason,
            'characteristics': hex(sec_chars)
        })
    if overlay_size > 0:
        ov_anomaly = overlay_entropy_val > 7.0
        section_entropy.append({
            'name': f'[OVERLAY {overlay_size}B]',
            'entropy': round(overlay_entropy_val, 2),
            'anomaly': ov_anomaly,
            'anomaly_reason': 'High entropy overlay — possible appended payload' if ov_anomaly else '',
            'characteristics': 'N/A'
        })
    result['section_entropy'] = section_entropy
    result['section_names'] = [s['name'] for s in section_entropy]
    result['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # Final scoring with zero‑weight guard
    if total_weight == 0:
        print("[WARNING] All heuristic weights are zero — check weights.json. Defaulting to CLEAN.", file=sys.stderr)
        final_score = 0.0
    else:
        final_score = weighted_sum / total_weight
    final_score = max(0.0, min(1.0, final_score))

    if final_score < CLEAN_THRESHOLD:
        verdict = 'CLEAN'
    elif final_score < SUSPICIOUS_THRESHOLD:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'PACKED'
    result['verdict'] = verdict
    result['confidence'] = round(final_score, 4)
    result['total_weight'] = round(total_weight, 4)
    result['weighted_sum'] = round(weighted_sum, 4)
    return result


def format_yara_rule(result: dict) -> str:
    """Generate a YARA rule based on the analysis evidence."""
    sha256 = result['file']['sha256']
    short_hash = sha256[:8]
    verdict = result['verdict'].lower()
    rule_name = f"pedetect_{verdict}_{short_hash}"

    ep_bytes = result['file']['first_64_bytes']
    ep_hex = " ".join(ep_bytes[i:i+2] for i in range(0, len(ep_bytes), 2))

    section_names = result.get('section_names', [])
    section_strings = "\n        ".join(
        [f'$s{i} = "{name}" wide ascii' for i, name in enumerate(section_names)]
    )

    timestamp = result['metadata']['timestamp']
    confidence = result['confidence']

    rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated YARA rule from pedetect analysis"
        author = "pedetect v0.3.0"
        md5 = "{result['file']['md5']}"
        sha256 = "{sha256}"
        verdict = "{result['verdict']}"
        confidence = "{confidence}"
        timestamp = "{timestamp}"

    strings:
        $ep_bytes = {{ {ep_hex} }}
        {section_strings}

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $ep_bytes at 0 and
        (any of ($s*)) and
        ({confidence} > 0.7)
}}"""
    return rule


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
    lines.append('**Formula:** confidence = Σ(Score × Weight) / Σ(Weights)')
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

    if sections:
        entropies = [s['entropy'] for s in sections if not s['name'].startswith('[OVERLAY')]
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
        elif len(entropies) == 1:
            lines.append('  Entropy Variance: (need at least 2 sections)')
            lines.append('')

    if sections:
        for sec in sections:
            ent = sec['entropy']
            is_overlay = sec['name'].startswith('[OVERLAY')
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
            if is_overlay:
                label += ' (overlay)'
            lines.append(f'  {sec["name"]:<15} [{bar:<40}] {ent:.2f} {label}')
    else:
        lines.append('  (No section data available)')
    lines.append('')
    return '\n'.join(lines)


def format_verdict_explanation(result):
    lines = ['## Verdict Explanation', '']
    verdict = result['verdict']
    confidence = result['confidence']
    heuristics = result['heuristics']
    active = {name: h for name, h in heuristics.items() if h['score'] > 0}

    if verdict == 'ERROR':
        lines.append('The file could not be parsed as a valid PE.')
        return '\n'.join(lines)
    if verdict == 'CLEAN':
        lines.append(f'This file appears to be a legitimate, unobfuscated PE executable (confidence: {confidence:.1%}).')
        return '\n'.join(lines)
    if verdict == 'PACKED':
        lines.append(f'**This file is highly likely to be packed, crypted, or obfuscated** (confidence: {confidence:.1%}).')
    else:
        lines.append(f'This file shows moderate signs of obfuscation (confidence: {confidence:.1%}).')

    lines.append('')
    lines.append('### Key Findings')

    imp = heuristics.get('import_table', {})
    if imp.get('score', 0) >= 0.9:
        if any('stripped' in e.lower() for e in imp.get('evidence', [])):
            lines.append('- **Import table is stripped or missing.**')
    ent = heuristics.get('entropy', {})
    if ent.get('score', 0) >= 0.5:
        if any('High entropy' in e for e in ent.get('evidence', [])):
            lines.append('- **High entropy detected** in one or more sections.')
        if any('Crypter pattern' in e for e in ent.get('evidence', [])):
            lines.append('- **Crypter pattern detected.**')
        if any('uniformly packed' in e.lower() for e in ent.get('evidence', [])):
            lines.append('- **Uniform packing detected.**')
    sig = heuristics.get('ep_signature', {})
    if sig.get('score', 0) >= 0.8 and sig.get('evidence'):
        lines.append(f'- **Known packer signature matched:** {sig["evidence"][0]}.')
    sec = heuristics.get('section_anomalies', {})
    if sec.get('score', 0) >= 0.5:
        names = [e.split(': ')[-1] for e in sec.get('evidence', []) if 'Suspicious section name' in e]
        if names:
            lines.append(f'- **Non‑standard section names:** {", ".join(names)}.')
    hdr = heuristics.get('header_integrity', {})
    if hdr.get('score', 0) >= 0.5:
        if any('RWX section' in e for e in hdr.get('evidence', [])):
            lines.append('- **RWX sections found.**')
    overlay = result.get('overlay', {})
    if overlay.get('size', 0) > 512:
        lines.append(f'- **Overlay data detected:** {overlay["size"]} bytes past EOF (entropy: {overlay["entropy"]:.2f}).')

    lines.append('')
    lines.append('### Confidence Breakdown')
    top = sorted(active.items(), key=lambda x: x[1]['score'] * x[1].get('weight', 0.5), reverse=True)
    for name, h in top[:3]:
        display = name.replace('_', ' ').title()
        contribution = h['score'] * h.get('weight', 0.5)
        lines.append(f'- **{display}:** contributed {contribution:.3f} (raw {h["score"]:.2f} × weight {h.get("weight", 0.5)})')
    return '\n'.join(lines)


def format_dashboard(result):
    """Rich‑based interactive dashboard for modern terminals."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        from rich.layout import Layout
        from rich.live import Live
        import time
    except ImportError:
        print('[ERROR] "rich" library required for dashboard. Install with: pip install rich')
        return None

    console = Console()
    verdict_color = {'CLEAN': 'green', 'SUSPICIOUS': 'yellow', 'PACKED': 'red', 'ERROR': 'dim'}

    with Live(console=console, screen=True, refresh_per_second=4) as live:
        time.sleep(0.1)
        layout = Layout()
        layout.split(
            Layout(name='header', size=3),
            Layout(name='body'),
            Layout(name='footer', size=3)
        )
        layout['body'].split_row(
            Layout(name='left', ratio=3),
            Layout(name='right', ratio=2),
        )

        header_text = Text("PE Binary Obfuscation Detector  v0.3.0", style='bold white')
        layout['header'].update(Panel(header_text, border_style='blue'))

        table = Table(title='Weighted Scoring', title_style='bold cyan', expand=True)
        table.add_column('Heuristic', style='dim')
        table.add_column('Score', justify='right')
        table.add_column('Weight', justify='right')
        table.add_column('Contribution', justify='right', style='bold')
        for name, info in result['heuristics'].items():
            score = info['score']
            weight = info.get('weight', 0.5)
            contribution = score * weight
            display_name = name.replace('_', ' ').title()
            contrib_color = 'red' if contribution > 0.7 else ('yellow' if contribution > 0.3 else 'green')
            table.add_row(display_name, f'{score:.2f}', f'{weight}', f'[{contrib_color}]{contribution:.3f}[/{contrib_color}]')
        table.add_section()
        table.add_row('[bold]TOTAL[/bold]', '', f'[bold]{result["total_weight"]}[/bold]', f'[bold]{result["confidence"]:.4f}[/bold]')
        layout['left'].update(Panel(table, title='Scoring Breakdown', border_style='blue'))

        right_content = Table.grid(padding=(0, 2))
        right_content.add_column()
        vc = verdict_color.get(result['verdict'], 'white')
        right_content.add_row(Panel(
            Text(f"{result['verdict']}\n{result['confidence']:.1%}", style=f'bold {vc}', justify='center'),
            title='VERDICT', border_style=vc
        ))
        right_content.add_row('')
        ent_table = Table(title='Section Entropy', title_style='bold cyan')
        ent_table.add_column('Section')
        ent_table.add_column('Entropy', justify='right')
        ent_table.add_column('Bar')
        for sec in result.get('section_entropy', []):
            ent_val = sec['entropy']
            bar = '█' * int(ent_val / 8 * 30)
            color = 'red' if ent_val > 7 else ('yellow' if ent_val > 5 else 'green')
            ent_table.add_row(sec['name'], f'{ent_val:.2f}', f'[{color}]{bar}[/{color}]')
        right_content.add_row(ent_table)
        if result.get('overlay', {}).get('size', 0) > 0:
            right_content.add_row(f"[dim]Overlay: {result['overlay']['size']} bytes (entropy {result['overlay']['entropy']:.2f})[/dim]")
        layout['right'].update(Panel(right_content, border_style='blue'))

        footer_text = Text(
            f"File: {result['file']['path']}  |  Size: {result['file']['size']} bytes  |  {result['metadata']['timestamp']}",
            style='dim'
        )
        layout['footer'].update(Panel(footer_text, border_style='blue'))
        live.update(layout)
        time.sleep(5)
    return 'Dashboard rendered.'


def format_html_report(result):
    """Generate a standalone interactive HTML report."""
    import json as _json
    data_json = _json.dumps(result, indent=2)
    verdict_color = {'CLEAN': '#27ae60', 'SUSPICIOUS': '#f39c12', 'PACKED': '#e74c3c', 'ERROR': '#95a5a6'}
    color = verdict_color.get(result['verdict'], '#333')

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PE Obfuscation Detection Report — {result['file']['path']}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
  .card {{ background: #16213e; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
  h2 {{ margin-top: 0; color: #e94560; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #0f3460; }}
  th {{ color: #a0a0b0; font-weight: 600; text-transform: uppercase; font-size: 0.8em; }}
  .verdict {{ font-size: 1.8em; font-weight: 700; padding: 8px 0; }}
  .evidence {{ list-style: none; padding: 0; }}
  .evidence li {{ padding: 6px 0; border-bottom: 1px solid #0f3460; font-family: monospace; font-size: 0.9em; }}
  .evidence li::before {{ content: "▸ "; color: #e94560; }}
</style>
</head>
<body>
<div class="card">
  <h2>PE Binary Obfuscation Detector</h2>
  <p style="color:#a0a0b0;margin-top:-8px;">v{result['metadata']['version']} — {result['metadata']['timestamp']}</p>
  <table>
    <tr><th>File</th><td><code>{result['file']['path']}</code></td></tr>
    <tr><th>MD5</th><td><code>{result['file']['md5']}</code></td></tr>
    <tr><th>SHA256</th><td><code style="word-break:break-all;">{result['file']['sha256']}</code></td></tr>
    <tr><th>Size</th><td>{result['file']['size']:,} bytes</td></tr>
    <tr><th>Verdict</th><td class="verdict" style="color:{color}">{result['verdict']} <span style="font-size:0.6em;">({result['confidence']:.1%})</span></td></tr>
  </table>
</div>
<div class="card">
  <h2>Evidence Chain</h2>
  <ul class="evidence">
    {''.join(f'<li>{e}</li>' for e in result['evidence_chain'])}
  </ul>
</div>
<div class="card">
  <h2>Raw JSON</h2>
  <pre style="background:#0a0a1a;padding:12px;border-radius:6px;overflow-x:auto;font-size:0.8em;max-height:400px;"><code>{data_json}</code></pre>
</div>
</body>
</html>'''
