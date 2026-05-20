# pedetect/cli.py
import argparse, os, sys, json
from pedetect.core import (
    analyze_file,
    format_scoring_table,
    format_heatmap,
    format_verdict_explanation,
    format_dashboard,
    format_html_report,
    format_yara_rule
)

def is_safe_path(path: str) -> bool:
    """Check if the path is within the current working directory."""
    cwd = os.getcwd()
    abs_path = os.path.abspath(path)
    return abs_path.startswith(cwd)

def main():
    p = argparse.ArgumentParser(description='PE Binary Obfuscation Detector')
    p.add_argument('target')
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('-vv', '--very-verbose', action='store_true', help='Show weighted scoring table')
    p.add_argument('--heatmap', action='store_true', help='Show visual heatmap of scores and entropy')
    p.add_argument('--explain', action='store_true', help='Show human‑readable verdict explanation')
    p.add_argument('--html', metavar='OUTPUT', nargs='?', const='report.html',
                   help='Generate standalone interactive HTML report (optionally specify output path)')
    p.add_argument('--dashboard', action='store_true', help='Show rich terminal dashboard')
    p.add_argument('--tui', action='store_true', help='Launch interactive TUI dashboard (Textual)')
    p.add_argument('--yara', action='store_true', help='Export evidence as YARA rule')
    p.add_argument('-o', '--output', choices=['text','json'], default='text')
    p.add_argument('-f', '--file', help='Save output to file')
    p.add_argument('--sigdb', help='Path to signatures.json')
    args = p.parse_args()

    if not os.path.isfile(args.target):
        sys.exit('File not found')

    if args.file and not is_safe_path(args.file):
        print(f"[ERROR] Output path '{args.file}' is outside the allowed workspace.", file=sys.stderr)
        sys.exit(1)

    result = analyze_file(args.target, sig_db=args.sigdb)

    # TUI mode (interactive Textual dashboard)
    if args.tui:
        try:
            from pedetect.tui import launch_tui
            launch_tui(result)
        except ImportError:
            print('[ERROR] "textual" library required for TUI. Install with: pip install textual', file=sys.stderr)
            sys.exit(1)
        return

    if args.dashboard:
        format_dashboard(result)
        return

    # HTML report generation (standalone with D3.js and spectral mapping)
    if args.html:
        from pedetect.html_report import generate_full_html_report
        html_output = generate_full_html_report(result)
        html_path = args.html if args.html != 'report.html' else 'report.html'
        if args.file:
            html_path = args.file
        with open(html_path, 'w') as f:
            f.write(html_output)
        print(f"[OK] Interactive HTML report saved to: {html_path}")
        return

    if args.output == 'json':
        out = json.dumps(result, indent=2)
    else:
        out = f"File: {result['file']['path']}\nMD5:  {result['file']['md5']}\nSHA256: {result['file']['sha256']}\nSize: {result['file']['size']} bytes\nVerdict: {result['verdict']} ({result['confidence']:.2%})"
        if args.verbose:
            out += '\n' + '\n'.join(result['evidence_chain'])
        if args.very_verbose:
            out += '\n\n' + format_scoring_table(result)
        if args.heatmap:
            out += '\n\n' + format_heatmap(result)
        if args.explain:
            out += '\n\n' + format_verdict_explanation(result)

    if args.yara:
        yara_rule = format_yara_rule(result)
        if args.file:
            yara_path = args.file + ".yar"
            with open(yara_path, 'w') as yf:
                yf.write(yara_rule)
            print(f"YARA rule saved to {yara_path}")
        else:
            out += '\n\n--- YARA RULE ---\n' + yara_rule

    if args.file:
        with open(args.file, 'w') as f:
            f.write(out)
    else:
        print(out)

if __name__ == '__main__':
    main()
