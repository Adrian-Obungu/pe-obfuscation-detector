# pedetect/cli.py
import argparse, os, sys, json
from pedetect.core import analyze_file

def main():
    p = argparse.ArgumentParser(description='PE Binary Obfuscation Detector')
    p.add_argument('target')
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('-o', '--output', choices=['text','json'], default='text')
    p.add_argument('-f', '--file', help='Save output to file')
    p.add_argument('--sigdb', help='Path to signatures.json')
    args = p.parse_args()
    if not os.path.isfile(args.target):
        sys.exit('File not found')
    result = analyze_file(args.target, sig_db=args.sigdb)
    if args.output == 'json':
        out = json.dumps(result, indent=2)
    else:
        out = f"File: {result['file']['path']}\nMD5:  {result['file']['md5']}\nSHA256: {result['file']['sha256']}\nSize: {result['file']['size']} bytes\nVerdict: {result['verdict']} ({result['confidence']:.2%})"
        if args.verbose:
            out += '\n' + '\n'.join(result['evidence_chain'])
    if args.file:
        with open(args.file, 'w') as f:
            f.write(out)
    else:
        print(out)

if __name__ == '__main__':
    main()