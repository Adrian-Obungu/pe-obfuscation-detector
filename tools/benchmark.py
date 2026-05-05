import os
import csv
import json
import subprocess
import argparse
from typing import List, Dict

def run_pedetect(filepath: str) -> Dict:
    """Run pedetect and return the JSON result."""
    try:
        result = subprocess.run(
            ['pedetect', filepath, '-o', 'json'],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"verdict": "ERROR", "confidence": 0, "error": str(e)}

def run_die(filepath: str) -> str:
    """Run Detect It Easy (diec) if available."""
    try:
        result = subprocess.run(
            ['diec', '--json', filepath],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            # Simplified DiE verdict extraction
            if data.get('detects'):
                return "PACKED"
            return "CLEAN"
        return "N/A"
    except FileNotFoundError:
        return "N/A"

def main():
    parser = argparse.ArgumentParser(description="Benchmark pedetect against real-world samples.")
    parser.add_argument("--dir", required=True, help="Directory of PE files")
    parser.add_argument("--output", default="benchmark_results.csv", help="Output CSV file")
    args = parser.parse_args()

    results = []
    files = [os.path.join(args.dir, f) for f in os.listdir(args.dir) if os.path.isfile(os.path.join(args.dir, f))]

    print(f"Benchmarking {len(files)} files...")

    for f in files:
        print(f"Analyzing {os.path.basename(f)}...")
        ped_res = run_pedetect(f)
        die_verdict = run_die(f)
        
        results.append({
            "filename": os.path.basename(f),
            "md5": ped_res.get("file", {}).get("md5", ""),
            "pedetect_verdict": ped_res.get("verdict", "ERROR"),
            "pedetect_confidence": ped_res.get("confidence", 0),
            "die_verdict": die_verdict
        })

    with open(args.output, 'w', newline='') as csvfile:
        fieldnames = ["filename", "md5", "pedetect_verdict", "pedetect_confidence", "die_verdict"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"Benchmark complete. Results saved to {args.output}")

if __name__ == "__main__":
    main()
