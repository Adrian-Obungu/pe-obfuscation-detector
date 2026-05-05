# pedetect/heuristics/signatures.py
"""Heuristic 5: Entry Point byte signature matching."""
import json
import os
import sys
import pefile
from pedetect.config_loader import _load_config

# Attempt to use the 'regex' library for timeout support, fall back to 're'
try:
    import regex as re
    HAS_REGEX_LIB = True
except ImportError:
    import re
    HAS_REGEX_LIB = False

CONFIG = _load_config().get("signatures", {})
DEFAULT_SIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'signatures.json')
DEFAULT_MIN_EP_LENGTH = CONFIG.get("default_min_ep_length", 4)
MAX_EP_BYTES = CONFIG.get("max_ep_bytes", 256)

class EPSignatureMatcher:
    def __init__(self, sig_file=None):
        self.sig_file = sig_file or DEFAULT_SIG_PATH
        self.signatures = self._load()

    def _load(self):
        if not os.path.exists(self.sig_file):
            print(f"[WARNING] Signature file not found at {self.sig_file}", file=sys.stderr)
            return []
        try:
            with open(self.sig_file, 'r') as f:
                data = json.load(f)
            return data.get('signatures', [])
        except (json.JSONDecodeError, IOError) as e:
            print(f"[ERROR] Failed to load signatures: {e}", file=sys.stderr)
            return []

    @staticmethod
    def _bytes_to_hex(data):
        return ''.join(f'{b:02X}' for b in data)

    def match(self, pe):
        evidence = []
        scores = []
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = None
        ep_offset = 0
        for section in pe.sections:
            va_start = section.VirtualAddress
            va_end = va_start + section.Misc_VirtualSize
            if va_start <= ep_rva < va_end:
                ep_section = section
                ep_offset = ep_rva - va_start
                break
        if not ep_section:
            evidence.append('Cannot locate entry point in any section')
            return (0.0, evidence)

        section_data = ep_section.get_data()
        if not section_data:
            return (0.0, [])

        ep_window = section_data[ep_offset:ep_offset + MAX_EP_BYTES]
        if len(ep_window) < DEFAULT_MIN_EP_LENGTH:
            return (0.0, [])

        ep_hex = self._bytes_to_hex(ep_window)
        matches = []
        for sig in self.signatures:
            min_len = sig.get('min_ep_length', DEFAULT_MIN_EP_LENGTH)
            if len(ep_window) < min_len:
                continue
            pattern = sig['pattern'].replace(' ', '')
            regex_str = pattern.replace('??', '[0-9A-F]{2}')
            
            try:
                # Try anchored match at exact EP first
                if HAS_REGEX_LIB:
                    match_result = re.search(f'^{regex_str}', ep_hex, timeout=1)
                else:
                    match_result = re.search(f'^{regex_str}', ep_hex)
                
                # If not at EP, try anywhere in the window
                if not match_result:
                    if HAS_REGEX_LIB:
                        match_result = re.search(regex_str, ep_hex, timeout=1)
                    else:
                        match_result = re.search(regex_str, ep_hex)
                    if match_result:
                        evidence.append(
                            f"EP offset match for {sig['name']}: pattern found "
                            f"at byte offset {match_result.start() // 2}"
                        )
            except TimeoutError:
                print(f"[WARNING] Regex timeout for signature {sig['name']}", file=sys.stderr)
                continue
            except Exception as e:
                print(f"[ERROR] Regex error for signature {sig['name']}: {e}", file=sys.stderr)
                continue

            if match_result:
                matches.append({
                    'name': sig['name'],
                    'confidence': sig.get('confidence', 0.8),
                    'description': sig.get('description', '')
                })

        if matches:
            best = max(matches, key=lambda m: m['confidence'])
            evidence.append(
                f"EP signature match: {best['name']} — {best['description']} "
                f"(confidence: {best['confidence']})"
            )
            scores.append(best['confidence'])
            for match in matches:
                if match['name'] != best['name']:
                    evidence.append(
                        f"  Additional match: {match['name']} "
                        f"(confidence: {match['confidence']})"
                    )
        score = sum(scores) / max(len(scores), 1) if scores else 0.0
        return (min(score, 1.0), evidence)

def check_ep_signatures(pe, sig_file=None):
    matcher = EPSignatureMatcher(sig_file)
    return matcher.match(pe)
