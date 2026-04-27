# pedetect/heuristics/signatures.py
"""Heuristic 5: Entry Point byte signature matching."""
import json
import os
import re
import pefile

DEFAULT_SIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'signatures.json')

class EPSignatureMatcher:
    def __init__(self, sig_file=None):
        self.sig_file = sig_file or DEFAULT_SIG_PATH
        self.signatures = self._load()

    def _load(self):
        if not os.path.exists(self.sig_file):
            return []
        try:
            with open(self.sig_file, 'r') as f:
                data = json.load(f)
            return data.get('signatures', [])
        except (json.JSONDecodeError, IOError):
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
        ep_bytes = section_data[ep_offset:ep_offset + 64]
        if len(ep_bytes) < 4:
            return (0.0, [])
        ep_hex = self._bytes_to_hex(ep_bytes)
        matches = []
        for sig in self.signatures:
            min_len = sig.get('min_ep_length', 0)
            if len(ep_bytes) < min_len:
                continue
            pattern = sig['pattern'].replace(' ', '')
            regex_str = pattern.replace('??', '[0-9A-F]{2}')
            regex = re.compile(f'^{regex_str}')
            if regex.match(ep_hex):
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