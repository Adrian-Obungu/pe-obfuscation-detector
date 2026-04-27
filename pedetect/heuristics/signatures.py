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
        if not section_data:
            return (0.0, [])

        # Read up to 256 bytes from EP (or until end of section)
        ep_window = section_data[ep_offset:ep_offset + 256]
        if len(ep_window) < 4:
            return (0.0, [])

        ep_hex = self._bytes_to_hex(ep_window)
        matches = []
        for sig in self.signatures:
            min_len = sig.get('min_ep_length', 0)
            if len(ep_window) < min_len:
                continue
            pattern = sig['pattern'].replace(' ', '')
            # Convert wildcard pattern to regex
            regex_str = pattern.replace('??', '[0-9A-F]{2}')
            # Try anchored match at exact EP first
            regex_anchored = re.compile(f'^{regex_str}')
            match_result = regex_anchored.search(ep_hex)
            # If not at EP, try anywhere in the window (catches junk bytes)
            if not match_result:
                regex_unanchored = re.compile(regex_str)
                match_result = regex_unanchored.search(ep_hex)
                if match_result:
                    evidence.append(
                        f"EP offset match for {sig['name']}: pattern found "
                        f"at byte offset {match_result.start() // 2}"
                    )
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