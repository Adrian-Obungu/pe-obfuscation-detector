# pedetect/heuristics/strings_.py
"""Heuristic 6: String & resource cross-reference analysis."""
import pefile

MIN_STRING_LENGTH = 4

API_STRING_MAP = {
    b'RegCreateKeyEx': [b'SOFTWARE', b'SYSTEM\\CurrentControlSet', b'Microsoft\\Windows'],
    b'RegSetValueEx': [b'SOFTWARE', b'SYSTEM'],
    b'RegOpenKeyEx': [b'SOFTWARE', b'SYSTEM'],
    b'RegQueryValueEx': [b'SOFTWARE', b'SYSTEM'],
    b'InternetOpen': [b'http', b'https', b'Mozilla', b'User-Agent'],
    b'URLDownloadToFile': [b'http', b'https', b'.exe', b'.dll'],
    b'WinHttpOpen': [b'http', b'https', b'Mozilla'],
    b'WinHttpConnect': [b'http', b'https'],
    b'CreateFile': [b'.', b'\\', b'/'],
    b'WriteFile': [b'.'],
    b'ReadFile': [b'.'],
    b'CreateProcess': [b'.exe', b'.dll'],
    b'WinExec': [b'.exe'],
    b'ShellExecute': [b'open', b'http'],
}


def _extract_ascii_strings(pe, min_length=MIN_STRING_LENGTH):
    strings_found = []
    for section in pe.sections:
        data = section.get_data()
        current = b''
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    strings_found.append(current)
                current = b''
        if len(current) >= min_length:
            strings_found.append(current)
    return strings_found


def check_strings(pe: pefile.PE) -> tuple:
    evidence = []
    scores = []
    strings = _extract_ascii_strings(pe)
    try:
        import_entries = pe.DIRECTORY_ENTRY_IMPORT
    except AttributeError:
        return (0.0, evidence)
    imported_functions = set()
    for entry in import_entries:
        for func in entry.imports:
            if func.name:
                imported_functions.add(func.name)
    for api_name, expected_keywords in API_STRING_MAP.items():
        api_match = api_name in imported_functions
        if not api_match:
            api_match = any(
                f.startswith(api_name) for f in imported_functions
                if len(f) == len(api_name) + 1 and f[-1:] in (b'A', b'W')
            )
        if api_match:
            found = False
            for keyword in expected_keywords:
                for s in strings:
                    if keyword.lower() in s.lower():
                        found = True
                        break
                if found:
                    break
            if not found:
                api_display = api_name.decode('utf-8', errors='replace')
                evidence.append(
                    f"Possible fake import: {api_display} imported but no "
                    f"related string reference found"
                )
                scores.append(0.3)
    score = sum(scores) / max(len(scores), 1) if scores else 0.0
    return (min(score, 1.0), evidence)