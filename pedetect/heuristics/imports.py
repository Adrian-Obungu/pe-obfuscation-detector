# pedetect/heuristics/imports.py
"""Heuristic 3: Import table forensics."""
import pefile

SUSPICIOUS_COMBOS = [
    ( {b'kernel32.dll'}, {b'VirtualAlloc', b'VirtualProtect'}, 0.8, "Minimal kernel32 stub"),
    ( {b'kernel32.dll'}, {b'LoadLibraryA', b'GetProcAddress'}, 0.9, "Dynamic resolution loop"),
    ( {b'kernel32.dll'}, {b'LoadLibraryW', b'GetProcAddress'}, 0.9, "Dynamic resolution loop (wide)"),
    ( {b'kernel32.dll'}, {b'CreateProcess', b'WriteProcessMemory', b'VirtualAllocEx', b'ResumeThread'}, 1.0, "Process hollowing chain"),
    ( {b'ntdll.dll'}, {b'NtUnmapViewOfSection', b'NtWriteVirtualMemory', b'NtResumeThread'}, 1.0, "NT-level process hollowing"),
    ( {b'kernel32.dll'}, {b'VirtualAlloc', b'RtlMoveMemory', b'CreateThread', b'WaitForSingleObject'}, 0.9, "Shellcode launcher"),
    ( {b'kernel32.dll'}, {b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread'}, 0.9, "Remote injection chain"),
    ( {b'kernel32.dll'}, {b'IsDebuggerPresent', b'VirtualAlloc'}, 0.6, "Anti-debug + memory allocation"),
]

def check_import_table(pe: pefile.PE) -> tuple:
    evidence = []
    scores = []

    try:
        import_entries = pe.DIRECTORY_ENTRY_IMPORT
    except AttributeError:
        is_dll = (pe.FILE_HEADER.Characteristics & 0x2000) != 0
        if not is_dll:
            return (1.0, ["Import table stripped (non-DLL)"])
        else:
            return (0.3, ["Import table stripped (DLL)"])

    total_imports = 0
    dlls_imported = set()
    all_functions = set()
    only_ordinal_dlls = 0

    for entry in import_entries:
        dll_name = entry.dll.lower()
        dlls_imported.add(dll_name)
        func_names_for_dll = []
        ordinal_count = 0
        for func in entry.imports:
            total_imports += 1
            if func.name:
                func_names_for_dll.append(func.name)
                all_functions.add(func.name)
            else:
                ordinal_count += 1
        if ordinal_count > 0 and len(func_names_for_dll) == 0:
            only_ordinal_dlls += 1

    if total_imports < 5 and len(dlls_imported) == 1:
        evidence.append(f'Minimal imports: {total_imports} from {len(dlls_imported)} DEL')
        scores.append(0.9)
    elif total_imports < 10:
        evidence.append(f'Low import count: {total_imports}')
        scores.append(0.5)

    if only_ordinal_dlls > 0 and total_imports > 5:
        evidence.append(f'Ordinal-only imports from {only_ordinal_dlls} DLLs')
        scores.append(0.7)

    for dll_set, func_set, weight, desc in SUSPICIOUS_COMBOS:
        dll_match = any(d in dlls_imported for d in dll_set)
        func_match = func_set.issubset(all_functions)
        if dll_match and func_match:
            evidence.append(f'{desc} (weight: {weight})')
            scores.append(weight)

    tls_present = _has_tls_callback(pe)
    if tls_present and total_imports < 10:
        evidence.append("TLS callback present with minimal imports")
        scores.append(1.0)

    score = sum(scores) / max(len(scores), 1) if scores else 0.0
    return (min(score, 1.0), evidence)

def _has_tls_callback(pe: pefile.PE) -> bool:
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
            tls = pe.DIRECTORY_ENTRY_TLS.struct
            if hasattr(tls, 'AddressOfCallBacks') and tls.AddressOfCallBacks != 0:
                return True
    except Exception:
        pass
    return False
