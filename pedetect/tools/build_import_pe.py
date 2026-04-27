#!/usr/bin/env python3
"""Build a minimal PE with a custom import table for testing H3 heuristics."""
import struct, sys

def build_minimal_pe_with_imports(dll_name: bytes, func_names: list[bytes], out_path: str,
                                   section_name: bytes = b'.text\x00\x00\x00',
                                   ep_stub: bytes = None):
    """
    Build a valid PE32 with a single section and an import directory.
    
    Args:
        dll_name: e.g. b'kernel32.dll'
        func_names: e.g. [b'LoadLibraryA', b'GetProcAddress']
        out_path: output file path
        section_name: 8-byte section name
        ep_stub: bytes at entry point (default: simple RET)
    """
    if ep_stub is None:
        ep_stub = b'\xC3'  # RET

    # --- DOS Header ---
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x40)

    pe_sig = b'PE\x00\x00'

    # --- COFF Header: 1 section, SizeOfOptionalHeader = 0xE0 ---
    coff = struct.pack('<HHIIIHH', 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)

    # --- Optional Header (PE32) ---
    opt = bytearray(0xE0)
    struct.pack_into('<I', opt, 0x10, 0x1000)   # AddressOfEntryPoint
    struct.pack_into('<I', opt, 0x1C, 0x400000)  # ImageBase
    struct.pack_into('<I', opt, 0x24, 0x200)     # FileAlignment
    struct.pack_into('<I', opt, 0x28, 0x1000)    # SectionAlignment
    struct.pack_into('<I', opt, 0x38, 0x3000)    # SizeOfImage
    struct.pack_into('<I', opt, 0x3C, 0x200)     # SizeOfHeaders
    struct.pack_into('<H', opt, 0x5C, 2)         # Subsystem = GUI

    # --- Build import directory data ---
    # Import directory will be placed in section at offset 0x800
    import_data_rva = 0x2000  # RVA for import directory
    import_data_offset = 0x800  # file offset (section_base 0x200 + 0x600 bytes for EP/code + padding)

    # DLL name string
    dll_name_rva = import_data_rva + 0x40  # after descriptor
    dll_name_bytes = dll_name + b'\x00'

    # Function hint/name entries
    hint_name_rva = dll_name_rva + len(dll_name_bytes)
    hint_names = b''
    func_rvas = []
    for fn in func_names:
        func_rvas.append(hint_name_rva + len(hint_names))
        hint_names += struct.pack('<H', 0) + fn + b'\x00'  # Hint=0, Name, null

    # ILT (Import Lookup Table) — array of IMAGE_THUNK_DATA, null-terminated
    ilt_rva = hint_name_rva + len(hint_names)
    ilt = b''
    for rva in func_rvas:
        ilt += struct.pack('<I', rva)  # RVA to hint/name (bit 31 = 0 means import by name)
    ilt += struct.pack('<I', 0)  # null terminator

    # IAT (Import Address Table) — same structure, different RVA
    iat_rva = ilt_rva + len(ilt)
    iat = ilt  # Same contents initially

    # IMAGE_IMPORT_DESCRIPTOR (20 bytes)
    descriptor_rva = import_data_rva
    descriptor = struct.pack('<IIIII',
        ilt_rva,      # OriginalFirstThunk (ILT)
        0,            # TimeDateStamp
        0,            # ForwarderChain
        dll_name_rva, # Name RVA
        iat_rva,      # FirstThunk (IAT)
    ) + b'\x00' * 4  # terminator descriptor (all zeros, 20 bytes)

    import_data = descriptor + b'\x00' * (dll_name_rva - descriptor_rva - len(descriptor))
    import_data += dll_name_bytes
    import_data += hint_names
    import_data += ilt
    import_data += iat

    # Set Import Directory RVA and Size in optional header
    struct.pack_into('<I', opt, 0x68, import_data_rva)  # IMAGE_DIRECTORY_ENTRY_IMPORT RVA
    struct.pack_into('<I', opt, 0x6C, len(import_data))  # Size

    # --- Section Header ---
    section = section_name + struct.pack('<IIIIIIHHI',
        0x2000,          # VirtualSize
        0x1000,          # VirtualAddress
        0xA00,           # SizeOfRawData (0x600 for EP stub + 0x400 for import data)
        0x200,           # PointerToRawData
        0, 0, 0, 0,
        0xE0000040,      # RWX characteristics
    )

    # --- Headers ---
    headers = bytes(dos) + pe_sig + coff + bytes(opt) + section
    headers = headers.ljust(0x200, b'\x00')

    # --- Section Raw Data ---
    # EP stub at start of section
    ep_data = ep_stub + b'\x00' * (0x600 - len(ep_stub))  # pad to 0x600 bytes
    # Import data at offset 0x600 into section
    import_padded = import_data + b'\x00' * (0x400 - len(import_data))  # pad to 0x400
    section_raw = ep_data + import_padded

    # --- Build ---
    with open(out_path, 'wb') as f:
        f.write(headers + section_raw)
    print(f'Written: {out_path}')
    print(f'  DLL: {dll_name.decode()}')
    print(f'  Functions: {[fn.decode() for fn in func_names]}')
    print(f'  Total imports: {len(func_names)} from 1 DLL')

if __name__ == '__main__':
    # Default: kernel32.dll with LoadLibraryA + GetProcAddress (dynamic resolution loop)
    dll = b'kernel32.dll'
    funcs = [b'LoadLibraryA', b'GetProcAddress']
    out = '/tmp/corpus/minimal_imports.exe'

    if len(sys.argv) >= 2:
        out = sys.argv[1]
    if len(sys.argv) >= 3:
        dll = sys.argv[2].encode()
    if len(sys.argv) >= 4:
        funcs = [f.encode() for f in sys.argv[3:]]

    import os
    os.makedirs('/tmp/corpus', exist_ok=True)
    build_minimal_pe_with_imports(dll, funcs, out)