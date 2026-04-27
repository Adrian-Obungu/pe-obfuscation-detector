#!/usr/bin/env python3
"""Build a minimal PE with a custom import table for testing H3 heuristics."""
import struct, sys, os

def build_minimal_pe_with_imports(dll_name: bytes, func_names: list[bytes], out_path: str,
                                 section_name: bytes = b'.text\x00\x00\x00',
                                 ep_stub: bytes = None):
    if ep_stub is None:
        ep_stub = b'\xC3'  # RET

    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x40)
    pe_sig = b'PE\x00\x00'
    coff = struct.pack('<HHIIHHH', 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)

    opt = bytearray(0xE0)
    struct.pack_into('<I', opt, 0x10, 0x1000)
    struct.pack_into('<I', opt, 0x1C, 0x400000)
    struct.pack_into('<I', opt, 0x24, 0x200)
    struct.pack_into('<I', opt, 0x28, 0x1000)
    struct.pack_into('<I', opt, 0x38, 0x3000)
    struct.pack_into('<I', opt, 0x3C, 0x200)
    struct.pack_into('<H', opt, 0x5C, 2)

    import_data_rva = 0x2000
    import_data_offset = 0x800
    dll_name_rva = import_data_rva + 0x40
    dll_name_bytes = dll_name + b'\x00'
    hint_name_rva = dll_name_rva + len(dll_name_bytes)
    hint_names = b''
    func_rvas = []
    for fn in func_names:
        func_rvas.append(hint_name_rva + len(hint_names))
        hint_names += struct.pack('<H', 0) + fn + b'\x00'

    ilt_rva = hint_name_rva + len(hint_names)
    ilt = b''
    for rva in func_rvas:
        ilt += struct.pack('<I', rva)
    ilt += struct.pack('<I', 0)

    iat_rva = ilt_rva + len(ilt)
    iat = ilt

    descriptor_rva = import_data_rva
    descriptor = struct.pack('<IIIII',
        ilt_rva, 0, 0, dll_name_rva, iat_rva,
    ) + b'\x00' * 20

    import_data = descriptor + b'\x00' * (dll_name_rva - descriptor_rva - len(descriptor))
    import_data += dll_name_bytes
    import_data += hint_names
    import_data += ilt
    import_data += iat

    struct.pack_into('<I', opt, 0x68, import_data_rva)
    struct.pack_into('<I', opt, 0x6C, len(import_data))

    section = section_name + struct.pack('<IIIIIHHI',
        0x2000, 0x1000, 0xA00, 0x200, 0, 0, 0, 0, 0xE0000040)

    headers = bytes(dos) + pe_sig + coff + bytes(opt) + section
    headers = headers.ljust(0x200, b'\x00')

    ep_data = ep_stub + b'\x00' * (0x600 - len(ep_stub))
    import_padded = import_data + b'\x00' * (0x400 - len(import_data))
    section_raw = ep_data + import_padded

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(headers + section_raw)
    print(f'Written: {out_path}')
    print(f'  DLL: {dll_name.decode()}')
    print(f'  Functions: {[fn.decode() for fn in func_names]}')
    print(f'  Total imports: {len(func_names)} from 1 DLLnull' if func_names else '0')

if __name__ == '__main__':
    dll = b'kernel32.dll'
    funcs = [b'LoadLibraryA', b'GetProcAddress']
    out = '/tmp/corpus/minimal_imports.exe'
    if len(sys.argv) >= 2:
        out = sys.argv[1]
    if len(sys.argv) >= 3:
        dll = sys.argv[2].encode()
    if len(sys.argv) >= 4:
        funcs = [f.encode() for f in sys.argv[3:]]
    build_minimal_pe_with_imports(dll, funcs, out)
