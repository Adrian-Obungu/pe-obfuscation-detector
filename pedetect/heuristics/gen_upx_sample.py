import struct
import os

upx_stub = bytes.fromhex('60 BE 00 10 00 01 8D BE 00 00 F0 FF 57 83 CD FF')

dos = bytearray(64)
dos[0:2] = b'MZ'
struct.pack_into('<I', dos, 0x3C, 0x40)

pe_sig = b'PE\x00\x00'
coff = struct.pack('<HHIIIHH', 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)

opt = bytearray(0xE0)
struct.pack_into('<I', opt, 0x10, 0x1000)    # AddressOfEntryPoint
struct.pack_into('<I', opt, 0x1C, 0x400000)  # ImageBase
struct.pack_into('<I', opt, 0x38, 0x2000)    # SizeOfImage
struct.pack_into('<I', opt, 0x3C, 0x200)     # SizeOfHeaders
struct.pack_into('<H', opt, 0x5C, 2)         # Subsystem = GUI

# Section: UPX0, RVA 0x1000, raw offset 0x1F8 (exact header length)
section_name = b'UPX0\x00\x00\x00\x00'
section = section_name + struct.pack('<IIIIIIHHI',
    0x1000,           # VirtualSize
    0x1000,           # VirtualAddress
    0x200,            # SizeOfRawData
    0x200,            # PointerToRawData
    0, 0, 0, 0,
    0xE0000040)       # RWX characteristics

headers = bytes(dos) + pe_sig + coff + bytes(opt) + section
# Pad headers to exactly 0x200 with zeros
assert len(headers) <= 0x200, f"Headers too large: {len(headers)}"
headers = headers + b'\x00' * (0x200 - len(headers))

raw_data = upx_stub + os.urandom(0x200 - len(upx_stub))
full = headers + raw_data

with open('/tmp/test_upx_packed.exe', 'wb') as f:
    f.write(full)
print(f'UPX-like PE written: {len(full)} bytes')