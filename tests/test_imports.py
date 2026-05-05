import pytest
from unittest.mock import MagicMock
from pedetect.heuristics.imports import check_import_table

@pytest.fixture
def mock_pe():
    pe = MagicMock()
    pe.FILE_HEADER.Characteristics = 0x0102  # Executable, 32-bit
    return pe

def test_stripped_import_non_dll(mock_pe):
    del mock_pe.DIRECTORY_ENTRY_IMPORT
    mock_pe.FILE_HEADER.Characteristics = 0x0102
    score, evidence = check_import_table(mock_pe)
    assert score == 1.0
    assert "stripped (non-DLL)" in evidence[0]

def test_stripped_import_dll(mock_pe):
    del mock_pe.DIRECTORY_ENTRY_IMPORT
    mock_pe.FILE_HEADER.Characteristics = 0x2102  # DLL flag
    score, evidence = check_import_table(mock_pe)
    assert score == 0.3
    assert "stripped (DLL)" in evidence[0]

def test_minimal_imports(mock_pe):
    entry = MagicMock()
    entry.dll = b'kernel32.dll'
    imp = MagicMock()
    imp.name = b'ExitProcess'
    entry.imports = [imp]
    mock_pe.DIRECTORY_ENTRY_IMPORT = [entry]
    score, evidence = check_import_table(mock_pe)
    assert score >= 0.9
    assert "Minimal imports" in evidence[0]

def test_dynamic_resolution_loop(mock_pe):
    entry = MagicMock()
    entry.dll = b'kernel32.dll'
    imp1 = MagicMock(); imp1.name = b'LoadLibraryA'
    imp2 = MagicMock(); imp2.name = b'GetProcAddress'
    imp3 = MagicMock(); imp3.name = b'ExitProcess'
    entry.imports = [imp1, imp2, imp3]
    mock_pe.DIRECTORY_ENTRY_IMPORT = [entry]
    score, evidence = check_import_table(mock_pe)
    assert score >= 0.9
    assert any("Dynamic resolution loop" in e for e in evidence)

def test_ordinal_only_imports(mock_pe):
    entry = MagicMock()
    entry.dll = b'kernel32.dll'
    entry.imports = [MagicMock(name=None) for _ in range(6)]
    for imp in entry.imports: imp.name = None
    mock_pe.DIRECTORY_ENTRY_IMPORT = [entry]
    score, evidence = check_import_table(mock_pe)
    assert score >= 0.7
    assert any("Ordinal-only imports" in e for e in evidence)

def test_tls_callback_minimal_imports(mock_pe):
    entry = MagicMock()
    entry.dll = b'kernel32.dll'
    entry.imports = [MagicMock(name=b'ExitProcess')]
    mock_pe.DIRECTORY_ENTRY_IMPORT = [entry]
    mock_pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks = 0x401000
    score, evidence = check_import_table(mock_pe)
    assert score == 1.0
    assert any("TLS callback present" in e for e in evidence)

def test_process_hollowing_chain(mock_pe):
    entry = MagicMock()
    entry.dll = b'kernel32.dll'
    funcs = [b'CreateProcessA', b'WriteProcessMemory', b'VirtualAllocEx', b'ResumeThread']
    mock_imports = []
    for f in funcs:
        m = MagicMock()
        m.name = f
        mock_imports.append(m)
    entry.imports = mock_imports
    mock_pe.DIRECTORY_ENTRY_IMPORT = [entry]
    score, evidence = check_import_table(mock_pe)
    assert score >= 1.0
    assert any("Process hollowing chain detected" in e for e in evidence)
