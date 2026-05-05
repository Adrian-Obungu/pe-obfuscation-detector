import pytest
from unittest.mock import MagicMock
from pedetect.heuristics.header import check_header_integrity

@pytest.fixture
def mock_pe():
    pe = MagicMock()
    pe.DOS_HEADER.e_magic = 0x5A4D
    pe.NT_HEADERS.Signature = 0x00004550
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    section = MagicMock()
    section.VirtualAddress = 0x1000
    section.Misc_VirtualSize = 0x1000
    section.Name = b'.text\x00\x00\x00'
    section.Characteristics = 0x60000020  # Executable, Readable
    pe.sections = [section]
    pe.RICH_HEADER = None
    return pe

def test_valid_pe(mock_pe):
    score, evidence = check_header_integrity(mock_pe)
    # Score might be 0.3 because of missing Rich Header
    assert score <= 0.3
    assert any("No Rich Header detected" in e for e in evidence)

def test_corrupted_dos_magic(mock_pe):
    mock_pe.DOS_HEADER.e_magic = 0x0000
    score, evidence = check_header_integrity(mock_pe)
    assert score == 1.0
    assert "Invalid DOS magic" in evidence[0]

def test_rwx_section_present(mock_pe):
    mock_pe.sections[0].Characteristics = 0xE0000020  # RWX
    score, evidence = check_header_integrity(mock_pe)
    assert score >= 0.5
    assert any("RWX section found" in e for e in evidence)

def test_ep_outside_section(mock_pe):
    mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x5000
    score, evidence = check_header_integrity(mock_pe)
    assert score >= 0.8
    assert any("not within any section bounds" in e for e in evidence)

def test_rich_header_present(mock_pe):
    mock_pe.RICH_HEADER = MagicMock()
    score, evidence = check_header_integrity(mock_pe)
    assert any("Rich Header found" in e for e in evidence)
    # Negative contribution means score should be 0.0 if no other issues
    assert score == 0.0
