import pytest
import os
import json
from unittest.mock import MagicMock, patch
from pedetect.heuristics.signatures import EPSignatureMatcher, check_ep_signatures

@pytest.fixture
def mock_pe():
    pe = MagicMock()
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    section = MagicMock()
    section.VirtualAddress = 0x1000
    section.Misc_VirtualSize = 0x1000
    section.get_data.return_value = b'\x55\x8B\xEC\x6A\xFF' + b'\x00' * 251
    pe.sections = [section]
    return pe

def test_load_valid_signatures(tmp_path):
    sig_data = {
        "signatures": [
            {"name": "UPX", "pattern": "60 BE ?? ?? ?? ?? 8D BE", "confidence": 0.9, "description": "UPX Packer"}
        ]
    }
    sig_file = tmp_path / "signatures.json"
    sig_file.write_text(json.dumps(sig_data))
    
    matcher = EPSignatureMatcher(str(sig_file))
    assert len(matcher.signatures) == 1
    assert matcher.signatures[0]['name'] == "UPX"

def test_load_missing_file():
    matcher = EPSignatureMatcher("non_existent.json")
    assert matcher.signatures == []

def test_load_malformed_json(tmp_path):
    sig_file = tmp_path / "malformed.json"
    sig_file.write_text("{ invalid json }")
    matcher = EPSignatureMatcher(str(sig_file))
    assert matcher.signatures == []

def test_match_upx_stub(mock_pe, tmp_path):
    sig_data = {
        "signatures": [
            {"name": "UPX", "pattern": "60 BE 00 10 40 00 8D BE", "confidence": 0.9, "description": "UPX Packer"}
        ]
    }
    sig_file = tmp_path / "signatures.json"
    sig_file.write_text(json.dumps(sig_data))
    
    # Set EP bytes to match pattern
    mock_pe.sections[0].get_data.return_value = bytes.fromhex("60BE001040008DBE") + b'\x00' * 248
    
    score, evidence = check_ep_signatures(mock_pe, str(sig_file))
    assert score >= 0.85
    assert "UPX" in evidence[0]

def test_no_match_clean_ep(mock_pe, tmp_path):
    sig_data = {"signatures": [{"name": "UPX", "pattern": "60 BE", "confidence": 0.9}]}
    sig_file = tmp_path / "signatures.json"
    sig_file.write_text(json.dumps(sig_data))
    
    mock_pe.sections[0].get_data.return_value = b'\x90\x90\x90\x90' + b'\x00' * 252
    score, evidence = check_ep_signatures(mock_pe, str(sig_file))
    assert score == 0.0
    assert len(evidence) == 0

def test_ep_not_in_section(mock_pe):
    mock_pe.sections = []
    score, evidence = check_ep_signatures(mock_pe)
    assert score == 0.0
    assert "Cannot locate entry point" in evidence[0]
