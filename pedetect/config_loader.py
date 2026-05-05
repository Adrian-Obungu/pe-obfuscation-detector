import json
import os
import sys
from typing import Any, Dict

def _load_config() -> Dict[str, Any]:
    """
    Load the centralized configuration from config.json.
    
    Returns:
        Dict[str, Any]: The configuration dictionary.
    """
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    defaults = {
        "verdict": {
            "clean_threshold": 0.3,
            "suspicious_threshold": 0.6
        },
        "entropy": {
            "high_entropy_threshold": 7.0,
            "whole_file_threshold": 6.8,
            "low_entropy_threshold": 5.5,
            "high_rsrc_threshold": 7.0,
            "low_variance_threshold": 0.3,
            "chunk_size": 65536
        },
        "sections": {
            "suspicious_names": ["UPX0","UPX1","UPX2",".aspack",".adata",".MPRESS1",".MPRESS2",".petite",".winapi","pec1","pec2","pec",".nsp0",".nsp1",".nsp2",".yP",".y0da",".enigma",".vmp0",".vmp1",".themida",".sforce",".safedisc",".securom",".ndrv"],
            "min_normal_count": 3,
            "max_normal_count": 8,
            "raw_virtual_ratio_high": 5.0,
            "raw_virtual_ratio_low": 0.2
        },
        "signatures": {
            "default_min_ep_length": 4,
            "max_ep_bytes": 256
        }
    }
    
    if not os.path.exists(config_path):
        print(f"[WARNING] config.json not found at {config_path}. Using defaults.", file=sys.stderr)
        return defaults
        
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load config.json: {e}. Using defaults.", file=sys.stderr)
        return defaults
