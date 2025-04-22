#!/usr/bin/env python3
"""
compare_validation_results.py

Compares multiple CML instance validation JSON outputs and highlights key differences.

Usage:
  python3 compare_validation_results.py devnet_*.json ubuntu-cloudinit-test_*.json cml-cloudinit-test_*.json cml-controller-7f767e19_*.json

Best practice: Run this script in the same directory as your validation output files.
"""
import sys
import json
import os
from collections import defaultdict
from typing import List, Dict, Any

# Fields to compare (customize as needed)
KEY_FIELDS = [
    ('launch_metadata', ['ami_id', 'instance_type', 'key_name', 'launch_time']),
    ('iam_role_and_policy', ['role_name', 'ssm_policy_attached', 'policies']),
    ('ssm_status', []),
    ('ssh_status', []),
    ('network_diagnostics', []),
    ('cloudinit_logs', []),
    ('security_groups', []),
    ('nacl_rules', []),
]


def load_json(path: str) -> Dict[str, Any]:
    with open(path, 'r') as f:
        return json.load(f)


def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def extract_fields(data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
    if not fields:
        return data
    result = {}
    for field in fields:
        result[field] = data.get(field, None)
    return result


def compare_results(files: List[str]):
    results = {}
    for file in files:
        name = os.path.basename(file).split('_')[0]
        try:
            data = load_json(file)
            results[name] = data
        except Exception as e:
            print(f"Error loading {file}: {e}")
            continue

    print("\n=== CML Instance Validation Comparison ===\n")
    for key, subfields in KEY_FIELDS:
        print(f"--- {key} ---")
        row = {}
        for name, data in results.items():
            value = data.get(key, {})
            if subfields:
                value = extract_fields(value, subfields)
            row[name] = value
        # Pretty print differences
        for subkey in (subfields if subfields else row[list(row.keys())[0]].keys() if row else []):
            print(f"  {subkey}:")
            for name in results:
                print(f"    {name}: {row[name].get(subkey) if isinstance(row[name], dict) else row[name]}")
        if not subfields:
            # For nested or list fields, just print summary
            for name in results:
                val = row[name]
                if isinstance(val, dict) or isinstance(val, list):
                    preview = json.dumps(val, indent=2)[:300]
                    print(f"    {name}: {preview}{' ...' if len(preview)==300 else ''}")
                else:
                    print(f"    {name}: {val}")
        print()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 compare_validation_results.py <file1.json> <file2.json> ...")
        sys.exit(1)
    compare_results(sys.argv[1:])
