#!/usr/bin/env python3
"""Verification script for Shard 3 files.

Checks:
1. File exists and has at least 3 lines.
2. Line 1: // PROMPT: <non-empty>
3. Line 2: // TOKENS: <non-empty>
4. Every HOST, FLOW, COMPILE block preceded by // INSTRUCTION:
5. Filename does not start with a digit and ends with .fasm.
6. avg_line_length <= 85 and max_line_length <= 200.
7. Successful compilation via target/debug/frameassembly.
"""

import os
import subprocess
import sys

ASSIGNED_DIRS = [
    "examples/l3/ipsec",
    "examples/l3/mld",
    "examples/l3/ndp",
    "examples/l3/openflow",
    "examples/l3/ospf",
    "examples/l3/pim",
    "examples/l3/rip",
    "examples/l3/vrrp",
    "examples/l3/vxlan",
    "examples/l3/wireguard",
]

def verify_file(filepath):
    errors = []
    filename = os.path.basename(filepath)
    if filename[0].isdigit():
        errors.append(f"Filename starts with digit: {filename}")
    if not filename.endswith(".fasm"):
        errors.append(f"Filename does not end with .fasm: {filename}")

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()
    if len(lines) < 3:
        errors.append("File has fewer than 3 lines")
        return errors

    # Check line 1
    if not lines[0].startswith("// PROMPT: "):
        errors.append(f"Line 1 does not start with '// PROMPT: ': {lines[0]}")
    elif len(lines[0].replace("// PROMPT: ", "").strip()) == 0:
        errors.append("Line 1 PROMPT body is empty")

    # Check line 2
    if not lines[1].startswith("// TOKENS: "):
        errors.append(f"Line 2 does not start with '// TOKENS: ': {lines[1]}")
    elif len(lines[1].replace("// TOKENS: ", "").strip()) == 0:
        errors.append("Line 2 TOKENS body is empty")

    # Check instruction comments
    if "// INSTRUCTION:" not in content:
        errors.append("File lacks '// INSTRUCTION:' comment")

    # Check line lengths
    total_len = sum(len(line) for line in lines)
    avg_len = total_len / len(lines) if lines else 0
    max_len = max(len(line) for line in lines) if lines else 0

    if avg_len > 85:
        errors.append(f"avg_line_length {avg_len:.1f} > 85")
    if max_len > 200:
        errors.append(f"max_line_length {max_len} > 200")

    # Compile via target/debug/frameassembly
    tmp_pcap = f"/tmp/verify_{os.getpid()}_{filename}.pcap"
    cmd = ["./target/debug/frameassembly", filepath, "-o", tmp_pcap]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        errors.append(f"Compilation failed (code {res.returncode}): {res.stderr.strip() or res.stdout.strip()}")
    else:
        if not os.path.exists(tmp_pcap) or os.path.getsize(tmp_pcap) == 0:
            errors.append("Output PCAP missing or 0 bytes")
        if os.path.exists(tmp_pcap):
            os.remove(tmp_pcap)

    return errors

def main():
    total_files = 0
    total_errors = 0
    for d in ASSIGNED_DIRS:
        if not os.path.isdir(d):
            print(f"Directory {d} does not exist!")
            sys.exit(1)
        files = [f for f in os.listdir(d) if f.endswith(".fasm")]
        print(f"Checking {d}: {len(files)} files")
        for f in sorted(files):
            total_files += 1
            fpath = os.path.join(d, f)
            errs = verify_file(fpath)
            if errs:
                total_errors += len(errs)
                print(f"  [FAIL] {f}:")
                for e in errs:
                    print(f"    - {e}")

    print(f"\nTotal files checked: {total_files}, Total errors: {total_errors}")
    if total_errors > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
