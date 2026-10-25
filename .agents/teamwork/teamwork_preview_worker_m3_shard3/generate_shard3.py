#!/usr/bin/env python3
"""Generator script for 120 FrameAssembly L3 examples (Shard 3).
"""

import os
import subprocess
import sys

def check_file(filepath):
    lines = open(filepath).read().splitlines()
    assert lines[0].startswith("// PROMPT: "), f"{filepath}: line 1 prompt missing"
    assert lines[1].startswith("// TOKENS: "), f"{filepath}: line 2 tokens missing"
    assert "// INSTRUCTION:" in open(filepath).read(), f"{filepath}: instruction missing"
    avg = sum(len(l) for l in lines) / len(lines)
    m = max(len(l) for l in lines)
    assert avg <= 85, f"{filepath}: avg len {avg} > 85"
    assert m <= 200, f"{filepath}: max len {m} > 200"

    pcap = f"/tmp/test_{os.path.basename(filepath)}.pcap"
    cmd = ["./target/debug/frameassembly", filepath, "-o", pcap]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"FAILED {filepath}: {res.stderr} {res.stdout}")
        sys.exit(1)
    assert os.path.exists(pcap) and os.path.getsize(pcap) > 0, f"0 byte pcap {filepath}"
    os.remove(pcap)
    print(f"OK: {filepath} (avg={avg:.1f}, max={m})")

def write_fasm(rel_path, content):
    full_path = os.path.join("/home/steve/frameassembly", rel_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    check_file(full_path)

print("Generator initialized.")
