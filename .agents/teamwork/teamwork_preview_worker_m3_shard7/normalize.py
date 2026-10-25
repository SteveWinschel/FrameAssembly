#!/usr/bin/env python3
import os
import re
import subprocess
import sys

def wrap_tokens_line(line):
    # If line 2 // TOKENS: ... exceeds 180 chars, deduplicate and keep top tokens
    if len(line) <= 180:
        return line
    prefix = "// TOKENS: "
    body = line[len(prefix):].strip()
    tokens = [t.strip() for t in body.split(",") if t.strip()]
    seen = set()
    dedup = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            dedup.append(t)
    
    # Pack into <= 180 chars
    res = []
    cur_len = len(prefix)
    for t in dedup:
        needed = len(t) + (2 if res else 0)
        if cur_len + needed > 180:
            break
        res.append(t)
        cur_len += needed
    return prefix + ", ".join(res)

def wrap_prompt_line(line):
    if len(line) <= 180:
        return line
    prefix = "// PROMPT: "
    body = line[len(prefix):].strip()
    # Shorten body intelligently at sentence/clause boundary
    if len(body) > 160:
        body = body[:160].rsplit(" ", 1)[0] + "."
    return prefix + body

def split_statement_line(line):
    # Splits a statement line into multiple lines with 4-space continuation indent
    # Only split if line > 85 chars or has multiple VARBINDs / long parameters
    stripped = line.strip()
    if not stripped or stripped.startswith("//") or stripped.startswith("HOST ") or stripped.startswith("COMPILE") or stripped.startswith("FLOW ") or stripped == "}":
        return [line]

    indent = len(line) - len(line.lstrip(" "))
    cont_indent = " " * (indent + 4)
    
    # We want to break on VARBIND, and certain keywords if the line is long
    # Let's tokenize by space, preserving quoted strings
    tokens = []
    pattern = re.compile(r'("[^"]*"|\S+)')
    for m in pattern.finditer(stripped):
        tokens.append(m.group(1))

    # Reconstruct lines
    lines = []
    cur_tokens = []
    
    # Major break keywords:
    split_keys = {"VARBIND", "WAIT"}
    # Additional keywords when line gets long (> 70):
    minor_keys = {"USER", "ENGINEID", "BOOTS", "TIME", "AUTH", "AUTHPASS", "PRIV", "PRIVPASS", "CONTEXT", "ENTERPRISE", "AGENTIP", "GENTRAP", "SPECTRAP", "SYSUPTIME", "COMMUNITY", "REQID", "NONREPEATERS", "MAXREPETITIONS"}

    for i, tok in enumerate(tokens):
        # Should we break before tok?
        break_before = False
        if tok in split_keys:
            if cur_tokens:
                break_before = True
        elif tok in minor_keys:
            cur_line_len = indent + sum(len(t) for t in cur_tokens) + max(0, len(cur_tokens) - 1)
            if cur_line_len > 60:
                break_before = True
        
        if break_before:
            if cur_tokens:
                prefix_sp = " " * indent if not lines else cont_indent
                lines.append(prefix_sp + " ".join(cur_tokens))
                cur_tokens = []
        cur_tokens.append(tok)

    if cur_tokens:
        prefix_sp = " " * indent if not lines else cont_indent
        lines.append(prefix_sp + " ".join(cur_tokens))

    # Check if any resulting line is still > 190, if so break further
    final_lines = []
    for l in lines:
        if len(l) > 190:
            words = l.strip().split()
            sub_cur = []
            for w in words:
                candidate = cont_indent + " ".join(sub_cur + [w])
                if len(candidate) > 180 and sub_cur:
                    final_lines.append(cont_indent + " ".join(sub_cur))
                    sub_cur = [w]
                else:
                    sub_cur.append(w)
            if sub_cur:
                final_lines.append(cont_indent + " ".join(sub_cur))
        else:
            final_lines.append(l)

    return final_lines

def normalize_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    orig_lines = content.splitlines()
    new_lines = []
    for i, l in enumerate(orig_lines):
        if i == 0 and l.startswith("// PROMPT: "):
            new_lines.append(wrap_prompt_line(l))
        elif i == 1 and l.startswith("// TOKENS: "):
            new_lines.append(wrap_tokens_line(l))
        else:
            if len(l) > 85 or "VARBIND" in l:
                wrapped = split_statement_line(l)
                new_lines.extend(wrapped)
            else:
                new_lines.append(l)

    out_content = "\n".join(new_lines) + "\n"
    return out_content

if __name__ == "__main__":
    test_file = sys.argv[1] if len(sys.argv) > 1 else "examples/l7/snmp/snmpv1/snmpv1_all_supported_v1_varbind_types.fasm"
    norm = normalize_file(test_file)
    print("=== NORMALIZED CONTENT ===")
    print(norm)
    lengths = [len(l) for l in norm.splitlines()]
    print(f"Max: {max(lengths)}, Avg: {sum(lengths)/len(lengths):.1f}")
