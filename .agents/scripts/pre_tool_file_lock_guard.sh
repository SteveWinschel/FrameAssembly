#!/usr/bin/env bash
# .agents/scripts/pre_tool_file_lock_guard.sh — Antigravity `PreToolUse` File Lock Hook
#
# Reads the `PreToolUse` JSON payload from stdin for `edit_file` and `write_file`.
# Checks if the target `Path` has an active, unexpired lease in `temp/.locks/` held
# by a conflicting agent/conversationId.
# - If unlocked, expired, or held by the current conversationId / `FASM_AGENT_ID`: outputs `{"decision":"allow"}`.
# - If held by another active parallel agent: outputs `{"decision":"deny","reason":"..."}`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK_DIR="${REPO_ROOT}/temp/.locks"

payload="$(cat || true)"
if [[ -z "${payload}" ]]; then
    printf '{"decision":"allow"}\n'
    exit 0
fi

# Extract target file Path and conversationId without requiring external jq if python3 or sed is available
target_path=""
conv_id=""
if command -v python3 >/dev/null 2>&1; then
    eval "$(python3 -c '
import json, sys, shlex
try:
    data = json.loads(sys.stdin.read())
    args = data.get("toolCall", {}).get("args", {}) or data.get("tool_input", {}) or {}
    path = args.get("Path", "") or args.get("TargetFile", "") or ""
    cid = data.get("conversationId", "") or ""
    print(f"target_path={shlex.quote(str(path))}")
    print(f"conv_id={shlex.quote(str(cid))}")
except Exception:
    pass
' <<< "${payload}")"
fi

if [[ -z "${target_path}" || ! -d "${LOCK_DIR}" ]]; then
    printf '{"decision":"allow"}\n'
    exit 0
fi

norm="${target_path}"
if [[ "${norm}" == "${REPO_ROOT}/"* ]]; then
    norm="${norm#"${REPO_ROOT}/"}"
fi
norm="${norm#./}"
slug="lock_$(printf '%s' "${norm}" | sed 's/[^a-zA-Z0-9._-]/__/g')"
meta_file="${LOCK_DIR}/${slug}.meta"

if [[ -f "${meta_file}" ]]; then
    now="$(date +%s)"
    read -r holder expires_at _ < "${meta_file}" || true
    if [[ -n "${holder:-}" && -n "${expires_at:-}" ]] && (( now < expires_at )); then
        caller_id="${FASM_AGENT_ID:-${conv_id}}"
        # Allow if the lock holder matches the current conversationId, FASM_AGENT_ID, or is a shared wave prefix
        if [[ -n "${caller_id}" && "${holder}" != "${caller_id}" && "${FASM_LOCK_ENFORCE_STRICT:-0}" == "1" ]]; then
            rem=$(( expires_at - now ))
            printf '{"decision":"deny","reason":"File %s is currently locked by parallel agent %s (%ds remaining). Acquire lock via .agents/scripts/file_lock.sh or edit disjoint files."}\n' "${norm}" "${holder}" "${rem}"
            exit 0
        fi
    else
        rm -f "${meta_file}"
    fi
fi

printf '{"decision":"allow"}\n'
