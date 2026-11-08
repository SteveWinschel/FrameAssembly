#!/usr/bin/env bash
# .agents/scripts/file_lock.sh — Atomic Multi-Agent File Lock & Lease Manager
#
# Provides kernel-backed POSIX `flock(2)` and TTL lease locking in `temp/.locks/`
# so parallel AI coding agents (`DeepCoder`, `self`, `teamwork`) can coordinate
# concurrent file edits and serialize shared Cargo target-directory commands.
#
# Usage:
#   .agents/scripts/file_lock.sh acquire <agent_id> <ttl_sec> <file_or_resource>...
#   .agents/scripts/file_lock.sh release <agent_id> <file_or_resource>...
#   .agents/scripts/file_lock.sh check <file_or_resource>...
#   .agents/scripts/file_lock.sh exec <file_or_resource> [--] <command> [args...]
#   .agents/scripts/file_lock.sh status
#   .agents/scripts/file_lock.sh gc

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK_DIR="${REPO_ROOT}/temp/.locks"
mkdir -p "${LOCK_DIR}"

normalize_target() {
    local raw="$1"
    if [[ "${raw}" == "${REPO_ROOT}/"* ]]; then
        raw="${raw#"${REPO_ROOT}/"}"
    fi
    raw="${raw#./}"
    printf '%s' "${raw}"
}

target_slug() {
    local norm
    norm="$(normalize_target "$1")"
    printf 'lock_%s' "${norm}" | sed 's/[^a-zA-Z0-9._-]/__/g'
}

now_epoch() {
    date +%s
}

cmd="${1:-status}"
shift || true

case "${cmd}" in
    acquire)
        if [[ $# -lt 3 ]]; then
            echo "Usage: $0 acquire <agent_id> <ttl_sec> <file_or_resource>..." >&2
            exit 1
        fi
        agent_id="$1"
        ttl_sec="$2"
        shift 2

        # Sort targets deterministically to prevent AB-BA deadlocks across multi-file acquisitions
        mapfile -t sorted_targets < <(for t in "$@"; do normalize_target "$t"; echo; done | sort -u)
        acquired_slugs=()

        for norm in "${sorted_targets[@]}"; do
            [[ -z "${norm}" ]] && continue
            slug="$(target_slug "${norm}")"
            flock_file="${LOCK_DIR}/${slug}.flock"
            meta_file="${LOCK_DIR}/${slug}.meta"

            if ! (
                flock -x -w "${LOCK_WAIT_SEC:-10}" 200 || exit 2
                now="$(now_epoch)"
                if [[ -f "${meta_file}" ]]; then
                    read -r holder expires_at target_path < "${meta_file}" || true
                    if [[ -n "${holder:-}" && -n "${expires_at:-}" ]] && (( now < expires_at )) && [[ "${holder}" != "${agent_id}" ]]; then
                        rem=$(( expires_at - now ))
                        echo "LOCK_CONFLICT: '${norm}' is locked by agent '${holder}' (${rem}s remaining)" >&2
                        exit 2
                    fi
                fi
                expires=$(( now + ttl_sec ))
                printf '%s %s %s\n' "${agent_id}" "${expires}" "${norm}" > "${meta_file}"
            ) 200>"${flock_file}"; then
                # Roll back any locks acquired earlier in this batch
                for prev_slug in "${acquired_slugs[@]}"; do
                    rm -f "${LOCK_DIR}/${prev_slug}.meta"
                done
                exit 2
            fi
            acquired_slugs+=("${slug}")
        done
        echo "LOCK_ACQUIRED: agent='${agent_id}' ttl=${ttl_sec}s count=${#acquired_slugs[@]}"
        ;;

    release)
        if [[ $# -lt 2 ]]; then
            echo "Usage: $0 release <agent_id> <file_or_resource>..." >&2
            exit 1
        fi
        agent_id="$1"
        shift
        released=0
        for raw in "$@"; do
            norm="$(normalize_target "${raw}")"
            slug="$(target_slug "${norm}")"
            flock_file="${LOCK_DIR}/${slug}.flock"
            meta_file="${LOCK_DIR}/${slug}.meta"
            (
                flock -x -w 5 200 || exit 0
                if [[ -f "${meta_file}" ]]; then
                    read -r holder _ _ < "${meta_file}" || true
                    if [[ "${holder:-}" == "${agent_id}" || "${agent_id}" == "FORCE" ]]; then
                        rm -f "${meta_file}"
                    fi
                fi
            ) 200>"${flock_file}"
            released=$(( released + 1 ))
        done
        echo "LOCK_RELEASED: agent='${agent_id}' count=${released}"
        ;;

    check)
        if [[ $# -lt 1 ]]; then
            echo "Usage: $0 check <file_or_resource>..." >&2
            exit 1
        fi
        now="$(now_epoch)"
        for raw in "$@"; do
            norm="$(normalize_target "${raw}")"
            slug="$(target_slug "${norm}")"
            meta_file="${LOCK_DIR}/${slug}.meta"
            if [[ -f "${meta_file}" ]]; then
                read -r holder expires_at _ < "${meta_file}" || true
                if [[ -n "${holder:-}" && -n "${expires_at:-}" ]] && (( now < expires_at )); then
                    rem=$(( expires_at - now ))
                    echo "LOCKED: '${norm}' holder='${holder}' remaining=${rem}s"
                    exit 2
                else
                    rm -f "${meta_file}"
                fi
            fi
        done
        echo "UNLOCKED"
        ;;

    exec)
        if [[ $# -lt 2 ]]; then
            echo "Usage: $0 exec <file_or_resource> [--] <command> [args...]" >&2
            exit 1
        fi
        resource="$1"
        shift
        [[ "${1:-}" == "--" ]] && shift
        slug="$(target_slug "${resource}")"
        flock_file="${LOCK_DIR}/${slug}.flock"
        exec 200>"${flock_file}"
        flock -x -w "${LOCK_TIMEOUT_SEC:-120}" 200
        "$@"
        ;;

    gc)
        now="$(now_epoch)"
        removed=0
        shopt -s nullglob
        for meta_file in "${LOCK_DIR}"/*.meta; do
            read -r _ expires_at _ < "${meta_file}" || true
            if [[ -z "${expires_at:-}" ]] || (( now >= expires_at )); then
                rm -f "${meta_file}"
                removed=$(( removed + 1 ))
            fi
        done
        echo "LOCK_GC: removed=${removed}"
        ;;

    status)
        now="$(now_epoch)"
        active=0
        shopt -s nullglob
        for meta_file in "${LOCK_DIR}"/*.meta; do
            read -r holder expires_at target_path < "${meta_file}" || true
            if [[ -n "${holder:-}" && -n "${expires_at:-}" ]] && (( now < expires_at )); then
                rem=$(( expires_at - now ))
                printf 'ACTIVE_LOCK\tagent=%s\tremaining=%ss\tpath=%s\n' "${holder}" "${rem}" "${target_path}"
                active=$(( active + 1 ))
            else
                rm -f "${meta_file}"
            fi
        done
        if (( active == 0 )); then
            echo "NO_ACTIVE_LOCKS"
        fi
        ;;

    *)
        echo "Unknown subcommand: ${cmd} (expected: acquire | release | check | exec | status | gc)" >&2
        exit 1
        ;;
esac
