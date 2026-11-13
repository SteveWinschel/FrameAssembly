# bash completion for frameassembly(1)                     -*- shell-script -*-
# https://github.com/SteveWinschel/FrameAssembly

_frameassembly_complete_files() {
    local cur="$1"
    local mode="$2"
    local item lower

    compopt -o filenames 2>/dev/null || true
    COMPREPLY=()

    while IFS= read -r item; do
        [ -z "$item" ] && continue
        if [ -d "$item" ]; then
            COMPREPLY+=("$item")
            continue
        fi
        lower="$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')"
        case "$mode" in
            frasm)
                case "$lower" in
                    *.frasm) COMPREPLY+=("$item") ;;
                esac
                ;;
            pcap)
                case "$lower" in
                    *.pcap|*.pcapng) COMPREPLY+=("$item") ;;
                esac
                ;;
        esac
    done < <(compgen -f -- "$cur")
}

_frameassembly() {
    local cur subcmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ "$COMP_CWORD" -eq 1 ]; then
        _frameassembly_complete_files "$cur" "frasm"
        # shellcheck disable=SC2207
        COMPREPLY+=($(compgen -W "show reverse version help" -- "$cur"))
        return 0
    fi

    subcmd="${COMP_WORDS[1]}"
    case "$subcmd" in
        show)
            if [ "$COMP_CWORD" -eq 2 ]; then
                _frameassembly_complete_files "$cur" "frasm"
            fi
            ;;
        reverse)
            case "$COMP_CWORD" in
                2) _frameassembly_complete_files "$cur" "pcap" ;;
                3) _frameassembly_complete_files "$cur" "frasm" ;;
            esac
            ;;
        help)
            if [ "$COMP_CWORD" -eq 2 ]; then
                compopt +o filenames 2>/dev/null || true
                # shellcheck disable=SC2207
                COMPREPLY=($(compgen -W "show reverse version help" -- "$cur"))
            fi
            ;;
        version|-*)
            COMPREPLY=()
            ;;
        *)
            if [ "$COMP_CWORD" -eq 2 ]; then
                _frameassembly_complete_files "$cur" "pcap"
            fi
            ;;
    esac
    return 0
}

complete -F _frameassembly frameassembly
