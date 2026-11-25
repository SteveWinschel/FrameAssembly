# fish completion for frameassembly(1) — FrameAssembly v3.3.0
# https://github.com/SteveWinschel/FrameAssembly

complete -c frameassembly -f

function __fish_frameassembly_pos1
    set -l tokens (commandline -opc)
    test (count $tokens) -eq 1
end

function __fish_frameassembly_subcmd_arg
    set -l expected_sub $argv[1]
    set -l expected_arg_idx $argv[2]
    set -l tokens (commandline -opc)
    set -l expected_count (math 1 + $expected_arg_idx)
    test (count $tokens) -eq $expected_count; and test "$tokens[2]" = "$expected_sub"
end

function __fish_frameassembly_default_output_arg
    set -l tokens (commandline -opc)
    test (count $tokens) -eq 2
    and not contains -- "$tokens[2]" show reverse update version help
    and not string match -qr '^-.+' -- "$tokens[2]"
end

function __fish_frameassembly_frasm_files
    __fish_complete_suffix .frasm
end

function __fish_frameassembly_pcap_files
    __fish_complete_suffix .pcap
    __fish_complete_suffix .pcapng
end

function __fish_frameassembly_show_inputs
    __fish_complete_suffix .frasm
    __fish_complete_suffix .pcap
    __fish_complete_suffix .pcapng
end

function __fish_frameassembly_stdio_dash
    if test (commandline -ct) = "-"
        printf '%s\n' -
    end
end

# Position 1: .frasm files/directories, '-' (stdin), + 5 subcommands
complete -c frameassembly -n "__fish_frameassembly_pos1" -a "(__fish_frameassembly_frasm_files)"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a "(__fish_frameassembly_stdio_dash)" -d "Read .frasm code from stdin"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a show -d "Inspect a .frasm file or .pcap/.pcapng capture (or - for stdin)"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a reverse -d "Reverse a .pcap or .pcapng capture (or - for stdin) into .frasm code"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a update -d "Update frameassembly to the newest release"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a version -d "Print the FrameAssembly version"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a help -d "Print help for FrameAssembly or a subcommand"

# Default root command: frameassembly <input.frasm|-> [output.pcap|-]
complete -c frameassembly -n "__fish_frameassembly_default_output_arg" -a "(__fish_frameassembly_pcap_files)"
complete -c frameassembly -n "__fish_frameassembly_default_output_arg" -a "(__fish_frameassembly_stdio_dash)" -d "Write PCAPNG capture to stdout"

# show <input.frasm|capture.pcap|capture.pcapng|->
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg show 1" -a "(__fish_frameassembly_show_inputs)"
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg show 1" -a "(__fish_frameassembly_stdio_dash)" -d "Read .frasm or capture from stdin"

# reverse <input.pcap|-> [output.frasm|-]
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg reverse 1" -a "(__fish_frameassembly_pcap_files)"
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg reverse 1" -a "(__fish_frameassembly_stdio_dash)" -d "Read capture from stdin"
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg reverse 2" -a "(__fish_frameassembly_frasm_files)"
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg reverse 2" -a "(__fish_frameassembly_stdio_dash)" -d "Write .frasm code to stdout"

# help [subcommand]
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg help 1" -a "show reverse update version help"
