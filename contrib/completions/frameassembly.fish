# fish completion for frameassembly(1)
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
    and not contains -- "$tokens[2]" show reverse version help
    and not string match -qr '^-' -- "$tokens[2]"
end

function __fish_frameassembly_frasm_files
    __fish_complete_suffix .frasm
end

function __fish_frameassembly_pcap_files
    __fish_complete_suffix .pcap
    __fish_complete_suffix .pcapng
end

# Position 1: .frasm files/directories + 4 subcommands
complete -c frameassembly -n "__fish_frameassembly_pos1" -a "(__fish_frameassembly_frasm_files)"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a show -d "Validate a .frasm file and print a packet ladder table"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a reverse -d "Reverse a .pcap or .pcapng capture into .frasm code"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a version -d "Print the FrameAssembly version"
complete -c frameassembly -n "__fish_frameassembly_pos1" -a help -d "Print help for FrameAssembly or a subcommand"

# Default root command: frameassembly <input.frasm> [output.pcap]
complete -c frameassembly -n "__fish_frameassembly_default_output_arg" -a "(__fish_frameassembly_pcap_files)"

# show <input.frasm>
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg show 1" -a "(__fish_frameassembly_frasm_files)"

# reverse <input.pcap> [output.frasm]
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg reverse 1" -a "(__fish_frameassembly_pcap_files)"
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg reverse 2" -a "(__fish_frameassembly_frasm_files)"

# help [subcommand]
complete -c frameassembly -n "__fish_frameassembly_subcmd_arg help 1" -a "show reverse version help"
