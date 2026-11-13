# Step 1: Create a `.frasm` file

FrameAssembly turns **Packets as Code** into `.pcap` captures. Everything lives in a `.frasm` file with three kinds of blocks: `host` (who talks), `flow` (an optional reusable conversation), and one `compile` block (what gets written to the capture).

1. Create a new file and save it as `demo.frasm`.
2. Type `frasm` and press `Tab` to insert a complete skeleton, or paste this ping:

```frameassembly
host client { ip 10.0.0.10 mac 00:1a:2b:3c:4d:01 }
host server { ip 10.0.0.20 mac 00:1a:2b:3c:4d:02 }

compile {
    client -> server icmp echorequest id 1 seq 1
    client <- server icmp echoreply id 1 seq 1 wait 2ms
}
```

Each statement inside `compile` becomes exactly one Ethernet frame. Checksums, TCP sequence numbers, and multicast MAC addresses are filled in for you.

Press `Ctrl+Space` for autocomplete across all 81 protocols. If you paste an older snippet with `echo_request` or `ECHO_REQUEST`, use the lightbulb (`Ctrl+.`) for a one-click fix to the lowercase keyword.

> Files written for FrameAssembly 2.x used the `.fasm` extension. Rename them to `.frasm`; the code inside is unchanged.
