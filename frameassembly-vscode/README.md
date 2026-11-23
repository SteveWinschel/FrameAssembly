# FrameAssembly (`.frasm` v3.2.2) — Syntax Highlighting & Live Linter

[**CLI & Releases (`GitHub`)**](https://github.com/SteveWinschel/FrameAssembly) • [**Crates.io (`cargo install frameassembly`)**](https://crates.io/crates/frameassembly) • [**Documentation**](https://frameassembly-lang.dev/docs) • [**Use Cases**](https://frameassembly-lang.dev/use-cases)

Official syntax highlighting and live error linting for [**FrameAssembly**](https://github.com/SteveWinschel/FrameAssembly) (`.frasm` v3.2.2) **Packets as Code** files across all 81 Layer 2 through Layer 7 network protocols.

Built for network engineers, firewall administrators, SOC/NDR analysts, pentesters, and OT/SCADA integrators writing `.frasm` traffic scenarios for **Wireshark**, **`tshark`**, **`tcpreplay`**, **Suricata**, **Zeek**, **Checkmk**, and **Zabbix**.

---

## What This Extension Does

This extension stays out of your way—no toolbar buttons, side panels, or startup popups—and focuses strictly on two jobs:

1. **Syntax Highlighting (`.frasm` & Markdown Runbooks):**
   * Highlights `host`, `flow`, and `compile` blocks, all 81 protocol keywords, protocol modifiers, IPv4/IPv6 addresses, IEEE/Cisco MAC formats (`00:1a:2b:3c:4d:5e`, `00-1A-2B-3C-4D-5E`, `001a.2b3c.4d5e`), SNMP OIDs, hex values, and post-packet `wait` durations (`ns`, `us`, `ms`, `s`, `m`) using the dedicated `source.frameassembly` (`text/vnd.frameassembly`) grammar so x86 Flat Assembler (`;` comments) and FPGA bitstream (`#` comments) extensions never collide with your packet files.
   * Highlights fenced ```` ```frameassembly ```` and ```` ```frasm ```` code blocks inside Markdown documentation and incident runbooks (`markdown.frameassembly.codeblock`).
   * Configures `//` line-comment toggling (`Ctrl+/` / `Cmd+/`) and safe `{...}`, `(...)`, and `"..."` auto-closing pairs without inserting unsupported `'single quotes'` or `[brackets]`.
   * Displays the `.frasm` Explorer and editor-tab language file icon (`icons/frasm.svg`) alongside the `256x256` rounded-square FrameAssembly brand icon (`icon.png`).

2. **Live In-Editor Linting & 1-Click Typo Quick Fixes:**
   * Validates `.frasm` code in memory as you type using the embedded WebAssembly validator—flagging unknown keywords, out-of-range ports or VLAN IDs, mixed IPv4/IPv6 endpoints, invalid transport modifiers, and missing host declarations with red squiggles in the Problems panel.
   * Pasted an older snippet with uppercase or underscored keywords such as `ECHO_REQUEST`, `inner_vlan`, or `sport`? Press `Ctrl+.` / `Cmd+.` (or click the lightbulb) for a **1-click Quick Fix** to replace it with the valid lowercase keyword (`echorequest`, `innervlan`, `srcport`).

3. **Restricted Mode & Browser Editor Ready:**
   * Runs strictly read-only in memory—it never writes files, spawns shell processes, or opens network connections.
   * Works immediately in **VS Code Restricted Mode** (untrusted folders of downloaded captures), **VS Code for the Web (`vscode.dev` / `github.dev`)**, **Cursor**, **Windsurf**, **VSCodium**, and **Antigravity IDE**.

> **Upgrading from FrameAssembly 2.x?** FrameAssembly 3.x uses the `.frasm` file extension instead of `.fasm`. Rename existing files to `.frasm`.

---

## Installing the `frameassembly` CLI (Compile & Reverse Captures)

To compile `.frasm` code into `.pcap` or `.pcapng` packet captures, inspect the packet ladder in your terminal, or reverse existing `.pcap` / `.pcapng` captures back into `.frasm` code, install the companion `frameassembly` CLI.

**Recommended install via Cargo (Windows, macOS, and Linux):**

```sh
cargo install frameassembly
```

Prebuilt standalone archives, Debian/Ubuntu `.deb` packages, and `install.sh` / `install.ps1` installer scripts are also available on [**GitHub Releases**](https://github.com/SteveWinschel/FrameAssembly/releases/latest).

Once installed, run `frameassembly` from your terminal:

```sh
# Compile demo.frasm -> demo.pcap (classic libpcap) or pass demo.pcapng for nanosecond PCAPNG
frameassembly demo.frasm
frameassembly demo.frasm demo.pcapng

# Print the packet ladder table in the terminal without writing a file
frameassembly show demo.frasm

# Reverse an existing .pcap or .pcapng capture into .frasm code
frameassembly reverse capture.pcap

# Self-update frameassembly with zero flags (Cargo/rustup-first, or SHA-256-verified GitHub Release binary fallback)
# All 5 subcommands: show, reverse, update, help, version
frameassembly update
frameassembly help
frameassembly version
```

---

## Example `.frasm` Workflows

Note that `wait <duration>` sets the post-packet delay **after** that frame is sent (defaulting to `10ms` when omitted), so the final frame in a sequence needs no trailing `wait`.

### Simulating Encrypted `SNMPv3` `authPriv` Traps & `Syslog` Alerts (`Checkmk`, `Zabbix`, `PRTG`)

Test whether **Checkmk**, **Zabbix**, **PRTG**, **LibreNMS**, or `snmptrapd` triggers an alert without pulling fiber on a live switch:

```frameassembly
// SNMPv3 authPriv linkDown trap + RFC 5424 Syslog alert (5ms later)
host core_sw { ip 10.10.1.2  mac 001a.2b3c.4d01 }
host zabbix  { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow link_down_alert(sw, nms) {
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8880510001" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms
    sw -> nms vlan 100 syslog facility 16 severity 3 hostname "core-sw-01" app "link" msg "Gi0/1 changed state to down"
}

compile { link_down_alert(core_sw, zabbix) }
```

### Testing Shadow IT, NDR Policies & Stateful IDS Rules (`Suricata`, `Zeek`, `Snort`)

Stateful firewalls and IDS sensors ignore mid-stream packets without a valid 3-way TCP handshake and advancing sequence numbers. FrameAssembly tracks 4-tuple `seq` and `acknum` counters automatically across `tcp` and Layer 7 frames:

```frameassembly
// Stateful DNS lookup + Shadow IT TLS SNI policy test
host workstation { ip 10.40.5.25 mac 00:50:56:40:05:25 }
host sec_gateway { ip 10.40.5.1  mac 00:1c:73:40:05:01 }

flow shadow_it_policy_check(ws, gw) {
    ws -> gw dns query txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "a" wait 1ms
    ws <- gw dns response txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "a" rcode 5 wait 2ms
    ws -> gw tcp syn srcport 53443 dstport 443 win 65535 mss 1460 wait 1ms
    ws <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    ws -> gw tcp ack wait 1ms
    ws -> gw tls clienthello sni "shadow-upload.example.net" ciphersuite 4866 alpn "h2" wait 2ms
    ws <- gw tls alert payload "BLOCKED_BY_SNI_POLICY"
}

compile {
    shadow_it_policy_check(workstation, sec_gateway)
}
```

### Verifying `802.1Q` `VLAN`, `802.1ad` `QinQ` & Industrial OT / SCADA Rules (`Modbus`, `DNP3`)

Generate carrier `QinQ` double tags, `DSCP` markings, and SCADA register polls offline without touching production PLCs or fighting NIC VLAN tag stripping:

```frameassembly
// VLAN-tagged Modbus/TCP register poll + DNP3 read request
host scada_hmi { ip 172.22.10.5  mac 00:1b:21:22:0a:05 }
host field_plc { ip 172.22.10.50 mac 00:0e:8c:22:0a:32 }

flow ot_conduit_audit(hmi, plc) {
    hmi -> plc vlan 110 tcp syn srcport 54000 dstport 502 win 64240 mss 1460 wait 1ms
    hmi <- plc vlan 110 tcp syn ack win 64240 mss 1460 wait 1ms
    hmi -> plc vlan 110 tcp ack wait 2ms
    hmi -> plc vlan 110 modbus readholdingregisters txid 1 unitid 1 addr 100 count 2 wait 2ms
    hmi <- plc vlan 110 modbus readholdingregisters txid 1 unitid 1 count 2 value 42 isresponse wait 5ms
    hmi -> plc vlan 110 dnp3 read src 1 dst 10 group 60 variation 1
}

compile { ot_conduit_audit(scada_hmi, field_plc) }
```

---

## Protocol Coverage (81 Native Protocols)

All built-in keywords, protocols, modifiers, and duration units (`ns`, `us`, `ms`, `s`, `m`) in FrameAssembly 3.2.2 use lowercase without `_` or `-` (`echorequest`, `innervlan`, `clienthello`, `readholdingregisters`):

| OSI Layer | Count | Native Protocol Keywords |
| :--- | :---: | :--- |
| **Layer 2 (Switching & Data Link)** | 8 | `arp`, `vlan` (802.1Q), `qinq` (802.1ad), `mpls`, `lldp`, `stp`, `lacp`, `eapol` (802.1X) |
| **Layer 3 (Control, Tunnel, VPN, Routing)** | 20 | `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow` |
| **Layer 4 (Transport)** | 3 | `tcp`, `udp`, `sctp` |
| **Layer 7 (SNMP, Infra, AAA, Telemetry)** | 14 | `snmp1`, `snmp2`, `snmp3`, `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow` |
| **Layer 7 (Web, Cloud, TLS, VoIP, Access)** | 16 | `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp` |
| **Layer 7 (Mail, Auth, Storage, DB, Brokers)** | 14 | `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp` |
| **Layer 7 (Industrial ICS / SCADA / OT)** | 6 | `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua` |

## License

MIT License. Copyright (c) 2026 [Steve Winschel](https://github.com/SteveWinschel/FrameAssembly).
