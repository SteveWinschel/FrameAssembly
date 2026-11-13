# SNMPv1, SNMPv2c & Encrypted SNMPv3

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

SNMPv3 `authPriv` fails quietly. One wrong hex `engineid`, a stale `engineboots` counter, or an `enginetime` outside the 150-second window, and the receiver drops the trap without a log line. Checkmk, Zabbix, and LibreNMS stay a cheerful green while the switch in the back row cooks itself. Nobody finds out until someone walks past and feels the heat.

The usual way to test this is `snmptrap` with fourteen positional flags, a MIB directory that half-loads, and a lab switch you pull a cable out of. With FrameAssembly you write the trap as `.frasm` code, pass the plain passphrases, and the compiler localizes the keys against the `engineid`, encrypts the `scopedPDU`, and signs the packet. No MIB files are involved: OIDs are numeric, values are typed by name.

```console
$ frameassembly show snmp_alert.frasm
$ frameassembly snmp_alert.frasm snmp_alert.pcap && sudo tcpreplay -i eth0 snmp_alert.pcap
```

## 1. Encrypted `snmp3` `authPriv` Traps and `inform` Alerts

A trap with SHA-256 authentication and AES-128 encryption, sent to Zabbix on VLAN 100. Every `snmp3` trap carries `sysuptime` and `oid`; the compiler prepends `sysUpTime.0` and `snmpTrapOID.0` as the first two varbinds for you.

```frameassembly
host core_sw { ip 10.10.1.2  mac 00:1a:2b:3c:4d:01 }
host zabbix  { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow authpriv_trap(sw, nms) {
    // linkDown for ifIndex 1, encrypted. Wireshark steps below use these exact credentials.
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8801" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" sysuptime 432005 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2
}

compile { authpriv_trap(core_sw, zabbix) }
```

Traps are fire-and-forget. If the collector must acknowledge, use `inform` and the matching `response`. Both share a `reqid`, and the `contextname` is where per-VRF or per-VLAN MIB views live:

```frameassembly
host core_rtr { ip 10.151.0.1   mac 00:25:90:51:00:01 }
host nms_srv  { ip 10.151.0.250 mac 00:25:90:51:00:fa }

flow acknowledged_inform(rtr, nms) {
    // BGP peer state change, SHA-512 + AES-128, delivered to UDP 162 and acknowledged
    rtr -> nms dscp 16 snmp3 inform dstport 162 user "ops_v3" engineid "80001f8880510001" engineboots 30 enginetime 400001 contextname "core-fabric" auth sha512 "HighSecSha512!" priv aes "HighSecAes128!" reqid 9702 sysuptime 40000100 oid 1.3.6.1.2.1.15.7.2 varbind 1.3.6.1.2.1.15.3.1.2.198.51.100.2 int 1 wait 2ms
    rtr <- nms dscp 16 snmp3 response user "ops_v3" engineid "80001f8880510001" engineboots 30 enginetime 400001 contextname "core-fabric" auth sha512 "HighSecSha512!" priv aes "HighSecAes128!" reqid 9702 varbind 1.3.6.1.2.1.15.3.1.2.198.51.100.2 int 1
}

compile { acknowledged_inform(core_rtr, nms_srv) }
```

A plain `trap` follows the same pattern (`trap` instead of `inform`, no reply). Set `dscp 16` if your network marks management traffic and you want to see whether the NMS queue survives it.

### Decrypting the Capture in Wireshark

Decrypting is the quickest way to prove the packet is what you meant to send.

```bash
tshark -r snmp_alert.pcap \
  -o 'uat:snmp_users:"80001f8801","netops","SHA2-256","AuthPass123!","AES","PrivPass123!"' \
  -V
```

In the Wireshark GUI: Edit > Preferences > Protocols > SNMP > Users Table > Edit. Add the **Engine ID** (`80001f8801`, or leave it blank to match every engine), the **Username** (`netops`), the **Auth model** (`SHA2-256`, `SHA2-384`, `SHA2-512`, `SHA1`, or `MD5`), the **Auth password**, the **Priv protocol** (`AES` or `DES`), and the **Priv password**. The `encryptedPDU` unlocks and the packet shows `[Authentication OK]`.

## 2. `linkDown` / `linkUp` Flap Storms and Alert Throttling

The first time you learn that one flapping port sends 500 Slack messages should not be during a real fiber cut. Put a down/up pair in a flow, call it three times in `compile`, and watch how the trap daemon and the deduplication rules cope. The `wait 50ms` spacing is the knob to turn if you want it meaner.

```frameassembly
host flapping_sw { ip 10.125.0.10  mac 00:1c:73:25:00:10 }
host trap_sink   { ip 10.125.0.250 mac 00:1c:73:25:00:fa }

flow link_flap_cycle(sw, sink) {
    sw -> sink snmp2 trap community "noc_traps" reqid 6001 sysuptime 300100 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.2.10 string "Ethernet10" varbind 1.3.6.1.2.1.2.2.1.8.10 int 2 varbind 1.3.6.1.2.1.2.2.1.5.10 gauge32 0 wait 50ms
    sw -> sink snmp2 trap community "noc_traps" reqid 6002 sysuptime 300105 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.2.2.1.2.10 string "Ethernet10" varbind 1.3.6.1.2.1.2.2.1.8.10 int 1 varbind 1.3.6.1.2.1.2.2.1.5.10 gauge32 1000000000 wait 50ms
}

compile {
    link_flap_cycle(flapping_sw, trap_sink)
    link_flap_cycle(flapping_sw, trap_sink)
    link_flap_cycle(flapping_sw, trap_sink)
}
```

Replay the result at line rate (`sudo tcpreplay -i eth0 --topspeed snmp_alert.pcap`) to see where the collector's queue gives up. A collector that survives 500 identical traps in a second is rarer than you would hope.

## 3. 400G `counter64` Polls, Optical `dBm` Readings and VRF Contexts

Prometheus `snmp_exporter` parsers, custom NMS templates, and 64-bit counter-wrap graphs all need realistic poll answers. Producing them normally means a spine switch with 400G optics in the lab.

A `getbulk` for one scalar plus the repeating high-capacity counter rows, answered with `counter64`, `gauge32`, and an optical level of -7 dBm:

```frameassembly
host poller    { ip 10.156.0.10 mac 00:1b:54:56:00:10 }
host pe_router { ip 10.156.0.1  mac 00:1b:54:56:00:01 }

flow poll_400g_counters(nms, pe) {
    // nonrepeaters 1 fetches sysUpTime.0 once; the ifHCInOctets column repeats up to 10 times
    nms -> pe snmp2 getbulk community "telemetry_ro" reqid 7001 nonrepeaters 1 maxrepetitions 10 varbind 1.3.6.1.2.1.1.3.0 null varbind 1.3.6.1.2.1.31.1.1.1.6 null wait 2ms
    nms <- pe snmp2 response community "telemetry_ro" reqid 7001 varbind 1.3.6.1.2.1.1.3.0 timeticks 8640000 varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.30065.1.3011 varbind 1.3.6.1.2.1.31.1.1.1.1.1 string "Ethernet1/1" varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 2199023255552 varbind 1.3.6.1.2.1.2.2.1.14.1 counter32 0 varbind 1.3.6.1.2.1.31.1.1.1.15.1 gauge32 400000 varbind 1.3.6.1.4.1.9.9.91.1.1.1.1.4.1 int -7
}

compile { poll_400g_counters(poller, pe_router) }
```

The same router polled through an SNMPv3 context, so a PCI-scoped VRF returns its own routing table and not the global one:

```frameassembly
host poller    { ip 10.156.0.10 mac 00:1b:54:56:00:10 }
host pe_router { ip 10.156.0.1  mac 00:1b:54:56:00:01 }

flow poll_vrf_context(nms, pe) {
    nms -> pe snmp3 get user "vrf_auditor" engineid "800000090300001b54560001" engineboots 10 enginetime 80000 contextname "vrf-pci" auth sha256 "VrfAuthKey!" priv aes "VrfPrivKey!" reqid 7002 varbind 1.3.6.1.2.1.4.21.1.7.0.0.0.0 null wait 2ms
    nms <- pe snmp3 response user "vrf_auditor" engineid "800000090300001b54560001" engineboots 10 enginetime 80000 contextname "vrf-pci" auth sha256 "VrfAuthKey!" priv aes "VrfPrivKey!" reqid 7002 varbind 1.3.6.1.2.1.4.21.1.7.0.0.0.0 ipval 172.31.254.1
}

compile { poll_vrf_context(poller, pe_router) }
```

### The 9 `varbind` Types

Chain as many `varbind <oid> <type> [value]` entries onto one statement as you need. OIDs are written numerically.

| Type Keyword | Example | Notes |
| :--- | :--- | :--- |
| `null` / `nullval` | `varbind 1.3.6.1.2.1.1.1.0 null` | Empty placeholder in `get`, `getnext`, and `getbulk` requests |
| `string "<text>"` | `varbind 1.3.6.1.2.1.1.5.0 string "core-sw"` | Hostnames, interface names, serial numbers, status text |
| `int <-2B..2B>` | `varbind 1.3.6.1.2.1.2.2.1.8.1 int 2` | Signed 32-bit integer: `1` up, `2` down, or negative readings such as `-18` dBm or `-15` °C |
| `timeticks <u32>` | `varbind 1.3.6.1.2.1.1.3.0 timeticks 8640000` | Hundredths of a second (`8640000` is 24 hours) |
| `ipval <ip>` | `varbind 1.3.6.1.2.1.4.20.1.1.10.0.0.1 ipval 10.0.0.1` | IPv4 `IpAddress` or a 16-byte IPv6 `InetAddress` (`2001:db8::1`) |
| `oidval <oid>` | `varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.9.1.1` | A value that is itself an OID, such as `sysObjectID.0` |
| `counter32 <u32>` | `varbind 1.3.6.1.2.1.2.2.1.10.1 counter32 459012` | Wrapping 32-bit packet, byte, or error counter |
| `gauge32 <u32>` | `varbind 1.3.6.1.2.1.2.2.1.5.1 gauge32 1000000000` | Non-wrapping 32-bit value: link speed, CPU percent, PoE watts, queue depth |
| `counter64 <u64>` | `varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 98765432100` | 64-bit counter (`ifHCInOctets`, `ifHCOutOctets`); `snmp2` and `snmp3` only |

### OIDs You Will Otherwise Google

| Object or Trap | OID | Typical Type | Common Values |
| :--- | :--- | :--- | :--- |
| `sysDescr.0` / `sysObjectID.0` | `1.3.6.1.2.1.1.1.0` / `1.3.6.1.2.1.1.2.0` | `string` / `oidval` | OS version banner / vendor model OID |
| `sysUpTime.0` | `1.3.6.1.2.1.1.3.0` | `timeticks` | Uptime in hundredths of a second |
| `sysContact.0` / `sysName.0` / `sysLocation.0` | `1.3.6.1.2.1.1.4.0` / `.5.0` / `.6.0` | `string` | Admin email, hostname, rack location |
| `ifIndex.<n>` / `ifDescr.<n>` | `1.3.6.1.2.1.2.2.1.1.<n>` / `.2.<n>` | `int` / `string` | Port index (`1`, `2`) / name (`"Gi0/1"`) |
| `ifAdminStatus.<n>` / `ifOperStatus.<n>` | `1.3.6.1.2.1.2.2.1.7.<n>` / `.8.<n>` | `int` | `1` up, `2` down, `3` testing |
| `ifHCInOctets.<n>` / `ifHCOutOctets.<n>` | `1.3.6.1.2.1.31.1.1.1.6.<n>` / `.10.<n>` | `counter64` | 64-bit inbound / outbound byte counters |
| `coldStart` / `warmStart` | `1.3.6.1.6.3.1.1.5.1` / `1.3.6.1.6.3.1.1.5.2` | Trap `oid` | Device rebooted / SNMP agent restarted |
| `linkDown` / `linkUp` | `1.3.6.1.6.3.1.1.5.3` / `1.3.6.1.6.3.1.1.5.4` | Trap `oid` | Interface went down / came back up |
| `authenticationFailure` | `1.3.6.1.6.3.1.1.5.5` | Trap `oid` | Bad community string or unauthorized poll |

## 4. Rogue `set` Requests, EngineID Probes and IDS Rules

`"public"` and `"private"` are still the most productive words in an internal pentest. This capture gives Suricata, Zeek, or the SIEM something to chew on: an unauthenticated SNMPv3 EngineID discovery probe, then an SNMPv2c `set` that admin-downs port 24, then the `authenticationFailure` trap the switch would send.

Discovery probe and the agent's answer (empty `user`, zero engine values, and a `usmStatsUnknownEngineIDs` counter in the reply):

```frameassembly
host rogue_scanner { ip 192.168.66.13 mac 00:0c:29:66:00:13 }
host access_sw     { ip 192.168.66.1  mac 00:1c:73:66:00:01 }

flow engineid_probe(attacker, sw) {
    attacker -> sw snmp3 get user "" engineid "0000000000" engineboots 0 enginetime 0 reqid 8001 wait 2ms
    attacker <- sw snmp3 response user "" engineid "80001f8880660001" engineboots 4 enginetime 9200 reqid 8001 varbind 1.3.6.1.6.3.15.1.1.4.0 counter32 1 wait 5ms
}

compile { engineid_probe(rogue_scanner, access_sw) }
```

The rogue write and the SecOps alert it should trigger:

```frameassembly
host rogue_scanner { ip 192.168.66.13 mac 00:0c:29:66:00:13 }
host access_sw     { ip 192.168.66.1  mac 00:1c:73:66:00:01 }
host secops_siem   { ip 10.104.0.99   mac 00:19:56:00:01:99 }

flow rogue_set(attacker, sw, siem) {
    // ifAdminStatus.24 = 2 (down), using the default write community
    attacker -> sw snmp2 set community "private" reqid 8002 varbind 1.3.6.1.2.1.2.2.1.7.24 int 2 wait 2ms
    attacker <- sw snmp2 response community "private" reqid 8002 varbind 1.3.6.1.2.1.2.2.1.7.24 int 2 wait 5ms
    // SNMPv1 authenticationFailure trap (gentrap 4) to the SIEM
    sw -> siem snmp1 trap community "sec_trap" enterprise 1.3.6.1.4.1.9.1 agentip 192.168.66.1 gentrap 4 spectrap 0 sysuptime 543210 varbind 1.3.6.1.4.1.9.2.1.5.0 ipval 192.168.66.13 varbind 1.3.6.1.4.1.9.2.1.6.0 string "bad_community_attempt"
}

compile { rogue_set(rogue_scanner, access_sw, secops_siem) }
```

```console
$ frameassembly snmp_ids.frasm snmp_ids.pcap && suricata -r snmp_ids.pcap -k none
```

## 5. Legacy `snmp1` Gear, `md5`/`des`, Carrier `qinq` + `mpls` and IPv6

Every network has one UPS management card, one laser printer, or one branch CPE that has never heard of anything newer than SNMPv1. Some of them also sit behind a carrier backhaul. An SNMPv1 enterprise trap for "on battery" (`gentrap 6`, `spectrap 1`):

```frameassembly
host ups_card { ip 10.145.40.5   mac 00:1a:2b:91:40:05 }
host noc_srv  { ip 10.145.40.100 mac 00:1a:2b:91:40:64 }

flow ups_on_battery(agent, nms) {
    agent -> nms snmp1 trap community "ups_traps" enterprise 1.3.6.1.2.1.33.2 agentip 10.145.40.5 gentrap 6 spectrap 1 sysuptime 9912400 varbind 1.3.6.1.2.1.33.1.2.3.0 int 28
}

compile { ups_on_battery(ups_card, noc_srv) }
```

Legacy SNMPv3 with MD5 and DES, wrapped in QinQ (outer 800, inner 162) and MPLS label 7300:

```frameassembly
host ups_card { ip 10.145.40.5   mac 00:1a:2b:91:40:05 }
host noc_srv  { ip 10.145.40.100 mac 00:1a:2b:91:40:64 }

flow legacy_v3_over_carrier(agent, nms) {
    agent -> nms qinq 800 innervlan 162 mpls 7300 snmp3 trap user "legacy_ups" engineid "80001f8880aa11bb22" engineboots 4 enginetime 12000 auth md5 "LegacyMd5Key!" priv des "LegacyDesKey!" oid 1.3.6.1.6.3.1.1.5.3 sysuptime 1200000 varbind 1.3.6.1.2.1.2.2.1.2.3 string "FastEthernet0/3"
}

compile { legacy_v3_over_carrier(ups_card, noc_srv) }
```

The same flows work unchanged over IPv6. On an IPv6 path the SNMPv1 `agent-addr` field is set to `0.0.0.0` automatically, as RFC 3584 requires:

```frameassembly
host v6_agent     { ip 2001:db8:3::1 }
host v6_collector { ip 2001:db8:3::2 }

flow ipv6_snmp_traps(a6, n6) {
    a6 -> n6 snmp1 trap community "public" enterprise 1.3.6.1.4.1.318 gentrap 6 spectrap 5 sysuptime 90000 varbind 1.3.6.1.2.1.1.5.0 string "ups-row4-v6" wait 5ms
    a6 -> n6 snmp3 trap user "ops_v6" engineid "80001f8880660006" auth sha256 "Ipv6AuthPass!" priv aes "Ipv6PrivPass!" oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.4.34.1.3.2.16 ipval 2001:db8:3::1
}

compile { ipv6_snmp_traps(v6_agent, v6_collector) }
```

## Modifier Cheat-Sheet

| Version | Keyword | Default Ports | Auth / Crypto | Supported Operations |
| :--- | :--- | :--- | :--- | :--- |
| **SNMPv1** | `snmp1` | `161` (poll), `162` (trap) | `community "<str>"` | `get`, `getnext`, `set`, `response`, `trap` |
| **SNMPv2c** | `snmp2` | `161` (poll), `162` (trap, inform) | `community "<str>"` | `get`, `getnext`, `getbulk`, `set`, `response`, `trap`, `inform` |
| **SNMPv3** | `snmp3` | `161` (poll), `162` (trap, inform) | `noAuthNoPriv`, `authNoPriv`, `authPriv` | `get`, `getnext`, `getbulk`, `set`, `response`, `trap`, `inform` |

| Modifier | Applies To | Default | What It Does |
| :--- | :--- | :--- | :--- |
| `community "<str>"` | `snmp1`, `snmp2` | `"public"` | Cleartext community string (`"public"`, `"private"`, and so on) |
| `reqid <u32>` | `snmp1`, `snmp2`, `snmp3` | `1` | Request ID that ties a `response` to its request or `inform` |
| `sysuptime <ticks>` | `snmp1`, `snmp2`, `snmp3` | `0` | Agent uptime in hundredths of a second (Trap-PDU timestamp in v1, `sysUpTime.0` in v2c and v3) |
| `oid <oid>` | `snmp1`, `snmp2`, `snmp3` | `linkDown` (v2c, v3) | Notification OID for `trap` and `inform`, or a shorthand single-OID `null` query on `get` |
| `nonrepeaters <n>` | `snmp2`, `snmp3` | `0` | First `<n>` scalar OIDs in a `getbulk` that are fetched only once |
| `maxrepetitions <m>` | `snmp2`, `snmp3` | `10` | Maximum table rows fetched per remaining OID in a `getbulk` |
| `enterprise <oid>` | `snmp1` | `1.3.6.1.4.1` | Vendor enterprise OID in an SNMPv1 Trap-PDU |
| `agentip <ipv4>` | `snmp1` | Sender IPv4 (`0.0.0.0` on IPv6) | Overrides the inner `agent-addr`, useful when simulating a trap proxy or concentrator |
| `gentrap <0..6>` | `snmp1` | `6` (or derived from `oid`) | `0` coldStart, `1` warmStart, `2` linkDown, `3` linkUp, `4` authFailure, `5` egpNeighborLoss, `6` enterpriseSpecific |
| `spectrap <u32>` | `snmp1` | `0` (`0..5`) / `1` (`6`) | Vendor-specific trap code when `gentrap` is `6` |
| `user "<name>"` | `snmp3` | `"admin"` | USM username (`""` for EngineID discovery probes) |
| `engineid "<hex>"` | `snmp3` | `"8000000001"` | Even-length hex EngineID, such as `"80001f8880510001"` |
| `engineboots <u32>` | `snmp3` | `0` | Engine reboot counter, used in anti-replay checks and the AES-128 IV |
| `enginetime <u32>` | `snmp3` | `0` | Seconds since the last engine boot, used in anti-replay checks and the AES-128 IV |
| `contextname "<str>"` | `snmp3` | `""` | VRF, bridge-domain, or per-VLAN MIB context, such as `"vrf-pci"` |
| `auth <alg> "<pass>"` | `snmp3` | None (`noAuth`) | Signs the packet: unquoted `md5`, `sha`, `sha256`, `sha384`, or `sha512`, then the passphrase |
| `priv <alg> "<pass>"` | `snmp3` | None (`noPriv`) | Encrypts the `scopedPDU`: unquoted `des` or `aes`, then the passphrase (requires `auth`) |

Wire behavior worth knowing:

* **Ports follow the operation.** `get`, `getnext`, `getbulk`, `set`, and `response` go to UDP `161`. `trap` and `inform` go to UDP `162`. Replies on `<-` swap the ports back to the sender's ephemeral port. Add `dstport 162` on an `inform`, or `srcport 162` on its `response`, if the reply should come from `162`.
* **Trap headers are prepended.** On `snmp2` and `snmp3`, `sysuptime` and `oid` become the first two varbinds (`sysUpTime.0`, `snmpTrapOID.0`), followed by your own `varbind` entries in order.
* **Bare keywords compile.** A statement with just `snmp1`, `snmp2`, or `snmp3` and no modifiers still produces a valid RFC trap on UDP `162`.
* **Syntax check.** Keep `auth` and `priv` algorithm names unquoted and quote only the password: `auth sha256 "MyAuthPass!" priv aes "MyPrivPass!"`, never `auth "sha256"`. `priv` always requires `auth`. `counter64`, `getbulk`, and `inform` exist only in `snmp2` and `snmp3`.

## Replaying and Reversing SNMP Captures

```bash
# Replay honoring your .frasm wait intervals
sudo tcpreplay -i eth0 snmp_alert.pcap

# Blast traps at wire speed to benchmark collector throughput
sudo tcpreplay -i eth0 --topspeed snmp_alert.pcap

# Turn an existing SNMP .pcap / .pcapng capture into .frasm code (defaults to <input_stem>.frasm)
frameassembly reverse snmp_walk.pcap snmp_walk.frasm
```

Reversing decompiles cleartext `snmp1`, `snmp2`, and `snmp3` (`noAuthNoPriv`) packets into statements with `varbind` entries. Encrypted `snmp3` `authPriv` packets, and keyed `authNoPriv` ones, are not decrypted. They are kept as `udp` statements with `hexpayload`, so recompiling reproduces the exact wire bytes.
