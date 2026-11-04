# SNMPv1, SNMPv2c & Encrypted SNMPv3 (`docs/l7_snmp.md`)

[**Use Cases**](#snmp-testing-and-security-use-cases) • [**How It Works**](#what-frameassembly-handles-for-you) • [**Keywords & Modifiers**](#snmp-keywords-and-modifiers) • [**All 9 VarBind Types & OIDs**](#varbind-types-and-common-mib-oids) • [**Wireshark Decryption**](#decrypting-and-replaying-snmpv3-captures)

## Why Use FrameAssembly for SNMP?

Simulating SNMP traffic—especially encrypted **SNMPv3 `authPriv` traps**—is normally way harder than whatever monitoring rule you are actually trying to test.

If you want to verify that **Zabbix**, **Checkmk**, **LibreNMS**, **PRTG**, **SolarWinds**, **Datadog**, or `snmptrapd` actually pages the on-call engineer when a core uplink dies, your usual options are grim -> configure an SNMP agent, hunt down broken vendor MIB dependencies, match hex EngineIDs and localized keys, and physically yank a patch cord out of a switch just to watch a dashboard turn red :)

With **FrameAssembly**, you describe the poll, walk, `SET`, or encrypted trap in a few lines of `.fasm` packet code, compile a clean `.pcap` with no MIB files or `sudo` privileges needed, and fire it at your collector or IDS with **`tcpreplay`**:

```frameassembly
host core_sw { ip 10.10.1.2  mac 00:1a:2b:3c:4d:01 }
host zabbix  { ip 10.10.1.50 mac 00:1a:2b:3c:4d:50 }

flow link_down_alert(sw, nms) {
    // SNMPv2c linkDown trap (sysUpTime.0 and snmpTrapOID.0 are added automatically)
    sw -> nms snmp2 trap community "public" sysuptime 432000 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.2.1 string "Gi0/1" varbind 1.3.6.1.2.1.2.2.1.8.1 int 2 wait 5ms

    // Encrypted SNMPv3 authPriv trap (SHA-256 + AES-128) on VLAN 100
    sw -> nms vlan 100 snmp3 trap user "netops" engineid "80001f8801" engineboots 5 enginetime 3600 auth sha256 "AuthPass123!" priv aes "PrivPass123!" sysuptime 432005 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.8.1 int 2
}

compile { link_down_alert(core_sw, zabbix) }
```

```console
$ frameassembly show snmp_alert.fasm
$ frameassembly snmp_alert.fasm -o snmp_alert.pcap && sudo tcpreplay -i eth0 snmp_alert.pcap
```

## SNMP Testing and Security Use Cases

### 1. Test Encrypted `SNMPv3` `authPriv` Traps & `INFORM` Alerts Without Touching Live Gear
Getting SNMPv3 `authPriv` traps working between a router and an NMS is notorious for silent packet drops whenever an `EngineID`, `EngineBoots` counter, `EngineTime` window, or `SHA-2`/`AES` key doesn't line up. Instead of fighting `snmptrap` CLI flags or rebooting lab gear, pass plain passphrases in `.fasm` code—FrameAssembly derives the localized keys, encrypts the payload, signs the packet, and handles acknowledged `inform` -> `response` handshakes out of the box:

```frameassembly
host core_rtr { ip 10.151.0.1   mac 00:25:90:51:00:01 }
host nms_srv  { ip 10.151.0.250 mac 00:25:90:51:00:fa }

flow snmpv3_alerts(rtr, nms) {
    // Encrypted SNMPv3 TRAP (SHA-256 + AES-128) reporting a 100G uplink down
    rtr -> nms dscp 16 snmp3 trap user "ops_v3" engineid "80001f8880510001" engineboots 30 enginetime 400000 contextname "core-fabric" auth sha256 "ProdAuthPass2026!" priv aes "ProdPrivPass2026!" reqid 9701 sysuptime 40000000 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.31.1.1.1.1.10 string "HundredGigE0/0/0/10" varbind 1.3.6.1.2.1.2.2.1.8.10 int 2 wait 5ms

    // Guaranteed-delivery SNMPv3 INFORM + NMS RESPONSE on UDP 162 (SHA-512 + AES-128)
    rtr -> nms dscp 16 snmp3 inform dstport 162 user "ops_v3" engineid "80001f8880510001" engineboots 30 enginetime 400001 contextname "core-fabric" auth sha512 "HighSecSha512!" priv aes "HighSecAes128!" reqid 9702 sysuptime 40000100 oid 1.3.6.1.2.1.15.7.2 varbind 1.3.6.1.2.1.15.3.1.2.198.51.100.2 int 1 wait 2ms
    rtr <- nms dscp 16 snmp3 response user "ops_v3" engineid "80001f8880510001" engineboots 30 enginetime 400001 contextname "core-fabric" auth sha512 "HighSecSha512!" priv aes "HighSecAes128!" reqid 9702 varbind 1.3.6.1.2.1.15.3.1.2.198.51.100.2 int 1
}

compile { snmpv3_alerts(core_rtr, nms_srv) }
```

### 2. Stress-Test Collector Queues & Alert Deduplication (`loop` Trap Storms & Link Flaps)
Finding out *during* a real fiber cut that a single flapping port sends 500 Slack alerts or chokes your trap daemon is bad timing. Wrap a `linkDown` / `linkUp` sequence inside `loop` to verify alert throttling and deduplication before production finds out for you:

```frameassembly
host flapping_sw { ip 10.125.0.10  mac 00:1c:73:25:00:10 }
host trap_sink   { ip 10.125.0.250 mac 00:1c:73:25:00:fa }

flow link_flap_cycle(sw, sink) {
    sw -> sink snmp2 trap community "noc_traps" reqid 6001 sysuptime 300100 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.2.10 string "Ethernet10" varbind 1.3.6.1.2.1.2.2.1.8.10 int 2 varbind 1.3.6.1.2.1.2.2.1.5.10 gauge32 0 wait 50ms
    sw -> sink snmp2 trap community "noc_traps" reqid 6002 sysuptime 300105 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.2.2.1.2.10 string "Ethernet10" varbind 1.3.6.1.2.1.2.2.1.8.10 int 1 varbind 1.3.6.1.2.1.2.2.1.5.10 gauge32 1000000000 wait 50ms
}

compile {
    loop 25 { link_flap_cycle(flapping_sw, trap_sink) }
}
```

### 3. Simulate 400G `Counter64` `GETBULK` Polls, Optical Sensors & Multi-VRF Contexts
Testing custom NMS templates, Prometheus `snmp_exporter` parsers, 64-bit interface counter wraps, negative optical `dBm` readings, or per-VRF routing table queries usually requires physical spine switches and MPLS PE routers. Here you can script the exact `getbulk` / `get` and `response` packets—exercising all 9 `varbind` types—in one flow:

```frameassembly
host poller    { ip 10.156.0.10 mac 00:1b:54:56:00:10 }
host pe_router { ip 10.156.0.1  mac 00:1b:54:56:00:01 }

flow poll_counters_and_vrfs(nms, pe) {
    // SNMPv2c GETBULK: fetch 1 scalar (sysUpTime.0) + repeating 400G Counter64 & optical dBm rows
    nms -> pe snmp2 getbulk community "telemetry_ro" reqid 7001 nonrepeaters 1 maxrepetitions 10 varbind 1.3.6.1.2.1.1.3.0 null varbind 1.3.6.1.2.1.31.1.1.1.6 null wait 2ms
    nms <- pe snmp2 response community "telemetry_ro" reqid 7001 varbind 1.3.6.1.2.1.1.3.0 timeticks 8640000 varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.30065.1.3011 varbind 1.3.6.1.2.1.31.1.1.1.1.1 string "Ethernet1/1" varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 2199023255552 varbind 1.3.6.1.2.1.2.2.1.14.1 counter32 0 varbind 1.3.6.1.2.1.31.1.1.1.15.1 gauge32 400000 varbind 1.3.6.1.4.1.9.9.91.1.1.1.1.4.1 int -7 wait 5ms

    // SNMPv3 multi-tenant VRF poll isolated via contextname "vrf-pci"
    nms -> pe snmp3 get user "vrf_auditor" engineid "800000090300001b54560001" engineboots 10 enginetime 80000 contextname "vrf-pci" auth sha256 "VrfAuthKey!" priv aes "VrfPrivKey!" reqid 7002 varbind 1.3.6.1.2.1.4.21.1.7.0.0.0.0 null wait 2ms
    nms <- pe snmp3 response user "vrf_auditor" engineid "800000090300001b54560001" engineboots 10 enginetime 80000 contextname "vrf-pci" auth sha256 "VrfAuthKey!" priv aes "VrfPrivKey!" reqid 7002 varbind 1.3.6.1.2.1.4.21.1.7.0.0.0.0 ipval 172.31.254.1
}

compile { poll_counters_and_vrfs(poller, pe_router) }
```

### 4. Pentesting, Rogue `SET` Detection & IDS Rule Validation (`Suricata`, `Zeek`, SIEM)
Leftover `"public"` and `"private"` community strings are still an internal pentester's best friend. Build clean, zero-noise captures to verify that **Suricata**, **Zeek**, or your SIEM flags unauthenticated SNMPv3 EngineID discovery probes, unauthorized `SET` requests shutting down switch ports (`ifAdminStatus = 2`), and resulting `authenticationFailure` traps:

```frameassembly
host rogue_scanner { ip 192.168.66.13 mac 00:0c:29:66:00:13 }
host access_sw     { ip 192.168.66.1  mac 00:1c:73:66:00:01 }
host secops_siem   { ip 10.104.0.99   mac 00:19:56:00:01:99 }

flow snmp_pentest_and_detection(attacker, sw, siem) {
    // 1. Unauthenticated SNMPv3 EngineID discovery probe
    attacker -> sw snmp3 get user "" engineid "0000000000" engineboots 0 enginetime 0 reqid 8001 wait 2ms
    attacker <- sw snmp3 response user "" engineid "80001f8880660001" engineboots 4 enginetime 9200 reqid 8001 varbind 1.3.6.1.6.3.15.1.1.4.0 counter32 1 wait 5ms

    // 2. Rogue SNMPv2c SET using default "private" write community to admin-down port 24
    attacker -> sw snmp2 set community "private" reqid 8002 varbind 1.3.6.1.2.1.2.2.1.7.24 int 2 wait 2ms
    attacker <- sw snmp2 response community "private" reqid 8002 varbind 1.3.6.1.2.1.2.2.1.7.24 int 2 wait 5ms

    // 3. Switch alerts SecOps with an SNMPv1 authenticationFailure trap (gentrap 4)
    sw -> siem snmp1 trap community "sec_trap" enterprise 1.3.6.1.4.1.9.1 agentip 192.168.66.1 gentrap 4 spectrap 0 sysuptime 543210 varbind 1.3.6.1.4.1.9.2.1.5.0 ipval 192.168.66.13 varbind 1.3.6.1.4.1.9.2.1.6.0 string "bad_community_attempt"
}

compile { snmp_pentest_and_detection(rogue_scanner, access_sw, secops_siem) }
```

```console
$ frameassembly snmp_ids.fasm -o snmp_ids.pcap && suricata -r snmp_ids.pcap -k none
```

### 5. Legacy `SNMPv1` UPS/Printer Hardware, `MD5`/`DES` & Carrier `QinQ` + `MPLS`
Every network has that one ancient UPS management card, laser printer, or branch CPE that only speaks `SNMPv1` (`gentrap` / `spectrap`) or legacy `SNMPv3` `MD5` + `DES`—sometimes Riding across a carrier `QinQ` + `MPLS` backhaul or IPv6 management network:

```frameassembly
host ups_card     { ip 10.145.40.5   mac 00:1a:2b:91:40:05 }
host noc_srv      { ip 10.145.40.100 mac 00:1a:2b:91:40:64 }
host v6_agent     { ip 2001:db8:3::1 }
host v6_collector { ip 2001:db8:3::2 }

flow legacy_and_carrier_snmp(agent, nms) {
    // SNMPv1 enterprise-specific UPS "on battery" trap (gentrap 6, spectrap 1)
    agent -> nms snmp1 trap community "ups_traps" enterprise 1.3.6.1.2.1.33.2 agentip 10.145.40.5 gentrap 6 spectrap 1 sysuptime 9912400 varbind 1.3.6.1.2.1.33.1.2.3.0 int 28 wait 5ms

    // Legacy SNMPv3 MD5 + DES trap inside Carrier QinQ (800/162) and MPLS label 7300
    agent -> nms qinq 800 inner_vlan 162 mpls 7300 snmp3 trap user "legacy_ups" engineid "80001f8880aa11bb22" engineboots 4 enginetime 12000 auth md5 "LegacyMd5Key!" priv des "LegacyDesKey!" oid 1.3.6.1.6.3.1.1.5.3 sysuptime 1200000 varbind 1.3.6.1.2.1.2.2.1.2.3 string "FastEthernet0/3"
}

flow ipv6_snmp_traps(a6, n6) {
    // Over IPv6, SNMPv1 automatically sets the 4-byte agent-addr field to 0.0.0.0 (RFC 3584)
    a6 -> n6 snmp1 trap community "public" enterprise 1.3.6.1.4.1.318 gentrap 6 spectrap 5 sysuptime 90000 varbind 1.3.6.1.2.1.1.5.0 string "ups-row4-v6" wait 5ms
    a6 -> n6 snmp3 trap user "ops_v6" engineid "80001f8880660006" auth sha256 "Ipv6AuthPass!" priv aes "Ipv6PrivPass!" oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.4.34.1.3.2.16 ipval 2001:db8:3::1
}

compile {
    legacy_and_carrier_snmp(ups_card, noc_srv)
    ipv6_snmp_traps(v6_agent, v6_collector)
}
```

## What FrameAssembly Handles for You

* **Smart UDP `161` vs. `162` Port Routing:** Polling operations (`get`, `getnext`, `getbulk`, `set`, `response`) automatically target **UDP `161`**, while notifications (`trap`, `inform`) target **UDP `162`**. Replies on `<-` automatically flip the ports back to the sender's ephemeral port (add `dstport 162` on `inform` or `srcport 162` on its `response` so the reply comes from `162`).
* **Zero MIB Files Needed:** Forget `MIBS=+ALL` path errors. Write numeric OIDs (`1.3.6.1.2.1.1.5.0`, quoted or unquoted) paired with plain type names (`string`, `int`, `counter64`, `ipval`, etc.).
* **Auto-Prepended Trap Headers:** Every `snmp2` and `snmp3` `trap` or `inform` requires `sysUpTime.0` and `snmpTrapOID.0` as its first two VarBinds. FrameAssembly prepends both automatically from `sysuptime` and `oid`, then appends your `varbind` list in order.
* **Built-In SNMPv3 USM Crypto:** Pass cleartext passwords to `auth` (`md5`, `sha`, `sha256`, `sha384`, `sha512`) and `priv` (`des`, `aes`). FrameAssembly localizes the keys against `engineid`, encrypts the `scopedPDU`, and signs the BER packet so Wireshark and `snmptrapd` can decrypt and verify it immediately.
* **Zero-Keyword Defaults:** Even a bare `sw -> nms snmp1`, `sw -> nms snmp2`, or `sw -> nms snmp3` compiles into a valid RFC trap on UDP `162`.

## SNMP Keywords and Modifiers

| Version | Keyword | Default Ports | Auth / Crypto | Supported Operations |
| :--- | :--- | :--- | :--- | :--- |
| **SNMPv1** | `snmp1` | `161` (Poll), `162` (Trap) | `community "<str>"` | `get`, `getnext`, `set`, `response`, `trap` |
| **SNMPv2c** | `snmp2` | `161` (Poll), `162` (Trap/Inform) | `community "<str>"` | `get`, `getnext`, `getbulk`, `set`, `response`, `trap`, `inform` |
| **SNMPv3** | `snmp3` | `161` (Poll), `162` (Trap/Inform) | `noAuthNoPriv`, `authNoPriv`, `authPriv` | `get`, `getnext`, `getbulk`, `set`, `response`, `trap`, `inform` |

### Shared & Version-Specific Modifiers

| Modifier | Applies To | Default | What It Does |
| :--- | :--- | :--- | :--- |
| `community "<str>"` | `snmp1`, `snmp2` | `"public"` | Cleartext community string (`"public"`, `"private"`, etc.) |
| `reqid <u32>` | `snmp1`, `snmp2`, `snmp3` | `1` | Request/Message ID matching a `response` to its request or `inform` |
| `sysuptime <ticks>` | `snmp1`, `snmp2`, `snmp3` | `0` | Agent uptime in `1/100`s ticks (`Trap-PDU` timestamp in v1; `sysUpTime.0` in v2c/v3) |
| `oid <oid>` | `snmp1`, `snmp2`, `snmp3` | `linkDown` (v2c/v3) | Notification OID for `trap`/`inform` (or shorthand single-OID `null` query on `get`) |
| `nonrepeaters <n>` | `snmp2`, `snmp3` | `0` | First `<n>` scalar OIDs in a `getbulk` request fetched only once |
| `maxrepetitions <m>` | `snmp2`, `snmp3` | `10` | Max table rows fetched per remaining OID in a `getbulk` request |
| `enterprise <oid>` | `snmp1` | `1.3.6.1.4.1` | Vendor enterprise OID in an SNMPv1 `Trap-PDU` |
| `agentip <ipv4>` | `snmp1` | Sender IPv4 (`0.0.0.0` on v6) | Overrides inner `agent-addr` (useful when simulating an SNMP trap proxy/concentrator) |
| `gentrap <0..6>` | `snmp1` | `6` (or auto from `oid`) | `0` `coldStart`, `1` `warmStart`, `2` `linkDown`, `3` `linkUp`, `4` `authFailure`, `5` `egpNeighborLoss`, `6` `enterpriseSpecific` |
| `spectrap <u32>` | `snmp1` | `0` (`0..5`) / `1` (`6`) | Vendor-specific trap sub-code when `gentrap` is `6` |
| `user "<name>"` | `snmp3` | `"admin"` | USM username (`""` for EngineID discovery probes) |
| `engineid "<hex>"` | `snmp3` | `"8000000001"` | Even-length hex EngineID string (e.g., `"80001f8880510001"`) |
| `engineboots <u32>` | `snmp3` | `0` | Engine reboot counter (used in anti-replay & AES-128 IV) |
| `enginetime <u32>` | `snmp3` | `0` | Seconds since last engine boot (used in anti-replay & AES-128 IV) |
| `contextname "<str>"`| `snmp3` | `""` | VRF, bridge-domain, or per-VLAN MIB context name (e.g., `"vrf-pci"`) |
| `auth <alg> "<pass>"`| `snmp3` | None (`noAuth`) | Signs packet with unquoted `md5`, `sha`, `sha256`, `sha384`, or `sha512` + passphrase |
| `priv <alg> "<pass>"`| `snmp3` | None (`noPriv`) | Encrypts `scopedPDU` with unquoted `des` or `aes` + passphrase (requires `auth`) |

> **Quick Syntax Check:** Keep `auth` and `priv` algorithm names **unquoted**, and put quotes around the password -> `auth sha256 "MyAuthPass!" priv aes "MyPrivPass!"` (never `auth "sha256"`). Also note that SNMPv3 forbids encryption without authentication (`priv` always requires `auth`), and `counter64` / `getbulk` / `inform` are `snmp2` and `snmp3` only.

## VarBind Types and Common MIB OIDs

Chain as many `varbind <oid> <type> [value]` entries onto a single statement as you want:

| Type Keyword | Example | Notes |
| :--- | :--- | :--- |
| `null` / `nullval` | `varbind 1.3.6.1.2.1.1.1.0 null` | Empty placeholder used in `get`, `getnext`, and `getbulk` requests |
| `string "<text>"` | `varbind 1.3.6.1.2.1.1.5.0 string "core-sw"` | Hostnames, interface names, serial numbers, and status messages |
| `int <-2B..2B>` | `varbind 1.3.6.1.2.1.2.2.1.8.1 int 2` | Signed 32-bit integer (`1`=`up`, `2`=`down`, or negative values like `-18` dBm / `-15` °C) |
| `timeticks <u32>` | `varbind 1.3.6.1.2.1.1.3.0 timeticks 8640000` | Elapsed time in `1/100`s centiseconds (`8640000` = 24 hours) |
| `ipval <ip>` | `varbind 1.3.6.1.2.1.4.20.1.1.10.0.0.1 ipval 10.0.0.1` | Accepts both IPv4 (`IpAddress`) and IPv6 (`2001:db8::1` 16-byte `InetAddress`) |
| `oidval <oid>` | `varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.9.1.1` | Value that points to another OID (such as `sysObjectID.0`) |
| `counter32 <u32>` | `varbind 1.3.6.1.2.1.2.2.1.10.1 counter32 459012` | Wrapping 32-bit packet/byte/error counter |
| `gauge32 <u32>` | `varbind 1.3.6.1.2.1.2.2.1.5.1 gauge32 1000000000` | Non-wrapping 32-bit gauge (link speed, CPU %, PoE watts, queue depth) |
| `counter64 <u64>` | `varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 98765432100` | 64-bit high-speed counter (`ifHCInOctets` / `ifHCOutOctets`; `snmp2` & `snmp3` only) |

### Handy MIB-II & Standard Trap OIDs (So You Don't Have to Google Them)

| Object / Trap | OID | Typical Type | Common Values |
| :--- | :--- | :--- | :--- |
| `sysDescr.0` / `sysObjectID.0` | `1.3.6.1.2.1.1.1.0` / `1.3.6.1.2.1.1.2.0` | `string` / `oidval` | OS version banner / vendor model OID |
| `sysUpTime.0` | `1.3.6.1.2.1.1.3.0` | `timeticks` | Uptime in hundredths of a second |
| `sysContact.0` / `sysName.0` / `sysLocation.0` | `1.3.6.1.2.1.1.4.0` / `.5.0` / `.6.0` | `string` | Admin email, hostname, rack location |
| `ifIndex.<n>` / `ifDescr.<n>` | `1.3.6.1.2.1.2.2.1.1.<n>` / `.2.<n>` | `int` / `string` | Port index (`1`, `2`) / name (`"Gi0/1"`) |
| `ifAdminStatus.<n>` / `ifOperStatus.<n>` | `1.3.6.1.2.1.2.2.1.7.<n>` / `.8.<n>` | `int` | `1` = `up`, `2` = `down`, `3` = `testing` |
| `ifHCInOctets.<n>` / `ifHCOutOctets.<n>` | `1.3.6.1.2.1.31.1.1.1.6.<n>` / `.10.<n>` | `counter64` | 64-bit inbound / outbound byte counters |
| `coldStart` / `warmStart` | `1.3.6.1.6.3.1.1.5.1` / `1.3.6.1.6.3.1.1.5.2` | Trap `oid` | Device rebooted / SNMP agent restarted |
| `linkDown` / `linkUp` | `1.3.6.1.6.3.1.1.5.3` / `1.3.6.1.6.3.1.1.5.4` | Trap `oid` | Interface went down / came back up |
| `authenticationFailure` | `1.3.6.1.6.3.1.1.5.5` | Trap `oid` | Bad community string or unauthorized poll |

## Decrypting and Replaying SNMPv3 Captures

### Decrypt `snmp3` in `tshark` (One-Liner)
```bash
tshark -r snmp_alert.pcap \
  -o 'uat:snmp_users:"80001f8801","netops","SHA2-256","AuthPass123!","AES","PrivPass123!"' \
  -V
```

### Decrypt `snmp3` in the Wireshark GUI
Open **Edit -> Preferences -> Protocols -> SNMP -> Users Table -> Edit...**, add your **Engine ID** (`80001f8801`, or leave blank to match all), **Username** (`netops`), **Auth model** (`SHA2-256`, `SHA2-512`, `SHA2-384`, `SHA1`, or `MD5`), **Auth password**, **Priv protocol** (`AES` or `DES`), and **Priv password**. Wireshark immediately unlocks the `encryptedPDU` and shows `[Authentication OK]`.

### Replay into a Live Collector (`tcpreplay`)
```bash
# Replay honoring your .fasm wait intervals
sudo tcpreplay -i eth0 snmp_alert.pcap

# Blast traps at wire speed to benchmark collector throughput
sudo tcpreplay -i eth0 --topspeed snmp_alert.pcap
```

## Related Documentation

* [**Getting Started (`getting_started.md`)**](getting_started.md) — Core `host` / `flow` / `compile` mechanics, MAC formats, and `frameassembly show`.
* [**Real-World Use Cases (`use_cases.md`)**](use_cases.md) — Copy-paste recipes for firewall audits, QoS trunks, SIEM ingest, and OT conduits.
* [**Layer 2 — Switching & Data Link (`l2_protocols.md`)**](l2_protocols.md) — Wrap SNMP traffic in `vlan`, `qinq`, and `mpls` headers.
* [**Layer 3 — Network, Routing & Tunnels (`l3_protocols.md`)**](l3_protocols.md) — Pair SNMP alerts with `ospf`, `bgp`, `vrrp`, `hsrp`, and `bfd` failovers.
* [**Layer 4 — Transports (`l4_transports.md`)**](l4_transports.md) — `udp`, stateful `tcp`, and `sctp` port and sequence behavior.
* [**Layer 7 — Infrastructure & Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — Combine SNMP with `syslog`, `netflow`, `ipfix`, `sflow`, `ntp`, and `radius`.
* [**Topologies & Dual-Stack (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Multi-device campus 802.1X NAC and WAN failover captures.