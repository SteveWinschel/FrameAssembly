# Layer 7 Network Management: SNMPv1, SNMPv2c & Encrypted SNMPv3 USM Guide

Testing your Network Management System (Zabbix, Checkmk, LibreNMS, PRTG, SolarWinds, Datadog, or Linux `snmptrapd`) shouldn't require waiting for a core router power supply to fail at 3:00 AM, fighting `net-snmp` MIB path errors, memorizing cryptic `snmptrap` single-letter type flags (`i`, `u`, `t`, `s`, `o`, `a`, `c`), or wrestling with SNMPv3 Engine ID key localization.

As a full-featured **SNMPv1 / SNMPv2c / SNMPv3 USM `authPriv` trap & poll pcap generator**, FrameAssembly lets you write clean, human-readable `.fasm` statements for **SNMPv1 (`SNMP1`)**, **SNMPv2c (`SNMP2`)**, and **SNMPv3 (`SNMP3`)**, and builds standards-compliant `.pcap` / `.pcapng` packet captures ready for Wireshark inspection or live replay into your monitoring collector.

---

## 1. Why SNMP Testing Is Effortless with FrameAssembly

* **Automatic UDP Port Routing (`161` vs. `162`):**
  * **Polling & Management PDUs** (`GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `REPORT`) automatically route to **UDP port `161`**.
  * **Asynchronous Notifications** (`TRAP` and `INFORM`) automatically route to **UDP port `162`**.
  * **Bidirectional Reply Port Tracking:** When a manager sends a `GET` (`mgr -> agent snmp2 get ...`) or an agent sends an `INFORM` (`mgr <- agent snmp2 inform ...`), the reply statement in the opposite direction automatically swaps the UDP source and destination ports so the `RESPONSE` lands back on the initiator's ephemeral port.
* **No MIB Files Needed:** You never have to install vendor MIB files or configure `MIBS=+ALL`. Write standard numeric dotted-decimal OIDs (`1.3.6.1.2.1.1.5.0`) and explicit, readable data-type keywords (`string`, `int`, `gauge32`, `counter32`, `counter64`, `timeticks`, `ipval`, `oidval`, `null`).
* **Automatic RFC 3416 Trap & Inform Header Prepending (`sysUpTime.0` & `snmpTrapOID.0`):**
  * RFC 3416 §4.2.6 requires every SNMPv2c and SNMPv3 `TRAP` or `INFORM` packet to carry `sysUpTime.0` (`1.3.6.1.2.1.1.3.0`) as its first VarBind and `snmpTrapOID.0` (`1.3.6.1.6.3.1.1.4.1.0`) as its second VarBind.
  * FrameAssembly builds both for you automatically from `sysuptime <ticks>` and `oid <trap_oid>`, then appends your custom `varbind` entries in exact order.
* **Real SNMPv3 USM Key Localization, Signing & Encryption Out of the Box:**
  * Provide plain-text passphrases (`auth sha256 "..." priv aes "..."`) and an `engineid` hex string.
  * FrameAssembly performs full **RFC 3414 / RFC 3826 / RFC 7860** password-to-key stretching (`1,048,576`-byte digest loop `Ku`) and Engine ID key localization (`Kul`), encrypts the `scopedPDU` using `DES-CBC` or `AES-128-CFB`, and signs the entire BER message with `HMAC-MD5-96`, `HMAC-SHA-96`, `HMAC-SHA-256-128`, `HMAC-SHA-384-192`, or `HMAC-SHA-512-256`.

### Quick Protocol Comparison

| Protocol Version | `.fasm` Keyword | RFC Standards | Default UDP Ports | Security Model | Supported PDU Keywords |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SNMPv1** | `SNMP1` | RFC 1157 | `161` (Poll), `162` (Trap) | Cleartext Community (`COMMUNITY`) | `GET`, `GETNEXT`, `SET`, `RESPONSE`, `TRAP` |
| **SNMPv2c** | `SNMP2` | RFC 1901, RFC 3416 | `161` (Poll), `162` (Trap / Inform) | Cleartext Community (`COMMUNITY`) | `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `TRAP`, `INFORM` |
| **SNMPv3** | `SNMP3` | RFC 3412, RFC 3414, RFC 3826, RFC 7860 | `161` (Poll), `162` (Trap / Inform) | USM (`noAuthNoPriv`, `authNoPriv`, `authPriv`) | `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `TRAP`, `INFORM`, `REPORT` |

> **Zero-Keyword Defaults:** Every SNMP protocol keyword works with zero sub-keywords. Writing `mgr <- sw snmp1`, `mgr <- sw snmp2`, or `mgr <- sw snmp3` emits a valid RFC-compliant Trap packet on UDP port `162` with sensible defaults (`community "public"` for v1/v2c, or `user "admin"` / `engineid "8000000001"` for v3).

---

## 2. Complete Reference for All 9 `VARBIND` Types & MIB-II Cheat Sheet

An SNMP packet carries a list of **Variable Bindings (`VARBIND`)**, where each entry pairs an Object Identifier (`<oid>`) with an ASN.1 SMI value. You can chain as many `VARBIND` clauses onto a single statement as you need.

### 2.1 The 9 Supported `VARBIND` Value Types

| `VARBIND` Keyword | Syntax Example | ASN.1 BER Tag | SMI Data Type & Typical Network Use Case |
| :--- | :--- | :--- | :--- |
| **`NULL`** or **`NULLVAL`** | `varbind 1.3.6.1.2.1.1.1.0 null` | `0x05` | **ASN.1 `NULL`**: Placeholder value used in `GET`, `GETNEXT`, and `GETBULK` polling requests where the agent fills in the value in its `RESPONSE`. Both `null` and `nullval` are accepted. |
| **`STRING`** | `varbind 1.3.6.1.2.1.1.5.0 string "core-sw-01"` | `0x04` | **ASN.1 `OCTET STRING`**: UTF-8 / ASCII text strings for hostnames (`sysName`), interface names (`ifDescr`, `ifAlias`), serial numbers, and alarm descriptions. |
| **`INT`** | `varbind 1.3.6.1.2.1.2.2.1.8.1 int 2` | `0x02` | **ASN.1 `INTEGER` (32-bit signed)**: Signed 32-bit integer for interface states (`1` = `up`, `2` = `down`, `3` = `testing`), BGP peer states (`1..6`), temperatures, or table indices (`ifIndex`). |
| **`TIMETICKS`** | `varbind 1.3.6.1.2.1.1.3.0 timeticks 8640000` | `0x43` | **SMI `TimeTicks` (32-bit unsigned)**: Elapsed time in **1/100ths of a second** (centiseconds) since agent boot or state change (`8640000` ticks = 24 hours). |
| **`IPVAL`** | `varbind 1.3.6.1.2.1.4.20.1.1.10.0.0.1 ipval 10.0.0.1` | `0x40` / `0x04` | **SMI `IpAddress` / `InetAddress`**: Accepts both IPv4 (`10.0.0.1`, encoded as 4-byte `0x40` `IpAddress`) and IPv6 (`2001:db8::1`, encoded as 16-byte `0x04` `OCTET STRING` per RFC 4001). |
| **`OIDVAL`** | `varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.9.1.1` | `0x06` | **ASN.1 `OBJECT IDENTIFIER`**: Value that is itself an OID pointer, such as `sysObjectID.0` or `snmpTrapOID.0`. Accepts unquoted (`1.3.6.1...`) or quoted (`"1.3.6.1..."`) OIDs. |
| **`COUNTER32`** | `varbind 1.3.6.1.2.1.2.2.1.10.1 counter32 4590123` | `0x41` | **SMI `Counter32` (32-bit unsigned)**: 32-bit monotonically increasing counter that wraps at $2^{32}-1$ (`ifInOctets`, `ifInErrors`, `snmpInPkts`). |
| **`GAUGE32`** | `varbind 1.3.6.1.2.1.2.2.1.5.1 gauge32 1000000000` | `0x42` | **SMI `Gauge32` (32-bit unsigned)**: 32-bit non-wrapping gauge that can rise or fall (`ifSpeed`, CPU load percentage, memory usage, optical transceiver dBm). |
| **`COUNTER64`** | `varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 98765432100` | `0x46` | **SMIv2 `Counter64` (64-bit unsigned)**: 64-bit high-capacity counter (`ifHCInOctets`, `ifHCOutOctets` for 10G/40G/100G/400G links). *Valid in `SNMP2` and `SNMP3` only (prohibited in `SNMP1` per RFC 2578).* |

> **OID Formatting Rules:**
> * You can write OIDs **unquoted** (`1.3.6.1.2.1.1.5.0`) or **quoted** (`"1.3.6.1.2.1.1.5.0"`).
> * Per ITU-T X.690 ASN.1 BER encoding rules, every OID must contain at least 2 numeric arcs, the first arc must be `0`, `1`, or `2`, and when the first arc is `0` or `1`, the second arc must be `< 40` (almost all IETF MIBs start with `1.3.6.1...`).

### 2.2 Common Standard MIB-II & Notification OIDs Cheat Sheet

Keep this table handy when building realistic polling flows or trap alerts for your NMS:

| MIB Object Name | Numeric OID | Typical `VARBIND` Type | Description & Common Values |
| :--- | :--- | :--- | :--- |
| **`sysDescr.0`** | `1.3.6.1.2.1.1.1.0` | `string` | Full OS, hardware, and software version banner |
| **`sysObjectID.0`** | `1.3.6.1.2.1.1.2.0` | `oidval` | Vendor enterprise hardware model OID (e.g., `1.3.6.1.4.1.9.1.716`) |
| **`sysUpTime.0`** | `1.3.6.1.2.1.1.3.0` | `timeticks` | Time since the network management portion of the system was re-initialized (`1/100` s) |
| **`sysContact.0`** | `1.3.6.1.2.1.1.4.0` | `string` | Responsible NOC/admin contact email or phone number |
| **`sysName.0`** | `1.3.6.1.2.1.1.5.0` | `string` | Fully-qualified administrative hostname (e.g., `"spine-01.dc1.example.com"`) |
| **`sysLocation.0`** | `1.3.6.1.2.1.1.6.0` | `string` | Physical data center, rack, and RU location |
| **`ifIndex.<n>`** | `1.3.6.1.2.1.2.2.1.1.<n>` | `int` | Unique numeric interface index (`1`, `2`, ...) |
| **`ifDescr.<n>`** | `1.3.6.1.2.1.2.2.1.2.<n>` | `string` | Interface name (`"GigabitEthernet0/1"`, `"et-0/0/0"`, `"eth0"`) |
| **`ifSpeed.<n>`** | `1.3.6.1.2.1.2.2.1.5.<n>` | `gauge32` | Interface bandwidth in bits/sec (`1000000000` for 1 Gbps) |
| **`ifAdminStatus.<n>`** | `1.3.6.1.2.1.2.2.1.7.<n>` | `int` | Desired administrative state: `1` = `up`, `2` = `down`, `3` = `testing` |
| **`ifOperStatus.<n>`** | `1.3.6.1.2.1.2.2.1.8.<n>` | `int` | Current operational link state: `1` = `up`, `2` = `down`, `3` = `testing` |
| **`ifInOctets.<n>`** | `1.3.6.1.2.1.2.2.1.10.<n>` | `counter32` | Legacy 32-bit inbound byte counter on interface `<n>` |
| **`ifHCInOctets.<n>`** | `1.3.6.1.2.1.31.1.1.1.6.<n>` | `counter64` | High-capacity 64-bit inbound byte counter (`ifXTable`, SNMPv2c/v3) |
| **`ifHCOutOctets.<n>`**| `1.3.6.1.2.1.31.1.1.1.10.<n>`| `counter64` | High-capacity 64-bit outbound byte counter (`ifXTable`, SNMPv2c/v3) |
| **`snmpTrapOID.0`** | `1.3.6.1.6.3.1.1.4.1.0` | `oidval` | Identifies the notification being sent (auto-prepended in v2c/v3 `TRAP` & `INFORM`) |
| **`coldStart`** | `1.3.6.1.6.3.1.1.5.1` | `oid` (Trap OID) | Agent rebooted with possible configuration changes (v1 `gentrap 0`) |
| **`warmStart`** | `1.3.6.1.6.3.1.1.5.2` | `oid` (Trap OID) | Agent restarted without configuration changes (v1 `gentrap 1`) |
| **`linkDown`** | `1.3.6.1.6.3.1.1.5.3` | `oid` (Trap OID) | Physical or logical interface transitioned to `down` (v1 `gentrap 2`) |
| **`linkUp`** | `1.3.6.1.6.3.1.1.5.4` | `oid` (Trap OID) | Physical or logical interface transitioned to `up` (v1 `gentrap 3`) |
| **`authenticationFailure`**| `1.3.6.1.6.3.1.1.5.5` | `oid` (Trap OID) | Agent received a poll with an invalid community string or bad credentials (v1 `gentrap 4`) |
| **`egpNeighborLoss`** | `1.3.6.1.6.3.1.1.5.6` | `oid` (Trap OID) | Exterior Gateway Protocol peer neighbor down (v1 `gentrap 5`) |

---

## 3. `SNMP1` (SNMPv1 — RFC 1157)

SNMPv1 is still widely encountered on legacy switches, PDUs, UPS battery controllers, environmental sensors, and printers. Unlike SNMPv2c/v3, **SNMPv1 uses a dedicated `Trap-PDU` packet format (`0xA4`)** with explicit `enterprise`, `agent-addr`, `generic-trap`, and `specific-trap` fields.

### 3.1 `SNMP1` Modifiers & Defaults

| Modifier | Syntax | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **PDU Type** | `GET` \| `GETNEXT` \| `SET` \| `RESPONSE` \| `TRAP` | `TRAP` | Selects the SNMPv1 PDU operation (`GETNEXT` has no underscore). `GETBULK` and `INFORM` are SNMPv2c/v3 only. |
| **`COMMUNITY`** | `COMMUNITY "<text>"` | `"public"` | Cleartext SNMPv1 community string (e.g., `"public"`, `"private"`). |
| **`REQID`** | `REQID <number>` | `1` | 32-bit `request-id` matching a `RESPONSE` to its `GET`, `GETNEXT`, or `SET` request. |
| **`SYSUPTIME`** | `SYSUPTIME <ticks>` | `0` | Populates the v1 `Trap-PDU` `time-stamp` header in hundredths of a second. |
| **`ENTERPRISE`**| `ENTERPRISE <oid>` | `"1.3.6.1.4.1"` | Originating vendor enterprise OID inside an SNMPv1 `Trap-PDU`. Falls back to `OID` if omitted. |
| **`OID`** | `OID <oid>` | None | Shorthand single-OID query (emits a `NULL` VarBind on `GET`/`GETNEXT`) or fallback enterprise/trap OID. |
| **`AGENTIP`** | `AGENTIP <ipv4>` | Sender IPv4 (`0.0.0.0` on IPv6) | Sets the 4-byte `agent-addr` field inside the SNMPv1 `Trap-PDU`. When running over **IPv6**, automatically defaults to `0.0.0.0` per **RFC 3584 §3.2**. |
| **`GENTRAP`** | `GENTRAP <0..6>` | `6` (or mapped from `OID`) | Generic trap integer (`0..=6`). Values `> 6` are rejected with a clear validation error. |
| **`SPECTRAP`** | `SPECTRAP <number>` | `0` (for `0..=5`), `1` (for `6`) | Vendor-specific trap code when `GENTRAP` is `6` (`enterpriseSpecific`). |
| **`VARBIND`** | `VARBIND <oid> <type> [val]` | Empty list | Appends an SMIv1 variable binding (`COUNTER64` is not permitted in `SNMP1`). |

### 3.2 All 7 SNMPv1 Generic Trap Codes (`GENTRAP 0..6`)

| `GENTRAP` Code | RFC 1157 Name | Standard `SPECTRAP` | Standard Notification OID Equivalent | Typical Trigger |
| :---: | :--- | :---: | :--- | :--- |
| **`0`** | `coldStart` | `0` | `1.3.6.1.6.3.1.1.5.1` | Device power-cycled or cold-booted |
| **`1`** | `warmStart` | `0` | `1.3.6.1.6.3.1.1.5.2` | SNMP agent service restarted (`systemctl restart snmpd`) |
| **`2`** | `linkDown` | `0` | `1.3.6.1.6.3.1.1.5.3` | Switch port or WAN link lost carrier (`ifIndex` included in VarBinds) |
| **`3`** | `linkUp` | `0` | `1.3.6.1.6.3.1.1.5.4` | Switch port or WAN link restored carrier |
| **`4`** | `authenticationFailure` | `0` | `1.3.6.1.6.3.1.1.5.5` | Unauthorized host polled the device with the wrong community string |
| **`5`** | `egpNeighborLoss` | `0` | `1.3.6.1.6.3.1.1.5.6` | EGP routing neighbor went down |
| **`6`** | `enterpriseSpecific` | `<vendor_code>` (e.g., `1`) | `<enterprise>.0.<spectrap>` | Vendor-defined alert (chassis fan failure, config change, UPS on battery) |

### 3.3 Compilable Example: `SNMP1` Polling, Tree Walking, `SET` & Generic/Enterprise Traps

```frameassembly
host nms_poller    { ip 10.100.1.10 mac 00:50:56:10:00:10 }
host legacy_switch { ip 10.100.1.50 mac 00:50:56:10:00:50 }
host ups_v6        { ip 2001:db8:100::50 }
host nms_v6        { ip 2001:db8:100::10 }

flow snmpv1_operations(nms, sw) {
    // 1. Poll sysDescr.0 and sysUpTime.0 (UDP 161) and receive RESPONSE
    nms -> sw snmp1 get community "public" reqid 1001 varbind 1.3.6.1.2.1.1.1.0 null varbind 1.3.6.1.2.1.1.3.0 null wait 2ms
    nms <- sw snmp1 response community "public" reqid 1001 varbind 1.3.6.1.2.1.1.1.0 string "Cisco IOS C2960 Software Version 15.2(7)E" varbind 1.3.6.1.2.1.1.3.0 timeticks 4320000 wait 5ms

    // 2. Walk the next MIB object with GETNEXT
    nms -> sw snmp1 getnext community "public" reqid 1002 varbind 1.3.6.1.2.1.1.1.0 null wait 2ms
    nms <- sw snmp1 response community "public" reqid 1002 varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.9.1.716 wait 5ms

    // 3. Update sysContact.0 with SNMPv1 SET
    nms -> sw snmp1 set community "private_rw" reqid 1003 varbind 1.3.6.1.2.1.1.4.0 string "noc-oncall@corp.example.com" wait 2ms
    nms <- sw snmp1 response community "private_rw" reqid 1003 varbind 1.3.6.1.2.1.1.4.0 string "noc-oncall@corp.example.com" wait 10ms

    // 4. Generic Trap: linkDown (gentrap 2, spectrap 0) on port ifIndex 5 (UDP 162)
    nms <- sw snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.1.716 agentip 10.100.1.50 gentrap 2 spectrap 0 sysuptime 4321000 varbind 1.3.6.1.2.1.2.2.1.1.5 int 5 varbind 1.3.6.1.2.1.2.2.1.2.5 string "GigabitEthernet0/5" varbind 1.3.6.1.2.1.2.2.1.8.5 int 2 wait 5ms

    // 5. Enterprise-Specific Trap: Cisco config change (gentrap 6, spectrap 1)
    nms <- sw snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.9.43.2 agentip 10.100.1.50 gentrap 6 spectrap 1 sysuptime 4321500 varbind 1.3.6.1.4.1.9.9.43.1.1.6.1.3.1 int 1
}

flow snmpv1_ipv6_rfc3584(nms, ups) {
    // Over IPv6, SNMPv1 Trap agent-addr automatically defaults to 0.0.0.0 per RFC 3584 Section 3.2
    nms <- ups snmp1 trap community "public" enterprise 1.3.6.1.4.1.318 gentrap 6 spectrap 5 sysuptime 90000 varbind 1.3.6.1.2.1.1.5.0 string "ups-row4-rack12"
}

compile {
    snmpv1_operations(nms_poller, legacy_switch)
    snmpv1_ipv6_rfc3584(nms_v6, ups_v6)
}
```

---

## 4. `SNMP2` (SNMPv2c — RFC 3416)

SNMPv2c modernizes SNMPv1 while keeping simple community-string authentication (`COMMUNITY "<text>"`). It introduces three major capabilities essential for production network monitoring:
1. **`GETBULK` (`NONREPEATERS` & `MAXREPETITIONS`):** Retrieves an entire table (such as 48 switch ports in `ifXTable`) in a single request/response round-trip instead of dozens of slow sequential `GETNEXT` packets.
   * `NONREPEATERS <n>` tells the agent that the first `<n>` OIDs in your request are scalar objects (like `sysUpTime.0`) that should only be fetched **once**.
   * `MAXREPETITIONS <m>` tells the agent to fetch up to `<m>` consecutive rows for each remaining tabular OID in your request.
2. **64-Bit Counters (`COUNTER64`):** Essential for 10G, 25G, 40G, 100G, and 400G interfaces where a 32-bit `ifInOctets` counter wraps in seconds.
3. **Unified `TRAP` vs. Acknowledged `INFORM` Notifications:**
   * **`TRAP` (`0xA7` `SNMPv2-Trap-PDU`):** Unacknowledged, fire-and-forget notification sent from agent to manager on **UDP port `162`**.
   * **`INFORM` (`0xA6` `InformRequest-PDU`):** Guaranteed-delivery notification sent on **UDP port `162`**. The receiving NMS (or peer manager) **must** reply with a `RESPONSE` packet carrying the same `REQID` and VarBinds so the sender knows the alert was received.

### 4.1 `SNMP2` Modifiers & Defaults

| Modifier | Syntax | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **PDU Type** | `GET` \| `GETNEXT` \| `GETBULK` \| `SET` \| `RESPONSE` \| `TRAP` \| `INFORM` | `TRAP` | Selects the SNMPv2c PDU operation (`GETNEXT` and `GETBULK` are single words). |
| **`COMMUNITY`** | `COMMUNITY "<text>"` | `"public"` | Cleartext SNMPv2c community string. |
| **`REQID`** | `REQID <number>` | `1` | 32-bit `request-id` correlating requests/informs with responses. |
| **`NONREPEATERS`** | `NONREPEATERS <count>` | `0` | Number of scalar VarBinds at the start of a `GETBULK` request fetched only once. |
| **`MAXREPETITIONS`**| `MAXREPETITIONS <rows>` | `10` | Maximum number of table rows returned per repeating OID in a `GETBULK` request. |
| **`SYSUPTIME`** | `SYSUPTIME <ticks>` | `0` | Value for the auto-prepended `sysUpTime.0` (`1.3.6.1.2.1.1.3.0`) VarBind on `TRAP` and `INFORM` PDUs. |
| **`OID`** | `OID <oid>` | `"1.3.6.1.6.3.1.1.5.3"` (`linkDown`) | Trap OID value for the auto-prepended `snmpTrapOID.0` (`1.3.6.1.6.3.1.1.4.1.0`) VarBind on `TRAP` and `INFORM` PDUs (or single-OID query shorthand on `GET`). |
| **`VARBIND`** | `VARBIND <oid> <type> [val]` | Empty list | Appends any of the 9 SMIv2 data types (`NULL`, `STRING`, `INT`, `TIMETICKS`, `IPVAL`, `OIDVAL`, `COUNTER32`, `GAUGE32`, `COUNTER64`). |

### 4.2 Compilable Example: `SNMP2` `GETBULK` Table Walk, All 9 `VARBIND` Types & `TRAP` vs. `INFORM`

```frameassembly
host zabbix_srv   { ip 172.16.10.10 mac 00:50:56:20:00:10 }
host spine_router { ip 172.16.10.1  mac 00:50:56:20:00:01 }

flow snmpv2c_monitoring_suite(nms, rtr) {
    // 1. High-speed GETBULK walk: fetch 1 scalar (sysUpTime.0) + up to 15 rows of ifHCInOctets
    nms -> rtr snmp2 getbulk community "spine_ro" reqid 2001 nonrepeaters 1 maxrepetitions 15 varbind 1.3.6.1.2.1.1.3.0 null varbind 1.3.6.1.2.1.31.1.1.1.6 null wait 2ms

    // 2. Agent RESPONSE showcasing multiple SMIv2 data types (TIMETICKS, STRING, INT, GAUGE32, COUNTER32, COUNTER64, IPVAL, OIDVAL)
    nms <- rtr snmp2 response community "spine_ro" reqid 2001 varbind 1.3.6.1.2.1.1.3.0 timeticks 9950000 varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.9.1.2870 varbind 1.3.6.1.2.1.2.2.1.2.1 string "HundredGigE0/0/0/0" varbind 1.3.6.1.2.1.2.2.1.8.1 int 1 varbind 1.3.6.1.2.1.2.2.1.5.1 gauge32 4294967295 varbind 1.3.6.1.2.1.2.2.1.14.1 counter32 0 varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 1844674407370955100 varbind 1.3.6.1.2.1.4.20.1.1.172.16.10.1 ipval 172.16.10.1 wait 5ms

    // 3. Unacknowledged SNMPv2c TRAP (UDP 162): linkUp (1.3.6.1.6.3.1.1.5.4)
    //    FrameAssembly automatically prepends sysUpTime.0 (9950050) and snmpTrapOID.0 (1.3.6.1.6.3.1.1.5.4)
    nms <- rtr snmp2 trap community "spine_trap" reqid 2002 sysuptime 9950050 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.2.2.1.1.1 int 1 varbind 1.3.6.1.2.1.2.2.1.2.1 string "HundredGigE0/0/0/0" wait 5ms

    // 4. Acknowledged SNMPv2c INFORM (UDP 162) + Manager RESPONSE handshake: BGP backward transition
    nms <- rtr snmp2 inform community "spine_inform" reqid 2003 sysuptime 9950100 oid 1.3.6.1.2.1.15.7.2 varbind 1.3.6.1.2.1.15.3.1.2.192.0.2.1 int 1 varbind 1.3.6.1.2.1.15.3.1.14.192.0.2.1 string "Hold Timer Expired" wait 2ms
    nms -> rtr snmp2 response community "spine_inform" reqid 2003 sysuptime 9950100 oid 1.3.6.1.2.1.15.7.2 varbind 1.3.6.1.2.1.15.3.1.2.192.0.2.1 int 1 varbind 1.3.6.1.2.1.15.3.1.14.192.0.2.1 string "Hold Timer Expired"
}

compile {
    snmpv2c_monitoring_suite(zabbix_srv, spine_router)
}
```

---

## 5. `SNMP3` (SNMPv3 USM Authentication & Encryption — RFC 3414 / 3826 / 7860)

Modern enterprise, data center, government, and PCI-DSS/HIPAA networks require **SNMPv3 User-Based Security Model (`USM`)** so management credentials and MIB payloads cannot be sniffed or forged on the wire.

### 5.1 Understanding the Three SNMPv3 Security Levels

FrameAssembly automatically sets the SNMPv3 `msgFlags` byte (`authFlag = 0x01`, `privFlag = 0x02`, `reportableFlag = 0x04`) based on which `AUTH` and `PRIV` modifiers you include on a statement:

1. **`noAuthNoPriv` (Unauthenticated, Cleartext — Omit `AUTH` and `PRIV`):**
   * Neither `authFlag` nor `privFlag` is set.
   * Used primarily for **RFC 3414 §4 Engine ID Discovery** (where the manager sends a probe with `user ""` and `engineid ""` to learn the agent's `msgAuthoritativeEngineID`, `msgAuthoritativeEngineBoots`, and `msgAuthoritativeEngineTime`) or lab diagnostics.
2. **`authNoPriv` (Signed Integrity, Cleartext Payload — Specify `AUTH` Only):**
   * Sets `authFlag` (`0x01`).
   * The `scopedPDU` remains readable in Wireshark without decryption keys, but the entire SNMPv3 packet is cryptographically signed with your localized HMAC key (`MD5`, `SHA`, `SHA256`, `SHA384`, or `SHA512`) and protected against replay attacks via `ENGINEBOOTS` and `ENGINETIME`.
3. **`authPriv` (Signed Integrity + Encrypted Payload — Specify Both `AUTH` and `PRIV`):**
   * Sets both `authFlag` (`0x01`) and `privFlag` (`0x02`).
   * FrameAssembly encrypts the `scopedPDU` (`DES-CBC` per RFC 3414 or `AES-128-CFB` per RFC 3826) using a deterministic 8-byte privacy salt (`0102030405060708`) for reproducible PCAP builds, then computes the truncated HMAC signature over the entire encrypted message.
   * *(Note: Per RFC 3414, encryption without authentication—`noAuthPriv`—is forbidden by the SNMPv3 standard and rejected by FrameAssembly.)*

### 5.2 `SNMP3` Modifiers & Cryptographic Algorithms

| Modifier | Syntax | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **PDU Type** | `GET` \| `GETNEXT` \| `GETBULK` \| `SET` \| `RESPONSE` \| `TRAP` \| `INFORM` \| `REPORT` | `TRAP` | Selects the SNMPv3 PDU operation (`reportableFlag` `0x04` is automatically enabled on confirmed PDUs `GET`, `GETNEXT`, `GETBULK`, `SET`, and `INFORM`). |
| **`USER`** | `USER "<username>"` | `"admin"` | USM `msgUserName` (use `""` for initial Engine ID discovery probes). |
| **`ENGINEID`** | `ENGINEID "<even_hex>"` | `"8000000001"` | Authoritative Engine ID as an even-length hexadecimal string (e.g., `"80001f8880aabbccddeeff"`), or `""` during discovery. |
| **`ENGINEBOOTS`** | `ENGINEBOOTS <count>` | `0` | `msgAuthoritativeEngineBoots` counter (number of times the SNMP engine has rebooted). |
| **`ENGINETIME`** | `ENGINETIME <seconds>` | `0` | `msgAuthoritativeEngineTime` in seconds since last boot (used in the AES-128 IV and anti-replay window). |
| **`CONTEXTNAME`** | `CONTEXTNAME "<text>"` | `""` | Optional VRF, bridge-domain, or per-VLAN MIB context inside `scopedPDU` (e.g., `"vrf-prod"`, `"vlan-100"`). |
| **`AUTH`** | `AUTH <MD5\|SHA\|SHA256\|SHA384\|SHA512> "<pass>"` | None (`noAuth`) | Localizes `<pass>` with `ENGINEID` and signs the packet: `MD5` (96-bit, RFC 3414), `SHA` (SHA-1 96-bit, RFC 3414), `SHA256` (128-bit, RFC 7860), `SHA384` (192-bit, RFC 7860), `SHA512` (256-bit, RFC 7860). |
| **`PRIV`** | `PRIV <DES\|AES> "<pass>"` | None (`noPriv`) | Localizes `<pass>` with `ENGINEID` (using the active `AUTH` hash function) and encrypts `scopedPDU` with `DES` (`DES-CBC`, RFC 3414) or `AES` (`AES-128-CFB`, RFC 3826). Requires `AUTH`. |
| **`REQID`** | `REQID <number>` | `1` | Populates both the outer SNMPv3 `msgID` and inner PDU `request-id`. |
| **`SYSUPTIME` / `OID`**| `SYSUPTIME <ticks>`, `OID <oid>` | `0` / `linkDown` | Auto-prepends `sysUpTime.0` and `snmpTrapOID.0` on SNMPv3 `TRAP` and `INFORM` PDUs. |

> **Important Syntax Rule — Keep Algorithm Keywords Unquoted:**
> Always write the algorithm keyword in `AUTH` and `PRIV` as an **unquoted keyword** followed by your **quoted passphrase string**:
> * **Correct:** `auth sha256 "MyAuthSecret123!" priv aes "MyPrivSecret456!"`
> * **Incorrect:** `auth "sha256" "MyAuthSecret123!"` (never put quotes around `md5`, `sha`, `sha256`, `sha384`, `sha512`, `des`, or `aes`).

### 5.3 Compilable Example: All Three `SNMP3` Security Levels (`noAuthNoPriv`, `authNoPriv` & `authPriv`)

```frameassembly
host noc_manager { ip 10.254.0.10 mac 00:50:56:fe:00:10 }
host core_router { ip 10.254.0.1  mac 00:50:56:fe:00:01 }
host mgr_v6      { ip 2001:db8:fe::10 }
host rtr_v6      { ip 2001:db8:fe::1 }

flow snmpv3_full_lifecycle(mgr, agent) {
    // 1. Level 1 — noAuthNoPriv: RFC 3414 Engine ID & timeline discovery probe + response
    mgr -> agent snmp3 get user "" engineid "" engineboots 0 enginetime 0 reqid 3001 wait 2ms
    mgr <- agent snmp3 response user "" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86400 reqid 3001 varbind 1.3.6.1.6.3.15.1.1.4.0 counter32 1 wait 2ms

    // 2. Level 2 — authNoPriv: Signed poll with HMAC-SHA-256 (RFC 7860), cleartext scopedPDU
    mgr -> agent snmp3 get user "auditor_ro" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86401 auth sha256 "AuditSha256Pass!" reqid 3002 varbind 1.3.6.1.2.1.1.5.0 null varbind 1.3.6.1.2.1.1.6.0 null wait 2ms
    mgr <- agent snmp3 response user "auditor_ro" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86401 auth sha256 "AuditSha256Pass!" reqid 3002 varbind 1.3.6.1.2.1.1.5.0 string "core-rtr-01.prod.example.com" varbind 1.3.6.1.2.1.1.6.0 string "DC1 Row-B Rack-04 RU-40" wait 5ms

    // 3. Level 3 — authPriv: Signed & encrypted SET, RESPONSE, TRAP, and INFORM (HMAC-SHA-512 + AES-128)
    mgr -> agent dscp 48 snmp3 set user "netadmin_rw" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86402 contextname "vrf-prod" auth sha512 "AdminSha512Key!" priv aes "AdminAes128Key!" reqid 3003 varbind 1.3.6.1.2.1.1.4.0 string "noc@example.com" wait 2ms
    mgr <- agent dscp 48 snmp3 response user "netadmin_rw" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86402 contextname "vrf-prod" auth sha512 "AdminSha512Key!" priv aes "AdminAes128Key!" reqid 3003 varbind 1.3.6.1.2.1.1.4.0 string "noc@example.com" wait 5ms

    // Encrypted SNMPv3 TRAP on UDP 162 (sysUpTime.0 and snmpTrapOID.0 auto-prepended)
    mgr <- agent dscp 48 snmp3 trap user "netadmin_rw" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86405 contextname "vrf-prod" auth sha512 "AdminSha512Key!" priv aes "AdminAes128Key!" reqid 3004 sysuptime 8640500 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.1.10 int 10 varbind 1.3.6.1.2.1.2.2.1.8.10 int 2 wait 5ms

    // Encrypted SNMPv3 INFORM + RESPONSE on UDP 162
    mgr <- agent dscp 48 snmp3 inform user "netadmin_rw" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86410 contextname "vrf-prod" auth sha512 "AdminSha512Key!" priv aes "AdminAes128Key!" reqid 3005 sysuptime 8641000 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.31.1.1.1.6.10 counter64 9988776655443322 wait 2ms
    mgr -> agent dscp 48 snmp3 response user "netadmin_rw" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86410 contextname "vrf-prod" auth sha512 "AdminSha512Key!" priv aes "AdminAes128Key!" reqid 3005 sysuptime 8641000 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.31.1.1.1.6.10 counter64 9988776655443322
}

compile {
    // Run the exact same SNMPv3 USM flow over IPv4 and IPv6
    snmpv3_full_lifecycle(noc_manager, core_router)
    snmpv3_full_lifecycle(mgr_v6, rtr_v6)
}
```

---

## 6. Decrypting & Replaying SNMPv3 Captures (`Wireshark`, `tshark` & `tcpreplay`)

Because FrameAssembly computes real RFC 3414 / 3826 / 7860 cryptographic keys, IVs, ciphertexts, and HMAC digests, Wireshark and `tshark` can verify the message signatures and decrypt `authPriv` packets right on your workstation.

### 6.1 Decrypting `SNMP3` in the Wireshark GUI
1. Build your `.fasm` packet capture and open it in Wireshark:
   ```bash
   frameassembly snmpv3_test.fasm -o snmpv3_test.pcap
   wireshark snmpv3_test.pcap
   ```
2. In Wireshark, navigate to **Edit $\rightarrow$ Preferences $\rightarrow$ Protocols $\rightarrow$ SNMP**.
3. Next to **Users Table**, click **Edit...** and click **`+`** to add a new USM user row matching your `.fasm` statement:
   * **Engine ID:** `80001f8880aabbccddeeff` *(leave blank to match any Engine ID)*
   * **Username:** `netadmin_rw`
   * **Authentication model:** `SHA2-512` *(or `MD5`, `SHA1`, `SHA2-256`, `SHA2-384`)*
   * **Password:** `AdminSha512Key!`
   * **Privacy protocol:** `AES` *(or `DES`)*
   * **Privacy password:** `AdminAes128Key!`
4. Click **OK**—Wireshark immediately decrypts the `encryptedPDU` payload, shows `[Authentication OK]`, and displays the inner `contextName` (`"vrf-prod"`), PDU type, and all `VarBind` OIDs and values.

### 6.2 Decrypting & Verifying `SNMP3` on the Linux CLI with `tshark`
You can pass the USM user table entry directly on the `tshark` command line without touching any GUI settings:

```bash
tshark -r snmpv3_test.pcap \
  -o 'uat:snmp_users:"80001f8880aabbccddeeff","netadmin_rw","SHA2-512","AdminSha512Key!","AES","AdminAes128Key!"' \
  -V
```

### 6.3 Replaying Traps into a Live Collector (`snmptrapd` / Zabbix / LibreNMS)
To test an alert pipeline or `snmptrapd` receiver on an interface (`eth0` or `lo`), replay your generated capture with `tcpreplay`:

```bash
# Replay at exact .fasm WAIT intervals
sudo tcpreplay --intf1=eth0 snmpv3_test.pcap

# Or blast traps at maximum speed to stress-test collector queues
sudo tcpreplay --intf1=eth0 --topspeed snmpv3_test.pcap
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — `.fasm` file anatomy, automatic defaults vs. explicit overrides, and step-by-step Wireshark workflows.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — Practical recipes for SNMP alerting, firewall ACL testing, QoS tagging, and telemetry validation.
- [**Layer 2 Switching & Data-Link Protocols (`l2_protocols.md`)**](l2_protocols.md) & [**Layer 3 Control, Tunneling, VPN & Routing Protocols (`l3_protocols.md`)**](l3_protocols.md) — Combine SNMP traps with `VLAN`, `QINQ`, `MPLS`, `DSCP`, `BGP`, `OSPF`, `VRRP`, and `BFD` failure scenarios.
- [**Layer 4 Transport Protocols (`l4_transports.md`)**](l4_transports.md) — `UDP`, `TCP`, and `SCTP` transport behaviors and port inheritance.
- [**Layer 7 Infrastructure, Time, AAA & Flow Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — Pair SNMP polling with `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`, `NTP`, `PTP`, `DNS`, `DHCP`, `RADIUS`, and `TACACS`.
- [**Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — End-to-end enterprise, data center, and Campus 802.1X NAC topologies with SNMPv3 reporting.
