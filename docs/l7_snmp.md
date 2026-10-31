# Layer 7 Network Management: SNMPv1, SNMPv2c & SNMPv3 USM Reference

FrameAssembly dynamically encodes ASN.1 Basic Encoding Rules (BER) structures, SMIv1/SMIv2 variable bindings (`VARBIND`), and full RFC 3414 / 3826 / 7860 SNMPv3 User-based Security Model (USM) authentication and encryption across **SNMPv1 (`SNMP1`)**, **SNMPv2c (`SNMP2`)**, and **SNMPv3 (`SNMP3`)**.

| Protocol | Keyword | Default UDP Ports | Security Model | Supported PDU Types |
| :--- | :--- | :--- | :--- | :--- |
| **SNMPv1** | `SNMP1` | `161` (Poll), `162` (Trap) | Community (`COMMUNITY`) | `GET`, `GETNEXT`, `SET`, `RESPONSE`, `TRAP` |
| **SNMPv2c**| `SNMP2` | `161` (Poll), `162` (Trap/Inform)| Community (`COMMUNITY`) | `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `TRAP`, `INFORM` |
| **SNMPv3** | `SNMP3` | `161` (Poll), `162` (Trap/Inform)| USM (`noAuthNoPriv`, `authNoPriv`, `authPriv`)| `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `TRAP`, `INFORM`, `REPORT` |

---

## 1. Shared Modifiers & All 9 `VARBIND` Data Types

* **PDU Type:** `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `TRAP`, `INFORM`, `REPORT` *(write `GETNEXT` and `GETBULK` without underscores)*.
* **Correlation & Uptime:** `REQID <u32>` *(no underscore)*, `SYSUPTIME <u32>` *(in 1/100ths of a second)*, `OID <oid>`.
* **OID Formatting:** Both unquoted (`1.3.6.1.2.1.1.5.0`) and quoted (`"1.3.6.1.2.1.1.5.0"`) OIDs are accepted. Root arcs must follow standard ITU-T X.690 rules (`0..=2`, with second arc `< 40` under roots `0` and `1`).

Every SNMP statement can include zero, one, or multiple `VARBIND <oid> <TYPE> [value]` clauses:

| `VARBIND` Type | Example Syntax | Wire Tag & Meaning |
| :--- | :--- | :--- |
| `NULL` or `NULLVAL` | `varbind 1.3.6.1.2.1.1.1.0 null` | `0x05` ASN.1 NULL (used in `GET`/`GETNEXT`/`GETBULK` queries) |
| `STRING` | `varbind 1.3.6.1.2.1.1.5.0 string "core-rtr-01"` | `0x04` OCTET STRING (UTF-8 / ASCII text) |
| `INT` | `varbind 1.3.6.1.2.1.2.2.1.8.1 int 2` | `0x02` Signed 32-bit INTEGER (e.g. `1`=up, `2`=down) |
| `TIMETICKS` | `varbind 1.3.6.1.2.1.1.3.0 timeticks 8640000` | `0x43` TimeTicks in hundredths of a second |
| `IPVAL` | `varbind 1.3.6.1.2.1.4.20.1.1.10.0.0.1 ipval 10.0.0.1`| `0x40` IPv4 (4B) or IPv6 (16B) address |
| `OIDVAL` | `varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.9.1.1` | `0x06` OBJECT IDENTIFIER value |
| `COUNTER32` | `varbind 1.3.6.1.2.1.2.2.1.10.1 counter32 4590123` | `0x41` 32-bit monotonically increasing counter |
| `GAUGE32` | `varbind 1.3.6.1.2.1.2.2.1.5.1 gauge32 1000000000` | `0x42` 32-bit non-wrapping gauge (speed, CPU, temp) |
| `COUNTER64` | `varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 98765432100`| `0x46` 64-bit high-capacity counter (`ifHCInOctets`) |

---

## 2. SNMPv1 (`SNMP1` — RFC 1157)

SNMPv1 uses plaintext community strings (`COMMUNITY "<str>"`, default `"public"`) and a dedicated v1 `Trap-PDU` header:
* `ENTERPRISE <oid>`: Originating vendor/object OID (e.g. `1.3.6.1.4.1.9.1.1`).
* `AGENTIP <ipv4>`: Originating IPv4 address inside the v1 Trap header.
* `GENTRAP <0..6>`: `0`=coldStart, `1`=warmStart, `2`=linkDown, `3`=linkUp, `4`=authenticationFailure, `5`=egpNeighborLoss, `6`=enterpriseSpecific.
* `SPECTRAP <u32>`: Vendor-specific trap code when `GENTRAP` is `6`.

```frameassembly
host nms_poller    { ip 10.100.1.10 }
host legacy_switch { ip 10.100.1.50 }

flow snmpv1_poll_and_traps(nms, sw) {
    nms -> sw snmp1 get community "public" reqid 1001 varbind 1.3.6.1.2.1.1.1.0 null wait 2ms
    nms <- sw snmp1 response community "public" reqid 1001 varbind 1.3.6.1.2.1.1.1.0 string "C2960 Software Version 15.2" wait 5ms

    // LinkDown trap (gentrap 2) and Enterprise-Specific trap (gentrap 6, spectrap 1)
    nms <- sw snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.1.716 agentip 10.100.1.50 gentrap 2 spectrap 0 sysuptime 4320500 varbind 1.3.6.1.2.1.2.2.1.1.5 int 5 varbind 1.3.6.1.2.1.2.2.1.8.5 int 2 wait 2ms
    nms <- sw snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.9.43.2 agentip 10.100.1.50 gentrap 6 spectrap 1 sysuptime 4321000 varbind 1.3.6.1.4.1.9.9.43.1.1.6.1.3.1 int 1
}

compile {
    snmpv1_poll_and_traps(nms_poller, legacy_switch)
}
```

---

## 3. SNMPv2c (`SNMP2` — RFC 3416)

Adds bulk table walks (`GETBULK` with `NONREPEATERS <u32>` and `MAXREPETITIONS <u32>`), 64-bit counters (`COUNTER64`), standard `TRAP` PDUs, and acknowledged `INFORM` notifications:

```frameassembly
host collector    { ip 172.16.10.10 }
host spine_router { ip 172.16.10.1 }

flow snmpv2c_bulk_trap_inform(nms, rtr) {
    nms -> rtr snmp2 getbulk community "spine_ro" reqid 2001 nonrepeaters 1 maxrepetitions 15 varbind 1.3.6.1.2.1.1.3.0 null varbind 1.3.6.1.2.1.31.1.1.1.6 null wait 2ms
    nms <- rtr snmp2 response community "spine_ro" reqid 2001 varbind 1.3.6.1.2.1.1.3.0 timeticks 9950000 varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 1844674407370955100 wait 5ms

    nms <- rtr snmp2 trap community "spine_trap" reqid 2002 sysuptime 9950050 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.2.2.1.1.1 int 1 wait 2ms
    nms <- rtr snmp2 inform community "spine_inform" reqid 2003 sysuptime 9950100 oid 1.3.6.1.2.1.15.7.1 varbind 1.3.6.1.2.1.15.3.1.2.192.0.2.1 int 6 wait 2ms
    nms -> rtr snmp2 response community "spine_inform" reqid 2003 varbind 1.3.6.1.2.1.15.3.1.2.192.0.2.1 int 6
}

compile {
    snmpv2c_bulk_trap_inform(collector, spine_router)
}
```

---

## 4. SNMPv3 USM Authentication & Encryption (`SNMP3`)

FrameAssembly derives localized authentication and privacy keys (`Ku` $\to$ `Kul`) from your passphrases and `ENGINEID`, encrypts the `scopedPDU` (`DES-CBC` or `AES-128-CFB`), and computes the truncated HMAC digest over the full message. To inspect encrypted payloads in Wireshark, add the same Username, EngineID, Auth protocol/password, and Priv protocol/password under *Edit $\rightarrow$ Preferences $\rightarrow$ Protocols $\rightarrow$ SNMP $\rightarrow$ Users Table*.

| Modifier | Syntax | Description |
| :--- | :--- | :--- |
| **Username** | `USER "<username>"` | USM username (`""` for Engine ID discovery) |
| **Engine ID** | `ENGINEID "<hex>"` | Authoritative Engine ID hex string (e.g. `"80001f888055667788"`) |
| **Engine Timeline**| `ENGINEBOOTS <u32>`, `ENGINETIME <u32>`| Reboot count and seconds since boot (for replay protection) |
| **Context Name** | `CONTEXTNAME "<str>"` | Optional VRF / VLAN MIB context inside `scopedPDU` |
| **Authentication**| `AUTH <MD5\|SHA\|SHA256\|SHA384\|SHA512> "<pass>"`| Enables `authFlag` and signs the message |
| **Encryption** | `PRIV <DES\|AES> "<pass>"` | Enables `privFlag` and encrypts `scopedPDU` (requires `AUTH`) |

> **Syntax Rule:** Keep the algorithm identifier in `AUTH` and `PRIV` **unquoted**—for example: `auth sha256 "MyAuthPass!" priv aes "MyPrivPass!"` (never put quotes around `sha256` or `aes`).

```frameassembly
host noc_mgr    { ip 10.254.0.10 }
host core_agent { ip 10.254.0.1 }

flow snmpv3_security_levels(mgr, agent) {
    // 1. Unauthenticated Engine ID discovery (noAuthNoPriv)
    mgr -> agent snmp3 get user "" engineid "" engineboots 0 enginetime 0 reqid 3001 wait 2ms
    mgr <- agent snmp3 response user "" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86400 reqid 3001 varbind 1.3.6.1.6.3.15.1.1.4.0 int 1 wait 2ms

    // 2. Signed poll without encryption (authNoPriv - HMAC-SHA256)
    mgr -> agent snmp3 get user "auditor_ro" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86401 auth sha256 "AuditSha256Pass!" reqid 3002 varbind 1.3.6.1.2.1.1.5.0 null wait 2ms
    mgr <- agent snmp3 response user "auditor_ro" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86401 auth sha256 "AuditSha256Pass!" reqid 3002 varbind 1.3.6.1.2.1.1.5.0 string "core-rtr-01.prod" wait 2ms

    // 3. Signed & encrypted SET and TRAP (authPriv - HMAC-SHA512 + AES-128)
    mgr -> agent snmp3 set user "netadmin_rw" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86402 contextname "vrf-prod" auth sha512 "AdminSha512Key!" priv aes "AdminAes128Key!" reqid 3003 varbind 1.3.6.1.2.1.1.4.0 string "noc@example.com" wait 2ms
    mgr <- agent snmp3 trap user "netadmin_rw" engineid "80001f8880aabbccddeeff" engineboots 12 enginetime 86405 contextname "vrf-prod" auth sha512 "AdminSha512Key!" priv aes "AdminAes128Key!" reqid 3004 varbind 1.3.6.1.2.1.1.3.0 timeticks 8640500 varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 9988776655443322
}

compile {
    snmpv3_security_levels(noc_mgr, core_agent)
}
```