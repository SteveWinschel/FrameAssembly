# Layer 7 Network Management: SNMPv1, SNMPv2c & SNMPv3 USM Cryptographic Engine Reference

FrameAssembly features a dedicated, RFC-compliant ASN.1 Basic Encoding Rules (BER) serializer and cryptographic User-based Security Model (USM) engine (`src/builders/l7/snmp/`) supporting all three Simple Network Management Protocol versions: **SNMPv1 (`SNMP1`, RFC 1157)**, **SNMPv2c (`SNMP2`, RFC 3416 / RFC 3418)**, and **SNMPv3 (`SNMP3`, RFC 3414 / RFC 3826 / RFC 7860)**.

Unlike template-based packet generators that emit static byte blobs, FrameAssembly dynamically encodes arbitrary Object Identifier (`OID`) trees using base-128 variable-length sub-identifiers, constructs nested ASN.1 `SEQUENCE` (`0x30`) containers with exact multi-byte BER lengths, derives localized authentication and privacy keys via RFC 3414 password-to-key (`Ku` $\to$ `Kul`) expansion, encrypts `scopedPDU` payloads using **DES-CBC** or **AES-128-CFB**, and computes truncated **HMAC-MD5-96**, **HMAC-SHA-96**, **HMAC-SHA-256-192**, **HMAC-SHA-384-256**, and **HMAC-SHA-512-384** message authentication codes.

---

## 1. SNMP Protocol Architecture & RFC Matrix

| Protocol | Keyword | Standard RFCs | Default UDP Ports | Security Model | Corpus Directory | Supported PDU Types |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SNMPv1** | `SNMP1` | RFC 1155, RFC 1157, RFC 1215 | `161` (Poll), `162` (Trap) | Community String (`COMMUNITY`) | [`examples/l7/snmp/snmpv1/`](../examples/l7/snmp/snmpv1) | `GET`, `GETNEXT`, `SET`, `RESPONSE`, `TRAP` (v1 Trap-PDU `0xA4`) |
| **SNMPv2c**| `SNMP2` | RFC 1901, RFC 3416, RFC 3418 | `161` (Poll), `162` (Trap/Inform)| Community String (`COMMUNITY`) | [`examples/l7/snmp/snmpv2c/`](../examples/l7/snmp/snmpv2c) | `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `TRAP` (`0xA7`), `INFORM` (`0xA6`) |
| **SNMPv3** | `SNMP3` | RFC 3411–3415, RFC 3826, RFC 7860 | `161` (Poll), `162` (Trap/Inform)| USM (`noAuthNoPriv`, `authNoPriv`, `authPriv`) | [`examples/l7/snmp/snmpv3/`](../examples/l7/snmp/snmpv3) | `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `TRAP` (`0xA7`), `INFORM` (`0xA6`) |

---

## 2. Complete SNMP Modifier & ASN.1 `VARBIND` Reference

### 2.1 PDU Types & Shared Modifiers (`SNMP1`, `SNMP2`, `SNMP3`)

| Modifier | Syntax | Argument Type | Description & Default |
| :--- | :--- | :--- | :--- |
| **PDU Type** | `GET` / `GETNEXT` / `SET` / `RESPONSE` / `TRAP` / `INFORM` / `GETBULK` / `REPORT` | Bare keyword (0-arg) | Selects ASN.1 context-specific PDU tag (`0xA0`..`0xA8`, default `GET`) |
| **Request ID** | `REQID <u32>` | `u32` | Sets 32-bit `request-id` correlating requests and responses |
| **Primary OID** | `OID <oid_or_str>` | Bare OID (`1.3.6.1...`) or quoted string | Appends a primary Object Identifier to the Variable Binding list |
| **System Uptime** | `SYSUPTIME <u32>` | `u32` | Sets `TimeTicks` (`1/100`s) in v1 Trap header or v2c/v3 `sysUpTime.0` varbind |
| **Typed VarBind** | `VARBIND <oid> <TYPE> [value]` | Compound modifier | Appends a strongly-typed SMIv1/SMIv2 `(OID, Type, Value)` tuple (multiple allowed per statement) |

> **Important Syntax & OID Validation Rules**: Always use `REQID <u32>` (never `REQ_ID`), `SYSUPTIME <u32>` (never `SYS_UPTIME`), `GETNEXT` (never `GET_NEXT`), and `GETBULK` (never `GET_BULK`). Both bare OID literals (`OID 1.3.6.1.2.1.1.1.0`) and quoted OID strings (`OID "1.3.6.1.2.1.1.1.0"`) are supported. Per ITU-T X.690 §8.19, the ASN.1 BER OID encoder strictly validates arc constraints: 1-arc OIDs (fewer than 2 arcs), root arcs outside `0..=2`, and second arcs `>= 40` under root arc `0` or `1` are rejected rather than silently clamped.

### 2.2 ASN.1 BER `VARBIND` Data Types (SMIv1 / SMIv2 — RFC 2578)

Every `SNMP1`, `SNMP2`, or `SNMP3` statement can include zero, one, or multiple `VARBIND <oid> <TYPE> <value>` clauses:

| `VARBIND` Type Keyword | Syntax Example | BER Tag | ASN.1 / SMIv2 Encoding Semantics |
| :--- | :--- | :--- | :--- |
| `NULL` or `NULLVAL` | `VARBIND 1.3.6.1.2.1.1.1.0 NULL` | `0x05 0x00` | ASN.1 `NULL` (used in `GET`, `GETNEXT`, `GETBULK` queries) |
| `STRING` | `VARBIND 1.3.6.1.2.1.1.5.0 STRING "core-rtr-01"` | `0x04` | ASN.1 `OCTET STRING` UTF-8 / ASCII text |
| `INT` | `VARBIND 1.3.6.1.2.1.2.2.1.8.1 INT 1` | `0x02` | Signed 32-bit two's complement `INTEGER` |
| `TIMETICKS` | `VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 8640000` | `0x43` | Application 3 `TimeTicks` in hundredths of a second |
| `IPVAL` | `VARBIND 1.3.6.1.2.1.4.20.1.1.10.0.0.1 IPVAL 10.0.0.1` | `0x40` | Application 0 `IpAddress` (4-octet IPv4 or 16-octet IPv6) |
| `OIDVAL` | `VARBIND 1.3.6.1.2.1.1.2.0 OIDVAL 1.3.6.1.4.1.9.1.1` | `0x06` | ASN.1 `OBJECT IDENTIFIER` value |
| `COUNTER32` | `VARBIND 1.3.6.1.2.1.2.2.1.10.1 COUNTER32 4590123` | `0x41` | Application 1 32-bit monotonically increasing counter |
| `GAUGE32` | `VARBIND 1.3.6.1.2.1.2.2.1.5.1 GAUGE32 1000000000` | `0x42` | Application 2 32-bit non-wrapping gauge / bandwidth |
| `COUNTER64` | `VARBIND 1.3.6.1.2.1.31.1.1.1.6.1 COUNTER64 98765432100` | `0x46` | Application 6 64-bit high-capacity counter (`ifHCInOctets`) |

---

## 3. SNMPv1 (`SNMP1` — RFC 1157)

SNMPv1 uses plaintext community strings (`COMMUNITY "<str>"`, default `"public"`) and defines a distinct `Trap-PDU` (`0xA4`) structure carrying enterprise OID, agent IPv4 address, generic trap type (`0..6`), specific trap code, and `sysUpTime` timestamp.

### 3.1 `SNMP1`-Specific Modifiers

| Modifier | Syntax | Argument Type | Description & Wire Default |
| :--- | :--- | :--- | :--- |
| **Community** | `COMMUNITY "<str>"` | Quoted string | Plaintext community string (default `"public"`) |
| **Enterprise OID** | `ENTERPRISE <oid>` | Bare or quoted OID | Enterprise OID in v1 `Trap-PDU` (e.g. `1.3.6.1.4.1.9.1.1`) |
| **Agent IP** | `AGENTIP <ipv4>` | IPv4 address | Originating `network-address` inside v1 `Trap-PDU` |
| **Generic Trap** | `GENTRAP <0..6>` | `u32` (`0..6`) | `0`=coldStart, `1`=warmStart, `2`=linkDown, `3`=linkUp, `4`=authFailure, `5`=egpNeighborLoss, `6`=enterpriseSpecific |
| **Specific Trap** | `SPECTRAP <u32>` | `u32` | Vendor-specific trap sub-code when `GENTRAP` is `6` |

### 3.2 Verified `SNMP1` Examples

```frameassembly
// PROMPT: SNMPv1 MIB-II system group polling (GET, GETNEXT, SET, RESPONSE) and RFC 1157 linkDown / enterpriseSpecific Traps.
// TOKENS: HOST, IP, MAC, FLOW, SNMP1, GET, GETNEXT, SET, RESPONSE, TRAP, COMMUNITY, REQID, ENTERPRISE, AGENTIP, GENTRAP, SPECTRAP, SYSUPTIME, VARBIND, NULL, STRING, INT, TIMETICKS, OIDVAL, WAIT, COMPILE

// INSTRUCTION: Declare the Network Management Station (NMS) poller.
host nms_poller {
    ip 10.100.1.10
    mac 00:50:56:a0:01:10
}

// INSTRUCTION: Declare the managed legacy campus access switch.
host legacy_switch {
    ip 10.100.1.50
    mac 00:1c:73:a0:01:50
}

// INSTRUCTION: Define SNMPv1 GET, GETNEXT, SET, and RESPONSE interactions alongside linkDown (GENTRAP 2) and enterpriseSpecific (GENTRAP 6) traps.
flow snmpv1_polling_and_traps(nms, agent) {
    nms -> agent snmp1 get community "public" reqid 1001 varbind 1.3.6.1.2.1.1.1.0 null varbind 1.3.6.1.2.1.1.3.0 null wait 2ms
    nms <- agent snmp1 response community "public" reqid 1001 varbind 1.3.6.1.2.1.1.1.0 string "Cisco IOS Software, C2960 Software Version 15.2" varbind 1.3.6.1.2.1.1.3.0 timeticks 4320000 wait 2ms
    nms -> agent snmp1 getnext community "public" reqid 1002 varbind 1.3.6.1.2.1.1.1.0 null wait 2ms
    nms <- agent snmp1 response community "public" reqid 1002 varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.9.1.716 wait 2ms
    nms -> agent snmp1 set community "private_rw" reqid 1003 varbind 1.3.6.1.2.1.1.6.0 string "Bldg-4-Wiring-Closet-2B" wait 2ms
    nms <- agent snmp1 response community "private_rw" reqid 1003 varbind 1.3.6.1.2.1.1.6.0 string "Bldg-4-Wiring-Closet-2B" wait 2ms
    nms <- agent snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.1.716 agentip 10.100.1.50 gentrap 2 spectrap 0 sysuptime 4320500 varbind 1.3.6.1.2.1.2.2.1.1.5 int 5 varbind 1.3.6.1.2.1.2.2.1.8.5 int 2 wait 2ms
    nms <- agent snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.9.43.2 agentip 10.100.1.50 gentrap 6 spectrap 1 sysuptime 4321000 varbind 1.3.6.1.4.1.9.9.43.1.1.6.1.3.1 int 1 wait 2ms
}

// INSTRUCTION: Compile the SNMPv1 management and trap capture.
compile {
    snmpv1_polling_and_traps(nms_poller, legacy_switch)
}
```

---

## 4. SNMPv2c (`SNMP2` — RFC 3416)

SNMPv2c introduces high-efficiency bulk table retrieval (`GETBULK` `0xA5` with `NONREPEATERS` and `MAXREPETITIONS`), 64-bit counters (`COUNTER64` for 10G/100G/400G `ifXTable` interfaces), unified `SNMPv2-Trap-PDU` (`0xA7`), and acknowledged manager-to-manager `InformRequest-PDU` (`INFORM` `0xA6`).

### 4.1 `SNMP2`-Specific Modifiers

| Modifier | Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **Community** | `COMMUNITY "<str>"` | Quoted string | Community string (default `"public"`) |
| **Bulk Non-Repeaters** | `NONREPEATERS <u32>` | `u32` | Scalar OIDs at the start of `GETBULK` fetched once |
| **Bulk Max-Repetitions**| `MAXREPETITIONS <u32>`| `u32` | Maximum lexicographic table rows returned per `GETBULK` |
| **Inform PDU** | `INFORM` | Bare keyword | Emits acknowledged `InformRequest-PDU` (`0xA6`) to UDP port `162` |

> **Important Syntax Rule**: Always use `NONREPEATERS` and `MAXREPETITIONS` (without underscores).

### 4.2 Verified `SNMP2` Examples

```frameassembly
// PROMPT: SNMPv2c high-capacity 400GbE interface table walk using GETBULK (COUNTER64, GAUGE32, COUNTER32, IPVAL) plus SNMPv2-Trap and acknowledged INFORM.
// TOKENS: HOST, IP, MAC, FLOW, SNMP2, GETBULK, RESPONSE, TRAP, INFORM, COMMUNITY, REQID, NONREPEATERS, MAXREPETITIONS, SYSUPTIME, OID, VARBIND, NULL, STRING, INT, COUNTER32, GAUGE32, COUNTER64, IPVAL, WAIT, COMPILE

// INSTRUCTION: Declare the Telemetry Collector NMS host.
host telemetry_nms {
    ip 172.16.10.10
    mac 00:50:56:16:10:10
}

// INSTRUCTION: Declare the Spine Router agent host.
host spine_router {
    ip 172.16.10.1
    mac 00:1c:73:16:10:01
}

// INSTRUCTION: Define an SNMPv2c GETBULK walk of ifXTable followed by an SNMPv2-Trap and an acknowledged INFORM notification.
flow snmpv2c_bulk_and_inform(nms, rtr) {
    nms -> rtr snmp2 getbulk community "spine_ro_v2c" reqid 2001 nonrepeaters 1 maxrepetitions 15 varbind 1.3.6.1.2.1.1.3.0 null varbind 1.3.6.1.2.1.31.1.1.1.1 null varbind 1.3.6.1.2.1.31.1.1.1.6 null wait 2ms
    nms <- rtr snmp2 response community "spine_ro_v2c" reqid 2001 varbind 1.3.6.1.2.1.31.1.1.1.1.1 string "Ethernet1/1" varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 1844674407370955100 varbind 1.3.6.1.2.1.31.1.1.1.15.1 gauge32 400000 varbind 1.3.6.1.2.1.2.2.1.14.1 counter32 0 varbind 1.3.6.1.2.1.4.20.1.1.172.16.10.1 ipval 172.16.10.1 wait 2ms
    nms <- rtr snmp2 trap community "spine_trap_v2c" reqid 2002 sysuptime 9950000 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.2.2.1.1.1 int 1 varbind 1.3.6.1.2.1.2.2.1.8.1 int 1 wait 2ms
    nms <- rtr snmp2 inform community "spine_inform_v2c" reqid 2003 sysuptime 9950100 oid 1.3.6.1.4.1.9.9.138.2.0.1 varbind 1.3.6.1.4.1.9.9.138.1.1.1.0 string "BGP_PEER_AS65002_ESTABLISHED" wait 2ms
    nms -> rtr snmp2 response community "spine_inform_v2c" reqid 2003 varbind 1.3.6.1.4.1.9.9.138.1.1.1.0 string "BGP_PEER_AS65002_ESTABLISHED" wait 2ms
}

// INSTRUCTION: Compile the SNMPv2c bulk walk, trap, and inform sequence.
compile {
    snmpv2c_bulk_and_inform(telemetry_nms, spine_router)
}
```

---

## 5. SNMPv3 USM Cryptographic Security (`SNMP3` — RFC 3414 / RFC 3826 / RFC 7860)

SNMPv3 replaces plaintext community strings with the **User-based Security Model (USM)**, providing replay protection via authoritative engine timelines (`ENGINEID`, `ENGINEBOOTS`, `ENGINETIME`), message integrity via keyed HMAC digests (`AUTH`), and confidentiality via symmetric encryption (`PRIV`).

### 5.1 Canonical `SNMP3` Modifiers

| Modifier | Syntax | Argument Type | Description & RFC Standard |
| :--- | :--- | :--- | :--- |
| **USM Username** | `USER "<username>"` | Quoted string | `msgUserName` in USM security parameters (default `"initial"`) |
| **Engine ID** | `ENGINEID "<hex>"` | Quoted hex string | Authoritative `msgAuthoritativeEngineID` (e.g. `"80001f888055667788"`) |
| **Engine Boots** | `ENGINEBOOTS <u32>` | `u32` | `msgAuthoritativeEngineBoots` reboot counter |
| **Engine Time** | `ENGINETIME <u32>` | `u32` | `msgAuthoritativeEngineTime` seconds since last engine boot |
| **Context Name** | `CONTEXTNAME "<str>"` | Quoted string | `contextName` inside `scopedPDU` for VRF/VLAN MIB views (default `""`) |
| **Authentication** | `AUTH <ALG> "<password>"` | Bare algorithm keyword + quoted password | Enables `authFlag` (`0x01`) and computes localized HMAC over full SNMPv3 message. Supported `<ALG>` keywords: `MD5`, `SHA`, `SHA256`, `SHA384`, `SHA512` |
| **Privacy (Encryption)**| `PRIV <ALG> "<password>"` | Bare algorithm keyword + quoted password | Enables `privFlag` (`0x02`) and encrypts `scopedPDU`. Supported `<ALG>` keywords: `DES` (RFC 3414 DES-CBC), `AES` (RFC 3826 AES-128-CFB) |

> **Critical Syntax Rule for `AUTH` and `PRIV`**:
> The algorithm identifier in `AUTH` and `PRIV` MUST be an **unquoted uppercase keyword** (`MD5`, `SHA`, `SHA256`, `SHA384`, `SHA512`, `DES`, `AES`) followed by the quoted passphrase string:
> - **Correct**: `AUTH SHA256 "AuthSecretPass123" PRIV AES "PrivSecretKey456"`
> - **Incorrect**: `AUTH "SHA256" "AuthSecretPass123"` (Never put quotes around the algorithm keyword!)
> - Also note: Always use `ENGINEID`, `ENGINEBOOTS`, `ENGINETIME`, and `CONTEXTNAME` (without underscores).

### 5.2 Supported USM Security Levels & Cryptographic Algorithms

1. **`noAuthNoPriv` (`msgFlags = 0x04`)**:
   - Specify `USER "<name>"` (or empty `USER ""` for RFC 3414 Engine ID discovery) without `AUTH` or `PRIV`.
2. **`authNoPriv` (`msgFlags = 0x05`)**:
   - Specify `USER "<name>" AUTH <MD5|SHA|SHA256|SHA384|SHA512> "<pass>"` without `PRIV`.
3. **`authPriv` (`msgFlags = 0x07`)**:
   - Specify both `AUTH <MD5|SHA|SHA256|SHA384|SHA512> "<auth_pass>"` and `PRIV <DES|AES> "<priv_pass>"`.
   - The compiler derives `Ku` via 1-megabyte password expansion, localizes `Kul` with the decoded `ENGINEID`, encrypts the ASN.1 `scopedPDU` using `DES-CBC` (64-bit salt IV) or `AES-128-CFB` (128-bit `ENGINEBOOTS || ENGINETIME || salt` IV), and writes the truncated HMAC into `msgAuthenticationParameters`.

### 5.3 Verified `SNMP3` Examples

#### Example A: RFC 3414 Engine ID Discovery, `noAuthNoPriv`, `authNoPriv` (HMAC-SHA-256), and `authPriv` (HMAC-SHA-512 + AES-128-CFB)
```frameassembly
// PROMPT: Complete SNMPv3 USM security progression from EngineID discovery to authNoPriv (SHA256) and authPriv (SHA512 + AES).
// TOKENS: HOST, IP, MAC, FLOW, SNMP3, GET, SET, RESPONSE, TRAP, USER, ENGINEID, ENGINEBOOTS, ENGINETIME, CONTEXTNAME, AUTH, PRIV, SHA256, SHA512, AES, REQID, VARBIND, NULL, STRING, INT, TIMETICKS, COUNTER64, WAIT, COMPILE

// INSTRUCTION: Declare the secure Network Operations Center (NOC) manager.
host noc_manager {
    ip 10.254.0.10
    mac 00:50:56:fe:00:10
}

// INSTRUCTION: Declare the core router SNMPv3 agent.
host core_agent {
    ip 10.254.0.1
    mac 00:1c:73:fe:00:01
}

// INSTRUCTION: Execute RFC 3414 Engine ID discovery, SHA256 authNoPriv polling, and SHA512 + AES authPriv configuration & trap.
flow snmpv3_usm_security_levels(mgr, agent) {
    mgr -> agent snmp3 get user "" engineid "" engineboots 0 enginetime 0 reqid 3001 wait 2ms
    mgr <- agent snmp3 response user "" engineid "80001f8880aabbccddeeff0011" engineboots 12 enginetime 86400 reqid 3001 varbind 1.3.6.1.6.3.15.1.1.4.0 int 1 wait 2ms
    mgr -> agent snmp3 get user "auditor_ro" engineid "80001f8880aabbccddeeff0011" engineboots 12 enginetime 86401 contextname "vrf-prod" auth sha256 "AuditSha256Pass!" reqid 3002 varbind 1.3.6.1.2.1.1.5.0 null wait 2ms
    mgr <- agent snmp3 response user "auditor_ro" engineid "80001f8880aabbccddeeff0011" engineboots 12 enginetime 86401 contextname "vrf-prod" auth sha256 "AuditSha256Pass!" reqid 3002 varbind 1.3.6.1.2.1.1.5.0 string "core-rtr-01.prod.example.com" wait 2ms
    mgr -> agent snmp3 set user "netadmin_rw" engineid "80001f8880aabbccddeeff0011" engineboots 12 enginetime 86402 contextname "vrf-prod" auth sha512 "AdminSha512MasterKey!" priv aes "AdminAes128CfbSecret!" reqid 3003 varbind 1.3.6.1.2.1.1.4.0 string "secops@example.com" wait 2ms
    mgr <- agent snmp3 response user "netadmin_rw" engineid "80001f8880aabbccddeeff0011" engineboots 12 enginetime 86402 contextname "vrf-prod" auth sha512 "AdminSha512MasterKey!" priv aes "AdminAes128CfbSecret!" reqid 3003 varbind 1.3.6.1.2.1.1.4.0 string "secops@example.com" wait 2ms
    mgr <- agent snmp3 trap user "netadmin_rw" engineid "80001f8880aabbccddeeff0011" engineboots 12 enginetime 86405 contextname "vrf-prod" auth sha512 "AdminSha512MasterKey!" priv aes "AdminAes128CfbSecret!" reqid 3004 varbind 1.3.6.1.2.1.1.3.0 timeticks 8640500 varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 9988776655443322 wait 2ms
}

// INSTRUCTION: Compile the SNMPv3 USM security progression capture.
compile {
    snmpv3_usm_security_levels(noc_manager, core_agent)
}
```

#### Example B: Dual-Stack IPv6 SNMPv3 Matrix Across All 5 HMAC Algorithms (`MD5`, `SHA`, `SHA256`, `SHA384`, `SHA512`) and Both Ciphers (`DES`, `AES`)
```frameassembly
// PROMPT: IPv6 SNMPv3 USM cryptographic verification across MD5, SHA, SHA256, SHA384, and SHA512 with DES-CBC and AES-128-CFB privacy.
// TOKENS: HOST, IP, MAC, FLOW, SNMP3, GET, GETBULK, INFORM, RESPONSE, USER, ENGINEID, ENGINEBOOTS, ENGINETIME, AUTH, PRIV, MD5, SHA, SHA256, SHA384, SHA512, DES, AES, NONREPEATERS, MAXREPETITIONS, REQID, VARBIND, NULL, STRING, GAUGE32, WAIT, COMPILE

// INSTRUCTION: Declare IPv6 Management Station.
host nms_v6 {
    ip 2001:db8:fe:161::10
    mac 00:50:56:61:61:10
}

// INSTRUCTION: Declare IPv6 Core Switch Agent.
host switch_v6 {
    ip 2001:db8:fe:161::1
    mac 00:1c:73:61:61:01
}

// INSTRUCTION: Exercise all five RFC 3414 / RFC 7860 authentication algorithms and both DES and AES privacy ciphers over IPv6.
flow ipv6_snmpv3_crypto_matrix(nms, sw) {
    nms -> sw snmp3 get user "u_md5_des" engineid "800000090300001c73616101" engineboots 5 enginetime 1000 auth md5 "Md5AuthKey999" priv des "DesPrivKey999" reqid 401 varbind 1.3.6.1.2.1.1.1.0 null wait 2ms
    nms <- sw snmp3 response user "u_md5_des" engineid "800000090300001c73616101" engineboots 5 enginetime 1000 auth md5 "Md5AuthKey999" priv des "DesPrivKey999" reqid 401 varbind 1.3.6.1.2.1.1.1.0 string "Arista EOS-4.32.1F" wait 2ms
    nms -> sw snmp3 get user "u_sha1_aes" engineid "800000090300001c73616101" engineboots 5 enginetime 1001 auth sha "Sha1AuthKey999" priv aes "AesPrivKey999" reqid 402 varbind 1.3.6.1.2.1.1.5.0 null wait 2ms
    nms -> sw snmp3 getbulk user "u_sha256_aes" engineid "800000090300001c73616101" engineboots 5 enginetime 1002 auth sha256 "Sha256AuthKey999" priv aes "AesPrivKey999" reqid 403 nonrepeaters 0 maxrepetitions 10 varbind 1.3.6.1.2.1.2.2.1.5 null wait 2ms
    nms -> sw snmp3 get user "u_sha384_aes" engineid "800000090300001c73616101" engineboots 5 enginetime 1003 auth sha384 "Sha384AuthKey999" priv aes "AesPrivKey999" reqid 404 varbind 1.3.6.1.2.1.2.2.1.5.1 gauge32 1000000000 wait 2ms
    nms <- sw snmp3 inform user "u_sha512_aes" engineid "800000090300001c73616101" engineboots 5 enginetime 1004 auth sha512 "Sha512AuthKey999" priv aes "AesPrivKey999" reqid 405 varbind 1.3.6.1.2.1.1.5.0 string "TRAP_OPTICAL_DOM_HIGH_TEMP" wait 2ms
}

// INSTRUCTION: Compile the IPv6 SNMPv3 cryptographic matrix flow.
compile {
    ipv6_snmpv3_crypto_matrix(nms_v6, switch_v6)
}
```

---

## 6. Tri-Version SNMP Coexistence & Cross-Layer Encapsulation (`SNMP1` + `SNMP2` + `SNMP3`)

In production enterprise and carrier networks, a single Network Management Station frequently polls legacy edge devices over `SNMP1`, high-speed switches over `SNMP2` (`GETBULK`), and core routers over `SNMP3` (`authPriv`), often encapsulated inside management VLANs (`VLAN 99`) or MPLS management VRF labels.

```frameassembly
// PROMPT: Tri-version SNMP coexistence audit combining SNMPv1 traps, SNMPv2c bulk walks, and SNMPv3 USM SHA256+AES polling over VLAN 99.
// TOKENS: HOST, IP, MAC, FLOW, VLAN, PCP, DSCP, SNMP1, SNMP2, SNMP3, GET, GETBULK, RESPONSE, TRAP, COMMUNITY, USER, ENGINEID, ENGINEBOOTS, ENGINETIME, AUTH, PRIV, SHA256, AES, ENTERPRISE, AGENTIP, GENTRAP, SPECTRAP, SYSUPTIME, NONREPEATERS, MAXREPETITIONS, REQID, VARBIND, NULL, STRING, INT, COUNTER64, TIMETICKS, WAIT, COMPILE

// INSTRUCTION: Declare the unified Network Management Station on Management VLAN 99.
host unified_nms {
    ip 10.99.0.10
    mac 00:50:56:99:00:10
}

// INSTRUCTION: Declare the multi-agent network appliance responding to v1, v2c, and v3 management queries.
host managed_appliance {
    ip 10.99.0.100
    mac 00:1c:73:99:00:64
}

// INSTRUCTION: Define a tri-version SNMP audit flow over 802.1Q VLAN 99 with CS2 (DSCP 16) OAM marking.
flow tri_version_snmp_audit(nms, dev) {
    nms <- dev vlan 99 pcp 2 dscp 16 snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.1.1 agentip 10.99.0.100 gentrap 3 spectrap 0 sysuptime 12000 varbind 1.3.6.1.2.1.2.2.1.1.1 int 1 wait 2ms
    nms -> dev vlan 99 pcp 2 dscp 16 snmp2 getbulk community "perf_ro" reqid 5001 nonrepeaters 1 maxrepetitions 5 varbind 1.3.6.1.2.1.1.3.0 null varbind 1.3.6.1.2.1.31.1.1.1.6 null wait 2ms
    nms <- dev vlan 99 pcp 2 dscp 16 snmp2 response community "perf_ro" reqid 5001 varbind 1.3.6.1.2.1.1.3.0 timeticks 12500 varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 45000123456 wait 2ms
    nms -> dev vlan 99 pcp 2 dscp 16 snmp3 get user "sec_auditor" engineid "80001f8880990064" engineboots 3 enginetime 5400 auth sha256 "SecAuditSha256!" priv aes "SecAuditAes128!" reqid 5002 varbind 1.3.6.1.2.1.1.1.0 null wait 2ms
    nms <- dev vlan 99 pcp 2 dscp 16 snmp3 response user "sec_auditor" engineid "80001f8880990064" engineboots 3 enginetime 5400 auth sha256 "SecAuditSha256!" priv aes "SecAuditAes128!" reqid 5002 varbind 1.3.6.1.2.1.1.1.0 string "FrameAssembly Multi-Version SNMP Agent v1.2.0" wait 2ms
}

// INSTRUCTION: Compile the tri-version SNMP coexistence audit flow.
compile {
    tri_version_snmp_audit(unified_nms, managed_appliance)
}
```
