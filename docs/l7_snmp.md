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
HOST nms_poller {
    IP 10.100.1.10
    MAC 00:50:56:a0:01:10
}

// INSTRUCTION: Declare the managed legacy campus access switch.
HOST legacy_switch {
    IP 10.100.1.50
    MAC 00:1c:73:a0:01:50
}

// INSTRUCTION: Define SNMPv1 GET, GETNEXT, SET, and RESPONSE interactions alongside linkDown (GENTRAP 2) and enterpriseSpecific (GENTRAP 6) traps.
FLOW snmpv1_polling_and_traps(nms, agent) {
    nms -> agent SNMP1 GET COMMUNITY "public" REQID 1001 VARBIND 1.3.6.1.2.1.1.1.0 NULL VARBIND 1.3.6.1.2.1.1.3.0 NULL WAIT 2ms
    nms <- agent SNMP1 RESPONSE COMMUNITY "public" REQID 1001 VARBIND 1.3.6.1.2.1.1.1.0 STRING "Cisco IOS Software, C2960 Software Version 15.2" VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 4320000 WAIT 2ms
    nms -> agent SNMP1 GETNEXT COMMUNITY "public" REQID 1002 VARBIND 1.3.6.1.2.1.1.1.0 NULL WAIT 2ms
    nms <- agent SNMP1 RESPONSE COMMUNITY "public" REQID 1002 VARBIND 1.3.6.1.2.1.1.2.0 OIDVAL 1.3.6.1.4.1.9.1.716 WAIT 2ms
    nms -> agent SNMP1 SET COMMUNITY "private_rw" REQID 1003 VARBIND 1.3.6.1.2.1.1.6.0 STRING "Bldg-4-Wiring-Closet-2B" WAIT 2ms
    nms <- agent SNMP1 RESPONSE COMMUNITY "private_rw" REQID 1003 VARBIND 1.3.6.1.2.1.1.6.0 STRING "Bldg-4-Wiring-Closet-2B" WAIT 2ms
    nms <- agent SNMP1 TRAP COMMUNITY "public" ENTERPRISE 1.3.6.1.4.1.9.1.716 AGENTIP 10.100.1.50 GENTRAP 2 SPECTRAP 0 SYSUPTIME 4320500 VARBIND 1.3.6.1.2.1.2.2.1.1.5 INT 5 VARBIND 1.3.6.1.2.1.2.2.1.8.5 INT 2 WAIT 2ms
    nms <- agent SNMP1 TRAP COMMUNITY "public" ENTERPRISE 1.3.6.1.4.1.9.9.43.2 AGENTIP 10.100.1.50 GENTRAP 6 SPECTRAP 1 SYSUPTIME 4321000 VARBIND 1.3.6.1.4.1.9.9.43.1.1.6.1.3.1 INT 1 WAIT 2ms
}

// INSTRUCTION: Compile the SNMPv1 management and trap capture.
COMPILE {
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
HOST telemetry_nms {
    IP 172.16.10.10
    MAC 00:50:56:16:10:10
}

// INSTRUCTION: Declare the Spine Router agent host.
HOST spine_router {
    IP 172.16.10.1
    MAC 00:1c:73:16:10:01
}

// INSTRUCTION: Define an SNMPv2c GETBULK walk of ifXTable followed by an SNMPv2-Trap and an acknowledged INFORM notification.
FLOW snmpv2c_bulk_and_inform(nms, rtr) {
    nms -> rtr SNMP2 GETBULK COMMUNITY "spine_ro_v2c" REQID 2001 NONREPEATERS 1 MAXREPETITIONS 15 VARBIND 1.3.6.1.2.1.1.3.0 NULL VARBIND 1.3.6.1.2.1.31.1.1.1.1 NULL VARBIND 1.3.6.1.2.1.31.1.1.1.6 NULL WAIT 2ms
    nms <- rtr SNMP2 RESPONSE COMMUNITY "spine_ro_v2c" REQID 2001 VARBIND 1.3.6.1.2.1.31.1.1.1.1.1 STRING "Ethernet1/1" VARBIND 1.3.6.1.2.1.31.1.1.1.6.1 COUNTER64 1844674407370955100 VARBIND 1.3.6.1.2.1.31.1.1.1.15.1 GAUGE32 400000 VARBIND 1.3.6.1.2.1.2.2.1.14.1 COUNTER32 0 VARBIND 1.3.6.1.2.1.4.20.1.1.172.16.10.1 IPVAL 172.16.10.1 WAIT 2ms
    nms <- rtr SNMP2 TRAP COMMUNITY "spine_trap_v2c" REQID 2002 SYSUPTIME 9950000 OID 1.3.6.1.6.3.1.1.5.4 VARBIND 1.3.6.1.2.1.2.2.1.1.1 INT 1 VARBIND 1.3.6.1.2.1.2.2.1.8.1 INT 1 WAIT 2ms
    nms <- rtr SNMP2 INFORM COMMUNITY "spine_inform_v2c" REQID 2003 SYSUPTIME 9950100 OID 1.3.6.1.4.1.9.9.138.2.0.1 VARBIND 1.3.6.1.4.1.9.9.138.1.1.1.0 STRING "BGP_PEER_AS65002_ESTABLISHED" WAIT 2ms
    nms -> rtr SNMP2 RESPONSE COMMUNITY "spine_inform_v2c" REQID 2003 VARBIND 1.3.6.1.4.1.9.9.138.1.1.1.0 STRING "BGP_PEER_AS65002_ESTABLISHED" WAIT 2ms
}

// INSTRUCTION: Compile the SNMPv2c bulk walk, trap, and inform sequence.
COMPILE {
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
HOST noc_manager {
    IP 10.254.0.10
    MAC 00:50:56:fe:00:10
}

// INSTRUCTION: Declare the core router SNMPv3 agent.
HOST core_agent {
    IP 10.254.0.1
    MAC 00:1c:73:fe:00:01
}

// INSTRUCTION: Execute RFC 3414 Engine ID discovery, SHA256 authNoPriv polling, and SHA512 + AES authPriv configuration & trap.
FLOW snmpv3_usm_security_levels(mgr, agent) {
    mgr -> agent SNMP3 GET USER "" ENGINEID "" ENGINEBOOTS 0 ENGINETIME 0 REQID 3001 WAIT 2ms
    mgr <- agent SNMP3 RESPONSE USER "" ENGINEID "80001f8880aabbccddeeff0011" ENGINEBOOTS 12 ENGINETIME 86400 REQID 3001 VARBIND 1.3.6.1.6.3.15.1.1.4.0 INT 1 WAIT 2ms
    mgr -> agent SNMP3 GET USER "auditor_ro" ENGINEID "80001f8880aabbccddeeff0011" ENGINEBOOTS 12 ENGINETIME 86401 CONTEXTNAME "vrf-prod" AUTH SHA256 "AuditSha256Pass!" REQID 3002 VARBIND 1.3.6.1.2.1.1.5.0 NULL WAIT 2ms
    mgr <- agent SNMP3 RESPONSE USER "auditor_ro" ENGINEID "80001f8880aabbccddeeff0011" ENGINEBOOTS 12 ENGINETIME 86401 CONTEXTNAME "vrf-prod" AUTH SHA256 "AuditSha256Pass!" REQID 3002 VARBIND 1.3.6.1.2.1.1.5.0 STRING "core-rtr-01.prod.example.com" WAIT 2ms
    mgr -> agent SNMP3 SET USER "netadmin_rw" ENGINEID "80001f8880aabbccddeeff0011" ENGINEBOOTS 12 ENGINETIME 86402 CONTEXTNAME "vrf-prod" AUTH SHA512 "AdminSha512MasterKey!" PRIV AES "AdminAes128CfbSecret!" REQID 3003 VARBIND 1.3.6.1.2.1.1.4.0 STRING "secops@example.com" WAIT 2ms
    mgr <- agent SNMP3 RESPONSE USER "netadmin_rw" ENGINEID "80001f8880aabbccddeeff0011" ENGINEBOOTS 12 ENGINETIME 86402 CONTEXTNAME "vrf-prod" AUTH SHA512 "AdminSha512MasterKey!" PRIV AES "AdminAes128CfbSecret!" REQID 3003 VARBIND 1.3.6.1.2.1.1.4.0 STRING "secops@example.com" WAIT 2ms
    mgr <- agent SNMP3 TRAP USER "netadmin_rw" ENGINEID "80001f8880aabbccddeeff0011" ENGINEBOOTS 12 ENGINETIME 86405 CONTEXTNAME "vrf-prod" AUTH SHA512 "AdminSha512MasterKey!" PRIV AES "AdminAes128CfbSecret!" REQID 3004 VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 8640500 VARBIND 1.3.6.1.2.1.31.1.1.1.6.1 COUNTER64 9988776655443322 WAIT 2ms
}

// INSTRUCTION: Compile the SNMPv3 USM security progression capture.
COMPILE {
    snmpv3_usm_security_levels(noc_manager, core_agent)
}
```

#### Example B: Dual-Stack IPv6 SNMPv3 Matrix Across All 5 HMAC Algorithms (`MD5`, `SHA`, `SHA256`, `SHA384`, `SHA512`) and Both Ciphers (`DES`, `AES`)
```frameassembly
// PROMPT: IPv6 SNMPv3 USM cryptographic verification across MD5, SHA, SHA256, SHA384, and SHA512 with DES-CBC and AES-128-CFB privacy.
// TOKENS: HOST, IP, MAC, FLOW, SNMP3, GET, GETBULK, INFORM, RESPONSE, USER, ENGINEID, ENGINEBOOTS, ENGINETIME, AUTH, PRIV, MD5, SHA, SHA256, SHA384, SHA512, DES, AES, NONREPEATERS, MAXREPETITIONS, REQID, VARBIND, NULL, STRING, GAUGE32, WAIT, COMPILE

// INSTRUCTION: Declare IPv6 Management Station.
HOST nms_v6 {
    IP 2001:db8:fe:161::10
    MAC 00:50:56:61:61:10
}

// INSTRUCTION: Declare IPv6 Core Switch Agent.
HOST switch_v6 {
    IP 2001:db8:fe:161::1
    MAC 00:1c:73:61:61:01
}

// INSTRUCTION: Exercise all five RFC 3414 / RFC 7860 authentication algorithms and both DES and AES privacy ciphers over IPv6.
FLOW ipv6_snmpv3_crypto_matrix(nms, sw) {
    nms -> sw SNMP3 GET USER "u_md5_des" ENGINEID "800000090300001c73616101" ENGINEBOOTS 5 ENGINETIME 1000 AUTH MD5 "Md5AuthKey999" PRIV DES "DesPrivKey999" REQID 401 VARBIND 1.3.6.1.2.1.1.1.0 NULL WAIT 2ms
    nms <- sw SNMP3 RESPONSE USER "u_md5_des" ENGINEID "800000090300001c73616101" ENGINEBOOTS 5 ENGINETIME 1000 AUTH MD5 "Md5AuthKey999" PRIV DES "DesPrivKey999" REQID 401 VARBIND 1.3.6.1.2.1.1.1.0 STRING "Arista EOS-4.32.1F" WAIT 2ms
    nms -> sw SNMP3 GET USER "u_sha1_aes" ENGINEID "800000090300001c73616101" ENGINEBOOTS 5 ENGINETIME 1001 AUTH SHA "Sha1AuthKey999" PRIV AES "AesPrivKey999" REQID 402 VARBIND 1.3.6.1.2.1.1.5.0 NULL WAIT 2ms
    nms -> sw SNMP3 GETBULK USER "u_sha256_aes" ENGINEID "800000090300001c73616101" ENGINEBOOTS 5 ENGINETIME 1002 AUTH SHA256 "Sha256AuthKey999" PRIV AES "AesPrivKey999" REQID 403 NONREPEATERS 0 MAXREPETITIONS 10 VARBIND 1.3.6.1.2.1.2.2.1.5 NULL WAIT 2ms
    nms -> sw SNMP3 GET USER "u_sha384_aes" ENGINEID "800000090300001c73616101" ENGINEBOOTS 5 ENGINETIME 1003 AUTH SHA384 "Sha384AuthKey999" PRIV AES "AesPrivKey999" REQID 404 VARBIND 1.3.6.1.2.1.2.2.1.5.1 GAUGE32 1000000000 WAIT 2ms
    nms <- sw SNMP3 INFORM USER "u_sha512_aes" ENGINEID "800000090300001c73616101" ENGINEBOOTS 5 ENGINETIME 1004 AUTH SHA512 "Sha512AuthKey999" PRIV AES "AesPrivKey999" REQID 405 VARBIND 1.3.6.1.2.1.1.5.0 STRING "TRAP_OPTICAL_DOM_HIGH_TEMP" WAIT 2ms
}

// INSTRUCTION: Compile the IPv6 SNMPv3 cryptographic matrix flow.
COMPILE {
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
HOST unified_nms {
    IP 10.99.0.10
    MAC 00:50:56:99:00:10
}

// INSTRUCTION: Declare the multi-agent network appliance responding to v1, v2c, and v3 management queries.
HOST managed_appliance {
    IP 10.99.0.100
    MAC 00:1c:73:99:00:64
}

// INSTRUCTION: Define a tri-version SNMP audit flow over 802.1Q VLAN 99 with CS2 (DSCP 16) OAM marking.
FLOW tri_version_snmp_audit(nms, dev) {
    nms <- dev VLAN 99 PCP 2 DSCP 16 SNMP1 TRAP COMMUNITY "public" ENTERPRISE 1.3.6.1.4.1.9.1.1 AGENTIP 10.99.0.100 GENTRAP 3 SPECTRAP 0 SYSUPTIME 12000 VARBIND 1.3.6.1.2.1.2.2.1.1.1 INT 1 WAIT 2ms
    nms -> dev VLAN 99 PCP 2 DSCP 16 SNMP2 GETBULK COMMUNITY "perf_ro" REQID 5001 NONREPEATERS 1 MAXREPETITIONS 5 VARBIND 1.3.6.1.2.1.1.3.0 NULL VARBIND 1.3.6.1.2.1.31.1.1.1.6 NULL WAIT 2ms
    nms <- dev VLAN 99 PCP 2 DSCP 16 SNMP2 RESPONSE COMMUNITY "perf_ro" REQID 5001 VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 12500 VARBIND 1.3.6.1.2.1.31.1.1.1.6.1 COUNTER64 45000123456 WAIT 2ms
    nms -> dev VLAN 99 PCP 2 DSCP 16 SNMP3 GET USER "sec_auditor" ENGINEID "80001f8880990064" ENGINEBOOTS 3 ENGINETIME 5400 AUTH SHA256 "SecAuditSha256!" PRIV AES "SecAuditAes128!" REQID 5002 VARBIND 1.3.6.1.2.1.1.1.0 NULL WAIT 2ms
    nms <- dev VLAN 99 PCP 2 DSCP 16 SNMP3 RESPONSE USER "sec_auditor" ENGINEID "80001f8880990064" ENGINEBOOTS 3 ENGINETIME 5400 AUTH SHA256 "SecAuditSha256!" PRIV AES "SecAuditAes128!" REQID 5002 VARBIND 1.3.6.1.2.1.1.1.0 STRING "FrameAssembly Multi-Version SNMP Agent v1.1.1" WAIT 2ms
}

// INSTRUCTION: Compile the tri-version SNMP coexistence audit flow.
COMPILE {
    tri_version_snmp_audit(unified_nms, managed_appliance)
}
```
