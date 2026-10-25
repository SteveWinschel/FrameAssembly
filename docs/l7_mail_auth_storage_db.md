# Layer 7 Electronic Mail, Directory Auth, Network Storage, Cache, Databases & Message Brokers Reference

FrameAssembly provides native, RFC-compliant wire builders for **14 Layer 7 Electronic Mail, Enterprise Identity & Directory Authentication, Network File Systems, In-Memory Key-Value Caches, Relational SQL Databases, and Message Broker** protocols across IPv4 and IPv6.

This canonical reference covers:
- **Electronic Mail Suite**: `SMTP` (RFC 5321), `IMAP` (RFC 9051 / RFC 3501), and `POP3` (RFC 1939)
- **Enterprise Identity & Directory Services**: `KERBEROS` (RFC 4120 v5) and `LDAP` (RFC 4511 v3)
- **Network File Storage & SAN/NAS**: `SMB` (MS-SMB2 v2/v3) and `NFS` (RFC 7530 / RFC 8881 NFSv4)
- **In-Memory Caching Tier**: `REDIS` (RESP2/RESP3) and `MEMCACHED` (ASCII / Binary Protocol)
- **Relational SQL Databases**: `MYSQL` (MySQL v10 Wire Protocol) and `POSTGRES` (PostgreSQL v3.0 Frontend/Backend Protocol)
- **Message Brokers & Constrained Pub/Sub**: `MQTT` (OASIS v3.1.1 / v5.0), `COAP` (RFC 7252), and `AMQP` (OASIS 0-9-1)

---

## 1. Protocol Architecture & RFC Matrix

| Protocol | Keyword | Standard Specification | Default Transport & Port | Corpus Directory | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SMTP** | `SMTP` | RFC 5321, RFC 3207 | TCP `25` / `587` | [`examples/l7/smtp/`](../examples/l7/smtp) | Mail relay (`EHLO`, `MAIL_FROM`, `RCPT_TO`, `PARAM`, `CODE`, `REPLY`, `BODY`) |
| **IMAP4rev2**| `IMAP` | RFC 9051, RFC 3501 | TCP `143` / `993` | [`examples/l7/imap/`](../examples/l7/imap) | Tagged mailbox operations (`TAG`, `CMD`, `ARG`, `PAYLOAD`) |
| **POP3** | `POP3` | RFC 1939 | TCP `110` / `995` | [`examples/l7/pop3/`](../examples/l7/pop3) | Mail retrieval (`CMD`, `ARG`, `OK`, `ERR`, `RESPONSE`) |
| **Kerberos** | `KERBEROS` | RFC 4120, RFC 3962 | UDP / TCP `88` | [`examples/l7/kerberos/`](../examples/l7/kerberos) | KDC tickets (`AS_REQ`, `AS_REP`, `TGS_REQ`, `TGS_REP`, `KRB_ERROR`, `REALM`, `CNAME`, `SNAME`, `ETYPE`) |
| **LDAPv3** | `LDAP` | RFC 4511 | TCP `389` / `636` | [`examples/l7/ldap/`](../examples/l7/ldap) | ASN.1 BER directory (`BIND_REQ`, `SEARCH_REQ`, `BASE_DN`, `FILTER`, `RESULT_CODE`) |
| **SMB2/3** | `SMB` | MS-SMB2 (v2.1 / v3.1.1) | TCP `445` | [`examples/l7/smb/`](../examples/l7/smb) | Network shares (`COMMAND`, `STATUS`, `TREE_ID`, `SESSION_ID`, `SHARE`, `FILENAME`) |
| **NFSv4** | `NFS` | RFC 7530, RFC 8881 | TCP / UDP `2049` | [`examples/l7/nfs/`](../examples/l7/nfs) | ONC-RPC file system (`VERS`, `PROC`, `TAG`, `PATH`) |
| **Redis** | `REDIS` | RESP2 / RESP3 | TCP `6379` | [`examples/l7/redis/`](../examples/l7/redis) | In-memory data store (`CMD`, `ARGS`, `REPLY_TYPE`/`REPLY`, `VALUE`, `PAYLOAD`) |
| **Memcached**| `MEMCACHED`| Memcached Text/Binary | TCP / UDP `11211` | [`examples/l7/memcached/`](../examples/l7/memcached)| Distributed object cache (`CMD`, `KEY`, `EXPTIME`, `OPCODE`, `OPAQUE`, `CAS`) |
| **MySQL** | `MYSQL` | MySQL v10 Client/Server | TCP `3306` | [`examples/l7/mysql/`](../examples/l7/mysql) | Relational SQL (`GREETING`, `LOGIN`, `SQL`/`QUERY`, `OK`, `ERR`, `EOF`, `DB`, `ERRCODE`) |
| **PostgreSQL**| `POSTGRES`| PostgreSQL v3.0 Wire | TCP `5432` | [`examples/l7/postgres/`](../examples/l7/postgres) | Relational SQL (`STARTUP`, `AUTH_OK`, `SQL`/`QUERY`, `COMMAND_COMPLETE`, `READY_FOR_QUERY`) |
| **MQTT** | `MQTT` | OASIS MQTT v3.1.1 / v5.0| TCP `1883` / `8883` | [`examples/l7/mqtt/`](../examples/l7/mqtt) | IoT pub/sub (`CONNECT`, `CONNACK`, `PUBLISH`, `SUBSCRIBE`, `TOPIC`, `QOS`, `RETAIN`, `PKT_ID`/`PKTID`) |
| **CoAP** | `COAP` | RFC 7252, RFC 7641 | UDP `5683` | [`examples/l7/coap/`](../examples/l7/coap) | Constrained REST (`CON`, `NON`, `ACK`, `RST`, `CODE`, `TOKEN`, `CONTENT_FORMAT`) |
| **AMQP** | `AMQP` | OASIS AMQP 0-9-1 | TCP `5672` | [`examples/l7/amqp/`](../examples/l7/amqp) | Message broker (`PROTOCOL_HEADER`, `CONNECTION_START`, `CHANNEL_OPEN`, `BASIC_PUBLISH`, `BASIC_DELIVER`, `HEARTBEAT`) |

---

## 2. Electronic Mail Suite (`SMTP`, `IMAP`, `POP3`)

### 2.1 Canonical Mail Protocol Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`SMTP`** | `EHLO "<domain>"` / `HELO "<domain>"` or bare `EHLO` / `HELO` | Optional String | Client ESMTP greeting with originating FQDN |
| **`SMTP`** | `MAIL_FROM` / `RCPT_TO` / `QUIT` | Bare flag (0-arg) | Standard RFC 5321 envelope commands (combine with `PARAM "<addr>"`) |
| **`SMTP`** | `CMD "<verb>"` / `PARAM "<arg>"` | Quoted string | Explicit SMTP command (e.g. `"STARTTLS"`, `"AUTH"`) and parameter |
| **`SMTP`** | `CODE <u32>` / `REPLY "<text>"` | `u32`, String | 3-digit server reply code (`220`, `250`, `354`, `221`) and banner/status text |
| **`SMTP`** | `BODY "<mime_msg>"` | Quoted string | RFC 5322 email headers and message body (terminated with `\r\n.\r\n`) |
| **`IMAP`** | `TAG "<tag>"` | Quoted string | Alphanumeric command tag (e.g. `"A001"`, `"A002"`, `"*"` for untagged) |
| **`IMAP`** | `CMD "<command>"` / `ARG "<args>"` | Quoted string | IMAP command (`"CAPABILITY"`, `"LOGIN"`, `"SELECT"`, `"FETCH"`, `"LOGOUT"`) and arguments |
| **`POP3`** | `CMD "<command>"` / `ARG "<arg>"` | Quoted string | POP3 command (`"USER"`, `"PASS"`, `"STAT"`, `"LIST"`, `"RETR"`, `"DELE"`, `"QUIT"`) |
| **`POP3`** | `OK` / `ERR` / `RESPONSE "<str>"` | Flag, String | POP3 server `+OK` or `-ERR` status indicator and response text |

> **Important Syntax Rule**:
> - In `SMTP`, `MAIL_FROM` and `RCPT_TO` are 0-argument flags; pass the email address using `PARAM "<email>"` (e.g., `SMTP MAIL_FROM PARAM "alice@corp.example.com"`).
> - In `IMAP` and `POP3`, use `PAYLOAD "<response_line>"` (or `RESPONSE "<str>"` in `POP3`) for server completion lines (`A001 OK LOGIN completed`, `+OK 2 messages (320 octets)`).

### 2.2 Verified `SMTP`, `IMAP`, and `POP3` Example

```frameassembly
// PROMPT: Enterprise email lifecycle covering SMTP message submission (RFC 5321), IMAP4rev2 folder synchronization (RFC 9051), and POP3 spool retrieval (RFC 1939).
// TOKENS: HOST, IP, MAC, FLOW, SMTP, CODE, REPLY, EHLO, MAIL_FROM, RCPT_TO, PARAM, BODY, QUIT, IMAP, TAG, CMD, ARG, POP3, OK, ERR, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare Mail User Agent (MUA) workstation.
HOST mua_client {
    IP 10.30.1.50
    MAC 00:50:56:30:01:50
}

// INSTRUCTION: Declare Unified Mail Transfer & Mailstore Server.
HOST mail_server {
    IP 10.30.1.10
    MAC 00:1c:73:30:01:10
}

// INSTRUCTION: Define SMTP submission, IMAP tagged session, and POP3 mailbox retrieval.
FLOW enterprise_mail_suite(mua, mta) {
    mua <- mta SMTP CODE 220 REPLY "mx01.corp.example.com ESMTP Postfix" WAIT 1ms
    mua -> mta SMTP EHLO "ws01.corp.example.com" WAIT 1ms
    mua <- mta SMTP CODE 250 REPLY "mx01.corp.example.com PIPELINING SIZE 52428800 STARTTLS" WAIT 1ms
    mua -> mta SMTP MAIL_FROM PARAM "alice@corp.example.com" WAIT 1ms
    mua <- mta SMTP CODE 250 REPLY "2.1.0 Ok" WAIT 1ms
    mua -> mta SMTP RCPT_TO PARAM "bob@corp.example.com" WAIT 1ms
    mua <- mta SMTP CODE 250 REPLY "2.1.5 Ok" WAIT 1ms
    mua -> mta SMTP BODY "Subject: Q4 Architecture Review\r\nFrom: alice@corp.example.com\r\nTo: bob@corp.example.com\r\n\r\nPlease review the updated topology." WAIT 2ms
    mua <- mta SMTP CODE 250 REPLY "2.0.0 Ok: queued as 4X9z8B1234" WAIT 1ms
    mua -> mta SMTP QUIT WAIT 1ms
    mua <- mta SMTP CODE 221 REPLY "2.0.0 Bye" WAIT 1ms
    mua -> mta IMAP TAG "A001" CMD "LOGIN" ARG "bob@corp.example.com SecretPass!" WAIT 1ms
    mua <- mta IMAP TAG "A001" PAYLOAD "A001 OK [CAPABILITY IMAP4rev2] Logged in" WAIT 1ms
    mua -> mta IMAP TAG "A002" CMD "SELECT" ARG "INBOX" WAIT 1ms
    mua <- mta IMAP TAG "A002" PAYLOAD "* 12 EXISTS\r\nA002 OK [READ-WRITE] Select completed" WAIT 1ms
    mua -> mta IMAP TAG "A003" CMD "FETCH" ARG "12 (FLAGS BODY[HEADER])" WAIT 1ms
    mua <- mta IMAP TAG "A003" PAYLOAD "* 12 FETCH (FLAGS (\\Seen))\r\nA003 OK Fetch completed" WAIT 1ms
    mua -> mta POP3 CMD "USER" ARG "bob" WAIT 1ms
    mua <- mta POP3 OK PAYLOAD "User accepted" WAIT 1ms
    mua -> mta POP3 CMD "PASS" ARG "SecretPass!" WAIT 1ms
    mua <- mta POP3 OK PAYLOAD "Mailbox locked and ready" WAIT 1ms
    mua -> mta POP3 CMD "STAT" WAIT 1ms
    mua <- mta POP3 OK PAYLOAD "12 48920" WAIT 1ms
    mua -> mta POP3 CMD "RETR" ARG "12" WAIT 1ms
    mua <- mta POP3 ERR PAYLOAD "Message 999 does not exist" WAIT 1ms
    mua -> mta POP3 CMD "QUIT" WAIT 1ms
}

// INSTRUCTION: Compile the SMTP, IMAP, and POP3 email suite capture.
COMPILE {
    enterprise_mail_suite(mua_client, mail_server)
}
```

---

## 3. Enterprise Identity & Directory Services (`KERBEROS` & `LDAP`)

### 3.1 Canonical `KERBEROS` (RFC 4120) and `LDAP` (RFC 4511) Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`KERBEROS`**| `AS_REQ` / `AS_REP` / `TGS_REQ` / `TGS_REP` / `KRB_ERROR` | Bare flag (0-arg) | RFC 4120 KDC message types (`10`, `11`, `12`, `13`, `30`) on UDP/TCP port `88` |
| **`KERBEROS`**| `REALM "<REALM>"` | Quoted string | Kerberos realm name (`GeneralString`, e.g. `"CORP.EXAMPLE.COM"`) |
| **`KERBEROS`**| `CNAME "<principal>"` / `SNAME "<service>"` | Quoted string | Client Principal Name and Service Principal Name (`"krbtgt/..."`, `"ldap/..."`, `"cifs/..."`) |
| **`KERBEROS`**| `ETYPE <u32>` | `u32` | RFC 3962 Encryption Type (`18` = `aes256-cts-hmac-sha1-96`, `17` = `aes128`, `23` = `rc4-hmac`) |
| **`LDAP`** | `BIND_REQ` / `BIND_RES` / `SEARCH_REQ` / `SEARCH_ENTRY` / `SEARCH_DONE` / `UNBIND_REQ` | Bare flag (0-arg) | RFC 4511 ASN.1 BER LDAPv3 `protocolOp` choice (`0x60`, `0x61`, `0x63`, `0x64`, `0x65`, `0x42`) on TCP `389` |
| **`LDAP`** | `MSGID <u32>` | `u32` | LDAP envelope `messageID` integer (`1, 2, 3...`) |
| **`LDAP`** | `BASE_DN "<dn>"` / `FILTER "<ldap_filter>"` | Quoted string | Distinguished Name (`BASE_DN`, never `DN`) and search filter string |
| **`LDAP`** | `RESULT_CODE <u32>` | `u32` | `LDAPResult` status (`0` = `success`, `49` = `invalidCredentials`) |

#### Wire Encoding Invariants (`KERBEROS`, `LDAP`)
- **`KERBEROS` RFC 4120 ASN.1 DER Structure (`src/builders/l7/kerberos.rs`)**:
  - **`KDC-REQ` (`AS_REQ` APPLICATION 10 `0x6A`, `TGS_REQ` APPLICATION 12 `0x6C`)**: Encodes SEQUENCE containing `[1] pvno (5)`, `[2] msg-type (10 or 12)`, and `[4] req-body (KDC-REQ-BODY)`. `KDC-REQ-BODY` encodes `[0] kdc-options` (BIT STRING), `[1] cname` (`PrincipalName` from `CNAME`), `[2] realm` (`Realm` from `REALM`), `[3] sname` (`PrincipalName` from `SNAME`), **`[7] till` (`GeneralizedTime` `"20370913024805Z"`)**, **`[8] nonce` (`UInt32`)**, and `[9] etype` (`SEQUENCE OF Int32` from `ETYPE`).
  - **`KDC-REP` (`AS_REP` APPLICATION 11 `0x6B`, `TGS_REP` APPLICATION 13 `0x6D`)**: Encodes `[0] pvno (5)`, `[1] msg-type (11 or 13)`, `[3] crealm` (`REALM`), `[4] cname` (`CNAME`), `[5] ticket` (APPLICATION 1 `Ticket` containing `tkt-vno=5`, `realm`, `sname`, and `enc-part`), and `[6] enc-part` (`EncryptedData` with `ETYPE`).
  - **`KRB_ERROR` (APPLICATION 30 `0x7E`)**: Encodes `[0] pvno (5)`, `[1] msg-type (30)`, `[4] stime`, `[5] susec`, `[6] error-code (25 = KDC_ERR_PREAUTH_REQUIRED)`, `[7] crealm`, `[8] cname` (`CNAME`), `[9] realm` (`REALM`), and `[10] sname` (`SNAME`).
- **`LDAP` All 8 Mandatory RFC 4511 §4.5.1 `SearchRequest` (`0x63`) ASN.1 BER Fields (`src/builders/l7/ldap.rs`)**:
  - Every LDAPv3 frame wraps `[messageID (INTEGER MSGID), protocolOp]` inside an outer `LDAPMessage` SEQUENCE (`0x30`).
  - **`SEARCH_REQ` (`0x63` APPLICATION 3 Constructed)**: Strictly encodes all **8 mandatory RFC 4511 §4.5.1 BER fields** so Wireshark's LDAP dissector parses the filter and attributes without error:
    1. `baseObject`: `0x04` OCTET STRING (`BASE_DN`)
    2. `scope`: `0x0A 0x01 0x02` ENUMERATED (`2` = `wholeSubtree`)
    3. `derefAliases`: `0x0A 0x01 0x00` ENUMERATED (`0` = `neverDerefAliases`)
    4. `sizeLimit`: `0x02 0x01 0x00` INTEGER (`0` = no limit)
    5. `timeLimit`: `0x02 0x01 0x00` INTEGER (`0` = no limit)
    6. `typesOnly`: `0x01 0x01 0x00` BOOLEAN (`FALSE`)
    7. `filter`: Context-specific `Filter` choice (e.g., `0x87` `present` filter or `0xA3` `equalityMatch` parsed from `FILTER`)
    8. `attributes`: `0x30` SEQUENCE of OCTET STRINGs (`AttributeSelection`)
  - **Other `protocolOp` Choices**: `BIND_REQ` (`0x60`: version `3`, `name` `BASE_DN`, simple auth `0x80`), `BIND_RES` (`0x61`: `LDAPResult` with `RESULT_CODE`), `SEARCH_ENTRY` (`0x64`: `objectName` `BASE_DN` + `PartialAttributeList`), `SEARCH_DONE` (`0x65`: `LDAPResult` with `RESULT_CODE`), and `UNBIND_REQ` (`0x42 0x00` NULL).

> **Important Syntax Rule**: In `LDAP`, always specify Distinguished Names with `BASE_DN "<dn>"` (never `DN "<dn>"`), and omit `VERSION 3` on `LDAP` statements (LDAPv3 version `3` is automatically encoded by the ASN.1 BER builder).

### 3.2 Verified `KERBEROS` v5 and `LDAP` v3 Active Directory Logon Example

```frameassembly
// PROMPT: Active Directory domain logon combining Kerberos v5 AS/TGS ticket exchange (AES-256) and LDAPv3 directory bind, search, and unbind.
// TOKENS: HOST, IP, MAC, FLOW, KERBEROS, AS_REQ, AS_REP, TGS_REQ, TGS_REP, KRB_ERROR, REALM, CNAME, SNAME, ETYPE, LDAP, BIND_REQ, BIND_RES, SEARCH_REQ, SEARCH_ENTRY, SEARCH_DONE, UNBIND_REQ, MSGID, BASE_DN, FILTER, RESULT_CODE, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare Domain Member Workstation.
HOST ad_workstation {
    IP 10.45.1.100
    MAC 00:50:56:45:01:64
}

// INSTRUCTION: Declare Active Directory Domain Controller (KDC + LDAP).
HOST domain_controller {
    IP 10.45.1.10
    MAC 00:1c:73:45:01:10
}

// INSTRUCTION: Execute Kerberos pre-auth error, AS_REQ/AS_REP TGT issuance, TGS_REQ/TGS_REP service ticket, and LDAPv3 group lookup.
FLOW active_directory_kerberos_ldap(ws, dc) {
    ws -> dc KERBEROS AS_REQ REALM "CORP.EXAMPLE.COM" CNAME "jdoe" SNAME "krbtgt/CORP.EXAMPLE.COM" ETYPE 18 WAIT 1ms
    ws <- dc KERBEROS KRB_ERROR REALM "CORP.EXAMPLE.COM" CNAME "jdoe" SNAME "krbtgt/CORP.EXAMPLE.COM" PAYLOAD "KRB5KDC_ERR_PREAUTH_REQUIRED_25" WAIT 1ms
    ws -> dc KERBEROS AS_REQ REALM "CORP.EXAMPLE.COM" CNAME "jdoe" SNAME "krbtgt/CORP.EXAMPLE.COM" ETYPE 18 PAYLOAD "PA_ENC_TIMESTAMP_AES256" WAIT 1ms
    ws <- dc KERBEROS AS_REP REALM "CORP.EXAMPLE.COM" CNAME "jdoe" SNAME "krbtgt/CORP.EXAMPLE.COM" ETYPE 18 WAIT 1ms
    ws -> dc KERBEROS TGS_REQ REALM "CORP.EXAMPLE.COM" CNAME "jdoe" SNAME "ldap/dc01.corp.example.com" ETYPE 18 WAIT 1ms
    ws <- dc KERBEROS TGS_REP REALM "CORP.EXAMPLE.COM" CNAME "jdoe" SNAME "ldap/dc01.corp.example.com" ETYPE 18 WAIT 1ms
    ws -> dc LDAP BIND_REQ MSGID 1 BASE_DN "cn=jdoe,ou=Users,dc=corp,dc=example,dc=com" WAIT 1ms
    ws <- dc LDAP BIND_RES MSGID 1 RESULT_CODE 0 WAIT 1ms
    ws -> dc LDAP SEARCH_REQ MSGID 2 BASE_DN "ou=Users,dc=corp,dc=example,dc=com" FILTER "(&(objectClass=user)(sAMAccountName=jdoe))" WAIT 1ms
    ws <- dc LDAP SEARCH_ENTRY MSGID 2 BASE_DN "cn=jdoe,ou=Users,dc=corp,dc=example,dc=com" PAYLOAD "memberOf: cn=Domain Admins,ou=Groups,dc=corp,dc=example,dc=com" WAIT 1ms
    ws <- dc LDAP SEARCH_DONE MSGID 2 RESULT_CODE 0 WAIT 1ms
    ws -> dc LDAP UNBIND_REQ MSGID 3 WAIT 1ms
}

// INSTRUCTION: Compile the Kerberos and LDAP directory authentication flow.
COMPILE {
    active_directory_kerberos_ldap(ad_workstation, domain_controller)
}
```

---

## 4. Network File Storage & SAN/NAS (`SMB` & `NFS`)

### 4.1 Canonical `SMB` (v2/v3) and `NFS` (v4) Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`SMB`** | `COMMAND "<cmd>"` | Quoted string | SMB2/3 command (`"NEGOTIATE"`, `"SESSION_SETUP"`, `"TREE_CONNECT"`, `"CREATE"`, `"WRITE"`, `"READ"`, `"TREE_DISCONNECT"`) |
| **`SMB`** | `STATUS <u32>` | `u32` | 32-bit little-endian `NTSTATUS` code (`0` = `STATUS_SUCCESS`, `0xC0000022` = `ACCESS_DENIED`) |
| **`SMB`** | `SESSION_ID <u64>` / `TREE_ID <u32>` / `MSGID <u64>` | Integer | 64-bit SMB2 Session ID, 32-bit Tree ID, and 64-bit Message ID |
| **`SMB`** | `SHARE "<unc_path>"` / `FILENAME "<file>"` | Quoted string | UTF-16LE UNC share path (e.g. `"\\\\nas01\\engineering"`) and target filename |
| **`NFS`** | `VERS <u32>` | `u32` (`3` or `4`) | NFS protocol version (default `4` for RFC 7530 / RFC 8881 NFSv4) |
| **`NFS`** | `PROC "<procedure>"` | Quoted string | ONC-RPC procedure name (`"NULL"`, `"COMPOUND"`, `"LOOKUP"`, `"READ"`, `"WRITE"`) |
| **`NFS`** | `TAG "<tag>"` / `PATH "<export_path>"` | Quoted string | NFSv4 `COMPOUND` XDR-padded `utf8str_cs` tag and exported file path |

#### Wire Encoding Invariants (`SMB`, `NFS`)
- **`SMB` 4-Byte NetBIOS + 64-Byte Little-Endian `\xFESMB` Header (`src/builders/l7/smb.rs`)**:
  - Prefixes every TCP port `445` packet with a 4-byte NetBIOS Session Service header (`0x00` + 24-bit big-endian payload length) followed by the **64-byte little-endian SMB2/3 Header** (`ProtocolId = "\xfeSMB"`, `StructureSize = 64`, `CreditCharge`, `STATUS` (`NTSTATUS` 4B LE), `Command` (`"NEGOTIATE"`=`0x0000`, `"SESSION_SETUP"`=`0x0001`, `"LOGOFF"`=`0x0002`, `"TREE_CONNECT"`=`0x0003`, `"TREE_DISCONNECT"`=`0x0004`, `"CREATE"`=`0x0005`, `"CLOSE"`=`0x0006`, `"READ"`=`0x0008`, `"WRITE"`=`0x0009`), `Credits`, `Flags`, `NextCommand`, `MSGID` (8B LE), `Reserved`, `TREE_ID` (4B LE), `SESSION_ID` (8B LE), `Signature` (16B)).
  - Encodes `SHARE` as UTF-16LE inside `TREE_CONNECT` requests and `FILENAME` as UTF-16LE inside `CREATE` requests.
- **`NFS` RFC 4506 4-Byte XDR String Padding & `TAG` in NFSv4 `COMPOUND` (`src/builders/l7/nfs.rs`)**:
  - Over TCP port `2049`, prefixes the ONC-RPC v2 message with a **4-byte big-endian RPC Record Marking header** (`0x80000000 | frag_len`, with the last-fragment bit set), followed by `[XID(4B BE), MsgType(0=Call / 1=Reply), RPCVersion(2), Program(100003 = NFS), Version(VERS = 4), Procedure(0 = NULL / 1 = COMPOUND)]` and RPC credentials/verifier.
  - **RFC 4506 4-Byte XDR String Padding & `COMPOUND` `TAG`**: In NFSv4 `COMPOUND` (`Procedure 1`), both the `TAG` string (`utf8str_cs`) and every component of `PATH` are serialized using **RFC 4506 XDR variable-length opaque/string encoding** — `[byte_len(4B BE), utf8_bytes..., 0..3 zero pad bytes]` aligned to a 4-byte boundary (`(4 - (len % 4)) % 4`), followed by `minorversion` (`0` or `1`) and the operation array (`OP_PUTFH = 22`, `OP_LOOKUP = 15`, `OP_READ = 25` / `OP_WRITE = 38`).

> **Important Syntax Rule**: In `SMB`, always specify the operation via `COMMAND "<OP>"` (e.g. `SMB COMMAND "NEGOTIATE"`, `SMB COMMAND "TREE_CONNECT"`), never bare `NEGOTIATE`.

### 4.2 Verified `SMB` v3.1.1 and `NFS` v4.1 Storage Example

```frameassembly
// PROMPT: Enterprise NAS storage operations covering SMB 3.1.1 share mounting and file creation alongside NFSv4.1 COMPOUND read/write RPCs.
// TOKENS: HOST, IP, MAC, FLOW, SMB, COMMAND, STATUS, SESSION_ID, TREE_ID, MSGID, SHARE, FILENAME, NFS, VERS, PROC, TAG, PATH, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare Compute Hypervisor Host mounting remote NAS storage.
HOST compute_host {
    IP 10.90.1.25
    MAC 00:50:56:90:01:25
}

// INSTRUCTION: Declare Unified Enterprise NAS Storage Filer.
HOST nas_filer {
    IP 10.90.1.10
    MAC 00:1c:73:90:01:10
}

// INSTRUCTION: Define SMB 3.1.1 Negotiate, Session Setup, Tree Connect, Create, Write, and Tree Disconnect plus NFSv4 COMPOUND I/O.
FLOW enterprise_nas_storage(host, filer) {
    host -> filer SMB COMMAND "NEGOTIATE" MSGID 0 WAIT 1ms
    host <- filer SMB COMMAND "NEGOTIATE" STATUS 0 MSGID 0 WAIT 1ms
    host -> filer SMB COMMAND "SESSION_SETUP" SESSION_ID 0x100001 MSGID 1 WAIT 1ms
    host <- filer SMB COMMAND "SESSION_SETUP" STATUS 0 SESSION_ID 0x100001 MSGID 1 WAIT 1ms
    host -> filer SMB COMMAND "TREE_CONNECT" SESSION_ID 0x100001 MSGID 2 SHARE "\\\\nas01.corp.example.com\\vmstore" WAIT 1ms
    host <- filer SMB COMMAND "TREE_CONNECT" STATUS 0 SESSION_ID 0x100001 TREE_ID 10 MSGID 2 WAIT 1ms
    host -> filer SMB COMMAND "CREATE" SESSION_ID 0x100001 TREE_ID 10 MSGID 3 FILENAME "prod-db-disk0.vhdx" WAIT 1ms
    host <- filer SMB COMMAND "CREATE" STATUS 0 SESSION_ID 0x100001 TREE_ID 10 MSGID 3 FILENAME "prod-db-disk0.vhdx" WAIT 1ms
    host -> filer SMB COMMAND "TREE_DISCONNECT" SESSION_ID 0x100001 TREE_ID 10 MSGID 4 WAIT 1ms
    host -> filer NFS VERS 4 PROC "NULL" WAIT 1ms
    host <- filer NFS VERS 4 PROC "NULL" WAIT 1ms
    host -> filer NFS VERS 4 PROC "COMPOUND" TAG "lookup_open_read" PATH "/exports/hpc/checkpoint_0042.dat" WAIT 1ms
    host <- filer NFS VERS 4 PROC "COMPOUND" TAG "lookup_open_read" PATH "/exports/hpc/checkpoint_0042.dat" PAYLOAD "NFS4_OK_DATA_CHUNK_4096B" WAIT 1ms
}

// INSTRUCTION: Compile the SMB 3.1.1 and NFSv4.1 storage capture.
COMPILE {
    enterprise_nas_storage(compute_host, nas_filer)
}
```

---

## 5. In-Memory Caching & Relational SQL Databases (`REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`)

### 5.1 Canonical Cache & Database Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`REDIS`** | `CMD "<command>"` / `ARGS "<args>"` | Quoted string | RESP command (`"PING"`, `"SET"`, `"GET"`, `"HSET"`, `"EVAL"`) and space-separated arguments |
| **`REDIS`** | `REPLY_TYPE "<type>"` (`REPLY "<str>"`) / `VALUE "<val>"` | Quoted string | RESP reply type (`"SIMPLE"`, `"BULK"`, `"INTEGER"`, `"ARRAY"`, `"ERROR"`) and value |
| **`MEMCACHED`**| `CMD "<command>"` / `KEY "<key>"` | Quoted string | ASCII command (`"set"`, `"get"`, `"add"`, `"delete"`, `"STORED"`) and cache key |
| **`MEMCACHED`**| `EXPTIME <u32>` / `OPCODE <u32>` / `OPAQUE <u32>` / `CAS <u64>` | Integer | Expiration TTL (s), Binary protocol (`0x80`) opcode, 32-bit opaque token, and 64-bit CAS |
| **`MYSQL`** | `GREETING` / `LOGIN` / `OK` / `ERR` / `EOF` | Bare flag (0-arg) | MySQL v10 protocol handshake greeting, auth login, or result packet type |
| **`MYSQL`** | `SERVER_VERSION "<ver>"` / `USER "<user>"` / `DB "<schema>"` | Quoted string | Server version banner (`"8.4.2-Enterprise"`), username, and database schema |
| **`MYSQL`** | `SQL "<query>"` (`QUERY "<query>"`) / `ERRCODE <u32>` | String, `u32` | `COM_QUERY` (`0x03`) SQL statement and MySQL 16-bit LE error code (e.g. `1062`) |
| **`POSTGRES`** | `STARTUP` / `AUTH_OK` / `COMMAND_COMPLETE` / `READY_FOR_QUERY` / `ERROR_RESPONSE` | Bare flag (0-arg) | PostgreSQL v3.0 frontend/backend message types on TCP port `5432` |
| **`POSTGRES`** | `DB "<dbname>"` / `USER "<role>"` | Quoted string | Target PostgreSQL database name and login role |
| **`POSTGRES`** | `SQL "<query>"` (`QUERY "<query>"`) | Quoted string | Simple Query (`'Q'`) SQL string |

#### Wire Encoding Invariants (`REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`)
- **`REDIS` RESP2/RESP3 Framing (`src/builders/l7/redis.rs`)**:
  - Client commands serialize as RESP Multibulk Arrays (`*<N>\r\n$<cmd_len>\r\n<CMD>\r\n...` across `CMD`, `ARGS`, and `VALUE`/`PAYLOAD`). Server replies serialize according to `REPLY_TYPE` / `REPLY`: `+` Simple String (`+OK\r\n`), `-` Error (`-ERR ...\r\n`), `:` Integer (`:1\r\n`), `$` Bulk String (`$<len>\r\n<val>\r\n` or `$-1\r\n`), or `*` Array.
- **`MEMCACHED` ASCII `<flags> <exptime> <bytes>` & Binary `0x80` Protocol (`src/builders/l7/memcached.rs`)**:
  - **ASCII Text Protocol**: Storage commands (`set`, `add`, `replace`) serialize as `<CMD> <KEY> <flags> <EXPTIME> <bytes>\r\n<value>\r\n`; retrieval commands serialize as `get <KEY>\r\n` and responses as `VALUE <KEY> <flags> <bytes> [<CAS>]\r\n<value>\r\nEND\r\n` or `STORED\r\n`.
  - **Binary Protocol (`0x80` Request / `0x81` Response)**: When `OPCODE` (or binary framing) is used, emits a 24-byte big-endian header (`[Magic(0x80/0x81), OPCODE(1B), KeyLen(2B BE), ExtrasLen(1B), DataType(0x00), Status/VBucket(2B BE), TotalBodyLen(4B BE), OPAQUE(4B BE), CAS(8B BE)]`) followed by Extras (`flags` + `EXPTIME`), `KEY`, and value bytes.
- **`MYSQL` 3-Byte Little-Endian Length Header & v10 Lifecycle (`src/builders/l7/mysql.rs`)**:
  - Every MySQL packet on TCP port `3306` starts with a 4-byte header: **3-byte little-endian payload length** (`[len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff]`) + **1-byte `seq_id`**.
  - Supports `GREETING` (Protocol `0x0a`, NUL-terminated `SERVER_VERSION`, thread ID, scramble salt, capabilities), `LOGIN` (client capability flags, `USER`, auth response, `DB`), `SQL` / `QUERY` (`0x03` `COM_QUERY` + SQL text), `OK` (`0x00` header), `ERR` (`0xFF` header + 2-byte little-endian `ERRCODE` + `#` SQLSTATE + message), and `EOF` (`0xFE` header).
- **`POSTGRES` v3.0 Self-Inclusive 4-Byte Big-Endian Length (`src/builders/l7/postgres.rs`)**:
  - Every tagged PostgreSQL message on TCP port `5432` starts with a 1-byte message tag followed by a **4-byte big-endian length that includes the 4 length bytes themselves** (`(4 + body.len()) as u32`):
    - `STARTUP`: Untagged `[Length(4B BE), ProtocolVersion(0x00030000), "user\x00", <USER>, "\x00database\x00", <DB>, "\x00\x00"]`.
    - `AUTH_OK`: `'R'` + `Length(8)` + `0x00000000`.
    - `SQL` / `QUERY`: `'Q'` + `Length(4 + query.len() + 1)` + `<query>\x00`.
    - `COMMAND_COMPLETE`: `'C'` + `Length` + `<tag>\x00`.
    - `ERROR_RESPONSE`: `'E'` + `Length` + `'S'`/`"ERROR\x00"` + `'M'`/`<msg>\x00` + `'\x00'`.
    - `READY_FOR_QUERY`: `'Z'` + `Length(5)` + `'I'` (idle transaction state).

### 5.2 Verified `REDIS`, `MEMCACHED`, `MYSQL`, and `POSTGRES` Data Tier Example

```frameassembly
// PROMPT: Multi-engine data tier transaction combining Redis RESP caching, Memcached CAS operations, MySQL 8.4 queries, and PostgreSQL 16 ACID transactions.
// TOKENS: HOST, IP, MAC, FLOW, REDIS, CMD, ARGS, REPLY_TYPE, MEMCACHED, KEY, EXPTIME, OPAQUE, CAS, MYSQL, GREETING, LOGIN, SERVER_VERSION, DB, SQL, OK, ERR, ERRCODE, EOF, POSTGRES, STARTUP, USER, AUTH_OK, COMMAND_COMPLETE, READY_FOR_QUERY, ERROR_RESPONSE, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare Backend Microservice Worker Node.
HOST app_worker {
    IP 10.110.1.50
    MAC 00:50:56:6e:01:50
}

// INSTRUCTION: Declare Data Tier Cluster Node hosting Redis, Memcached, MySQL, and PostgreSQL.
HOST data_cluster {
    IP 10.110.1.10
    MAC 00:1c:73:6e:01:10
}

// INSTRUCTION: Define Redis cache lookup/populate, Memcached CAS update, MySQL v10 query lifecycle, and PostgreSQL v3.0 transaction.
FLOW polyglot_data_tier_flow(app, db) {
    app -> db REDIS CMD "GET" ARGS "user:profile:4201" WAIT 1ms
    app <- db REDIS REPLY_TYPE "BULK" PAYLOAD "$-1\r\n" WAIT 1ms
    app -> db REDIS CMD "SET" ARGS "user:profile:4201 {\"tier\":\"platinum\"} EX 300" WAIT 1ms
    app <- db REDIS REPLY_TYPE "SIMPLE" PAYLOAD "+OK\r\n" WAIT 1ms
    app -> db MEMCACHED CMD "set" KEY "rate_limit:ip:198.51.100.9" EXPTIME 60 OPAQUE 701 CAS 10001 PAYLOAD "14" WAIT 1ms
    app <- db MEMCACHED CMD "STORED" KEY "rate_limit:ip:198.51.100.9" OPAQUE 701 CAS 10002 WAIT 1ms
    app <- db MYSQL GREETING SERVER_VERSION "8.4.2-MySQL-Enterprise" WAIT 1ms
    app -> db MYSQL LOGIN USER "orders_app" DB "commerce_prod" WAIT 1ms
    app <- db MYSQL OK WAIT 1ms
    app -> db MYSQL SQL "INSERT INTO orders (id, user_id, total_cents) VALUES (9001, 4201, 14999);" WAIT 1ms
    app <- db MYSQL OK WAIT 1ms
    app -> db MYSQL SQL "INSERT INTO orders (id, user_id, total_cents) VALUES (9001, 4201, 14999);" WAIT 1ms
    app <- db MYSQL ERR ERRCODE 1062 PAYLOAD "Duplicate entry '9001' for key 'orders.PRIMARY'" WAIT 1ms
    app <- db MYSQL EOF WAIT 1ms
    app -> db POSTGRES STARTUP USER "ledger_app" DB "financial_ledger" WAIT 1ms
    app <- db POSTGRES AUTH_OK READY_FOR_QUERY WAIT 1ms
    app -> db POSTGRES SQL "BEGIN; UPDATE accounts SET balance = balance - 14999 WHERE id = 4201; COMMIT;" WAIT 1ms
    app <- db POSTGRES COMMAND_COMPLETE READY_FOR_QUERY PAYLOAD "COMMIT" WAIT 1ms
    app -> db POSTGRES SQL "SELECT * FROM non_existent_audit_view;" WAIT 1ms
    app <- db POSTGRES ERROR_RESPONSE READY_FOR_QUERY PAYLOAD "ERROR: relation does not exist (SQLSTATE 42P01)" WAIT 1ms
}

// INSTRUCTION: Compile the polyglot cache and relational database capture.
COMPILE {
    polyglot_data_tier_flow(app_worker, data_cluster)
}
```

---

## 6. Message Brokers & Constrained IoT Pub/Sub (`MQTT`, `COAP`, `AMQP`)

| Protocol | Modifier Syntax | Argument Type | Wire Format & Sub-Keyword Details |
| :--- | :--- | :--- | :--- |
| **`MQTT`** | `CONNECT` / `CONNACK` / `PUBLISH` / `PUBACK` / `SUBSCRIBE` / `SUBACK` / `PINGREQ` / `PINGRESP` | Bare flag (0-arg) | **OASIS MQTT v3.1.1 / v5.0 (TCP `1883`)**: Fixed header `[type_and_flags(1B), remaining_len(varint)]`. `PUBLISH` (`0x30`) encodes `(QOS << 1) \| RETAIN`, 2B BE `TOPIC` length + `TOPIC`, 2B BE `PKT_ID` / `PKTID` (when `QOS > 0`), and payload. |
| **`MQTT`** | `CLIENT_ID "<id>"` / `TOPIC "<str>"` / `QOS <0..2>` / `RETAIN` / `PKT_ID <u32>` (`PKTID <u32>`) / `RETURN_CODE <u32>` | String, `u32`, Flag | `CONNECT` encodes `"MQTT"` protocol level `4` and `CLIENT_ID`; `CONNACK` encodes `RETURN_CODE`; `SUBSCRIBE` encodes `PKT_ID` / `PKTID`, `TOPIC`, and requested `QOS`. |
| **`COAP`** | `CON` / `NON` / `ACK` / `RST` / `CODE "<c.dd>"` / `MSGID <u32>` / `TOKEN <u32>` / `URI_PATH "<str>"` / `CONTENT_FORMAT <u32>` | Flag, String, `u32` | **RFC 7252 CoAP (UDP `5683`)**: 4-byte header `[ver(1)<<6 \| type<<4 \| tkl, code((class<<5)\|detail), MSGID(2B BE)]` + `TOKEN` bytes + delta-encoded Options (`11` = `URI_PATH`, `12` = `CONTENT_FORMAT`) + `0xFF` payload marker + payload. |
| **`AMQP`** | `PROTOCOL_HEADER` / `CONNECTION_START` / `CHANNEL_OPEN` / `BASIC_PUBLISH` / `BASIC_DELIVER` / `HEARTBEAT` | Bare flag (0-arg) | **OASIS AMQP 0-9-1 (TCP `5672`)**: `PROTOCOL_HEADER` emits the 8-byte signature `'AMQP\x00\x00\x09\x01'`; method/heartbeat frames emit `[FrameType(1=Method, 8=Heartbeat), CHANNEL(2B BE), Size(4B BE), ClassId(2B BE), MethodId(2B BE), arguments..., 0xCE(frame-end)]`. |
| **`AMQP`** | `CHANNEL <u32>` / `EXCHANGE "<str>"` / `ROUTING_KEY "<str>"` | `u32`, String | Virtual channel ID (`0` for `CONNECTION_START`/`HEARTBEAT`, `1+` for `CHANNEL_OPEN`, `BASIC_PUBLISH` Class `60` Method `40`, and `BASIC_DELIVER` Class `60` Method `60` with shortstr `EXCHANGE` and `ROUTING_KEY`). |

> See [**Layer 7 Web, Cloud-Native & IoT Messaging (`docs/l7_web_and_cloud.md` §5)**](./l7_web_and_cloud.md) for a complete compilable `MQTT`, `COAP`, and `AMQP` broker telemetry flow.

---

## 7. Cross-References & Related Protocol Guides

- [**Architecture, Lexer, Parser & Grammar Specification (`docs/architecture_and_grammar.md`)**](./architecture_and_grammar.md) — Complete compiler pipeline, polymorphic IPv4/IPv6 endpoint rules, and constrained decoding (`grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`).
- [**Layer 4 Transports (`docs/l4_transports.md`)**](./l4_transports.md) — Stateful TCP sequence/acknowledgment tracking (`SYN`, `ACK`, `PSH`, `FIN`) and UDP encapsulation for LDAP, Kerberos, SMB, NFS, and Database flows.
- [**Layer 7 Web, Real-Time Media & Cloud (`docs/l7_web_and_cloud.md`)**](./l7_web_and_cloud.md) — HTTP/1.1, HTTP/2, gRPC, TLS 1.3 (`STARTTLS` and `LDAPS` overlays), WebSocket, MQTT, CoAP, and AMQP framing.
- [**Multi-Protocol Enterprise Topologies (`docs/topologies_and_dual_stack.md`)**](./topologies_and_dual_stack.md) — End-to-end Active Directory (`LDAP` + `KERBEROS` + `SMB2` + `DNS`), three-tier web (`HTTP` + `POSTGRES` + `REDIS`), and secure mail gateway (`SMTP` + `IMAPS` + `TLS`) topologies.

