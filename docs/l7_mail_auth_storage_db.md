# Layer 7 Mail, Directory, Storage, Databases, Caches & Message Brokers Reference

Whether you need an **SMTP / IMAP / POP3 mail gateway test capture**, an **Active Directory Kerberos v5 / LDAPv3 & SMB2/3 / NFSv4 NAS storage pcap**, a **Redis / Memcached / MySQL / PostgreSQL database firewall capture**, or an **MQTT / CoAP / AMQP IoT message broker packet generator**, this guide covers **14 enterprise application, identity, storage, database, caching, and message-queuing protocols** across IPv4 and IPv6:
**`SMTP`**, **`IMAP`**, **`POP3`**, **`KERBEROS`**, **`LDAP`**, **`SMB`**, **`NFS`**, **`REDIS`**, **`MEMCACHED`**, **`MYSQL`**, **`POSTGRES`**, **`MQTT`**, **`COAP`**, and **`AMQP`**.

> **Looking for Web, TLS/QUIC, Remote CLI (`SSH`/`TELNET`), File Transfer (`TFTP`/`FTP`), or VoIP (`SIP`/`RTP`)?**
> Those 16 protocols are documented in [**Layer 7 Web, Cloud-Native, Transport Security, VoIP & Remote Access (`l7_web_and_cloud.md`)**](l7_web_and_cloud.md).

---

## Quick Protocol & Default Port Matrix

Every protocol below works with **zero mandatory modifiers** (emitting an RFC-compliant default frame on its standard port) or with explicit field overrides.

| Protocol | Keyword | Default Transport & Port | Standard / RFC | Common Network & Security Testing Use Cases |
| :--- | :--- | :--- | :--- | :--- |
| **SMTP** | `SMTP` | TCP `25` | RFC 5321 / RFC 6409 | Mail gateway relay filtering, DLP policy testing, ESMTP banner inspection |
| **IMAP4rev1/v2** | `IMAP` | TCP `143` | RFC 3501 / RFC 9051 | Mailbox access ACLs, tagged command/response parsing, cleartext auth alerts |
| **POP3** | `POP3` | TCP `110` | RFC 1939 | Legacy mail retrieval monitoring, `+OK`/`-ERR` authentication lockout tests |
| **Kerberos v5** | `KERBEROS` | UDP / TCP `88` | RFC 4120 / RFC 3961 | Active Directory KDC `AS-REQ`/`TGS-REQ` flows, encryption type (`ETYPE`) audits |
| **LDAPv3** | `LDAP` | TCP `389` | RFC 4511 | Directory `Bind`/`Search` inspection, LDAP filter & credential failure alerts |
| **SMB2 / SMB3** | `SMB` | TCP `445` | MS-SMB2 | Lateral-movement IDS rules, UNC share access control, ransomware simulation |
| **NFS v2/v3/v4** | `NFS` | TCP / UDP `2049` | RFC 7530 / RFC 5531 | NAS/HPC storage VLAN segmentation, ONC-RPC `COMPOUND` export mount verification |
| **Redis (RESP)** | `REDIS` | TCP `6379` | RESP2 / RESP3 | East-west cache tier ACLs, unauthenticated `SET`/`GET`/`EVAL` detection |
| **Memcached** | `MEMCACHED`| TCP / UDP `11211` | ASCII & Binary (`0x80`)| Cache key-value inspection, UDP `11211` reflection/amplification firewall blocks |
| **MySQL / MariaDB**| `MYSQL` | TCP `3306` | MySQL Wire v10 | Database activity monitoring (DAM), SQL query logging, error `1045`/`1062` alerts |
| **PostgreSQL** | `POSTGRES` | TCP `5432` | PostgreSQL Wire v3.0 | Startup role/database inspection, SQL transaction & error audit verification |
| **MQTT v3.1.1** | `MQTT` | TCP `1883` | OASIS MQTT v3.1.1 | IoT broker topic ACLs, QoS `0..2` delivery, `KEEPALIVE` and `RETAIN` policies |
| **CoAP** | `COAP` | UDP `5683` | RFC 7252 | Constrained IoT sensor REST calls (`CON`/`NON`/`ACK`/`RST`), CBOR/JSON payloads |
| **AMQP 0-9-1** | `AMQP` | TCP `5672` | AMQP 0-9-1 | RabbitMQ exchange/routing-key inspection, virtual channel and heartbeat traffic |

---

## 1. Electronic Mail Suite (`SMTP`, `IMAP`, `POP3`)

### 1.1 Simple Mail Transfer Protocol (`SMTP` — Default: TCP Port `25`)

Need an **SMTP TCP 25 `EHLO` / `MAIL FROM` / `RCPT TO` / `DATA` mail gateway & DLP test pcap**? `SMTP` builds RFC 5321 SMTP client commands (`EHLO`, `HELO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`), 3-digit server status replies (`220`, `250`, `354`, `221`, `550`), and RFC 5322 MIME message bodies.
- **Passing Envelope Addresses (`MAIL_FROM` / `RCPT_TO`):** You can pass the address either directly after `MAIL_FROM "<addr>"` / `RCPT_TO "<addr>"` or via the `PARAM "<addr>"` modifier (`mail_from param "alice@corp.example.com"`).
- **Sending the `DATA` Command vs. Message Body:** Use `cmd "DATA"` to emit the `DATA\r\n` command line, and use `body "<mime_text>"` on the following packet after the server's `354` response to transmit the email headers/body and trailing `.\r\n` terminator.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`EHLO`** | `EHLO ["<domain>"]` | `"EHLO"` | Emits `EHLO <domain>\r\n` Extended SMTP client greeting |
| **`HELO`** | `HELO ["<domain>"]` | `"HELO"` | Emits `HELO <domain>\r\n` standard SMTP client greeting |
| **`MAIL_FROM`** | `MAIL_FROM ["<addr>"]` | Sets `CMD "MAIL FROM"` | Emits `MAIL FROM:<<addr>>\r\n` (address may also be passed via `PARAM "<addr>"`) |
| **`RCPT_TO`** | `RCPT_TO ["<addr>"]` | Sets `CMD "RCPT TO"` | Emits `RCPT TO:<<addr>>\r\n` (address may also be passed via `PARAM "<addr>"`) |
| **`QUIT`** | `QUIT` | Off | Emits `QUIT\r\n` session termination command |
| **`CMD`** | `CMD "<verb>"` | `"EHLO"` | Explicit SMTP verb (`"DATA"`, `"STARTTLS"`, `"AUTH"`, `"VRFY"`, `"RSET"`, `"NOOP"`) |
| **`PARAM`** | `PARAM "<arg>"` | `"example.com"` | Command parameter or envelope address when not specified inline |
| **`CODE`** | `CODE <200..599>` | Omitted (Command) | Emits a 3-digit server reply (`220` Banner, `250` OK, `354` Start mail input, `221` Bye, `550` Rejected) |
| **`REPLY`** | `REPLY "<text>"` | `"OK"` | Server reply text accompanying `CODE` |
| **`BODY`** | `BODY "<mime_msg>"` | Empty | Transmits RFC 5322 email headers/body and appends `\r\n.\r\n` |

### 1.2 Internet Message Access Protocol (`IMAP` — Default: TCP Port `143`)

Need an **IMAP4 TCP 143 `LOGIN` / `SELECT` / `FETCH` mailbox access & audit pcap**? `IMAP` builds RFC 3501 / RFC 9051 IMAP4rev1/v4rev2 client commands (`<TAG> <CMD> <ARG>\r\n`) and server completion or untagged responses (`<TAG> <STATUS> <RESPONSE>\r\n`).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`TAG`** | `TAG "<text>"` | `"A001"` | Client command correlation tag (`"A001"`, `"A002"`) or untagged server prefix (`"*"`) |
| **`CMD`** | `CMD "<verb>"` | `"CAPABILITY"` | Client IMAP command (`"LOGIN"`, `"SELECT"`, `"EXAMINE"`, `"FETCH"`, `"SEARCH"`, `"STORE"`, `"IDLE"`, `"LOGOUT"`) |
| **`ARG`** | `ARG "<text>"` | Omitted | Command arguments (e.g., `"INBOX"`, `"1:* (FLAGS BODY.PEEK[HEADER])"`) |
| **`STATUS`** | `STATUS "<OK\|NO\|BAD>"`| Omitted (Command) | Emits a server completion line (`<TAG> <STATUS> <RESPONSE>\r\n`) |
| **`RESPONSE`** | `RESPONSE "<text>"` | `"Completed"` | Server response explanation text |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Raw untagged server response line or message body |

### 1.3 Post Office Protocol v3 (`POP3` — Default: TCP Port `110`)

Need a **POP3 TCP 110 `USER` / `PASS` / `STAT` / `RETR` mail retrieval & `+OK`/`-ERR` lockout test pcap**? `POP3` builds RFC 1939 POP3 mailbox commands (`USER`, `PASS`, `STAT`, `LIST`, `UIDL`, `RETR`, `DELE`, `QUIT`) and `+OK` / `-ERR` server replies.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`CMD`** | `CMD "<verb>"` | `"STAT"` | Client POP3 command (`"USER"`, `"PASS"`, `"STAT"`, `"LIST"`, `"UIDL"`, `"RETR"`, `"DELE"`, `"QUIT"`) |
| **`ARG`** | `ARG "<text>"` | Omitted | Command argument (username, password, or message number `"1"`) |
| **`OK`** | `OK` | Off | Emits a positive `+OK <RESPONSE>\r\n` server status line |
| **`ERR`** | `ERR` | Off | Emits a negative `-ERR <RESPONSE>\r\n` server status line |
| **`RESPONSE`** | `RESPONSE "<text>"` | `"POP3 server ready"` | Status text following `+OK` or `-ERR` |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Additional multi-line message or mailbox drop listing |

### Compilable Example: Enterprise Email Submission (`SMTP`) & Mailbox Retrieval (`IMAP` / `POP3`)

```frameassembly
host mail_client { ip 10.30.1.50 }
host mail_server { ip 10.30.1.10 }

flow email_submission_and_sync(mua, mta) {
    // 1. SMTP message submission (TCP 25): Banner -> EHLO -> MAIL FROM -> RCPT TO -> DATA -> BODY -> QUIT
    mua <- mta smtp code 220 reply "mx01.corp.example.com ESMTP Postfix" wait 1ms
    mua -> mta smtp ehlo "ws01.corp.example.com" wait 1ms
    mua <- mta smtp code 250 reply "mx01.corp.example.com PIPELINING SIZE 52428800" wait 1ms
    mua -> mta smtp mail_from param "netops@corp.example.com" wait 1ms
    mua <- mta smtp code 250 reply "2.1.0 Ok" wait 1ms
    mua -> mta smtp rcpt_to param "oncall@corp.example.com" wait 1ms
    mua <- mta smtp code 250 reply "2.1.5 Ok" wait 1ms
    mua -> mta smtp cmd "DATA" wait 1ms
    mua <- mta smtp code 354 reply "End data with <CR><LF>.<CR><LF>" wait 1ms
    mua -> mta smtp body "From: netops@corp.example.com\r\nTo: oncall@corp.example.com\r\nSubject: BGP Maintenance Window\r\n\r\nCore router upgrade scheduled at 02:00 UTC." wait 2ms
    mua <- mta smtp code 250 reply "2.0.0 Ok: queued as 4X9z2L01" wait 1ms
    mua -> mta smtp quit wait 1ms
    mua <- mta smtp code 221 reply "2.0.0 Bye" wait 3ms

    // 2. IMAP4rev1 mailbox login, INBOX selection, and message flag fetch (TCP 143)
    mua -> mta imap tag "A001" cmd "LOGIN" arg "oncall@corp.example.com VaultPass!99" wait 1ms
    mua <- mta imap tag "A001" status "OK" response "LOGIN completed" wait 1ms
    mua -> mta imap tag "A002" cmd "SELECT" arg "INBOX" wait 1ms
    mua <- mta imap tag "A002" status "OK" response "[READ-WRITE] SELECT completed" wait 1ms
    mua -> mta imap tag "A003" cmd "FETCH" arg "1 (FLAGS BODY[HEADER.FIELDS (SUBJECT)])" wait 1ms
    mua <- mta imap tag "A003" status "OK" response "FETCH completed" wait 3ms

    // 3. POP3 mailbox status check and logout (TCP 110)
    mua -> mta pop3 cmd "USER" arg "oncall@corp.example.com" wait 1ms
    mua <- mta pop3 ok response "User accepted" wait 1ms
    mua -> mta pop3 cmd "STAT" wait 1ms
    mua <- mta pop3 ok response "4 18420" wait 1ms
    mua -> mta pop3 cmd "QUIT" wait 1ms
    mua <- mta pop3 ok response "Logging out"
}

compile {
    email_submission_and_sync(mail_client, mail_server)
}
```

---

## 2. Enterprise Identity & Directory (`KERBEROS`, `LDAP`)

### 2.1 Kerberos v5 (`KERBEROS` — Default: UDP / TCP Port `88`)

Need an **Active Directory Kerberos v5 UDP/TCP 88 `AS-REQ` / `AS-REP` / `TGS-REQ` / `TGS-REP` / `KRB-ERROR` KDC ticket pcap**? `KERBEROS` builds RFC 4120 ASN.1 DER application-tagged Kerberos v5 Key Distribution Center (KDC) exchanges (`AS-REQ` tag `0x6A`, `AS-REP` tag `0x6B`, `TGS-REQ` tag `0x6C`, `TGS-REP` tag `0x6D`, and `KRB-ERROR` tag `0x7E`).
- **Transport Selection:** Defaults to UDP port `88`; add `transport tcp` on the statement to emit TCP port `88` (with the 4-byte RFC 4120 §7.2.2 TCP record length prefix).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`AS_REQ`** | `AS_REQ` | Default if none set | Authentication Service Request (`msg-type = 10`, ASN.1 tag `0x6A`) |
| **`AS_REP`** | `AS_REP` | Off | Authentication Service Reply (`msg-type = 11`, ASN.1 tag `0x6B`) |
| **`TGS_REQ`** | `TGS_REQ` | Off | Ticket-Granting Service Request (`msg-type = 12`, ASN.1 tag `0x6C`) |
| **`TGS_REP`** | `TGS_REP` | Off | Ticket-Granting Service Reply (`msg-type = 13`, ASN.1 tag `0x6D`) |
| **`KRB_ERROR`** | `KRB_ERROR` | Off | Kerberos Error PDU (`msg-type = 30`, ASN.1 tag `0x7E`) |
| **`REALM`** | `REALM "<REALM>"` | `"EXAMPLE.COM"` | Kerberos realm name (`GeneralString`) |
| **`CNAME`** | `CNAME "<principal>"` | `"alice"` | Client principal name (`PrincipalName`) |
| **`SNAME`** | `SNAME "<service>"` | `"krbtgt"` | Service principal name (e.g., `"krbtgt/CORP.EXAMPLE.COM"`, `"cifs/nas01.corp.example.com"`) |
| **`ETYPE`** | `ETYPE <code_id>` | `18` | RFC 3961/8009 encryption type (`18` = `aes256-cts-hmac-sha1-96`, `17` = `aes128-cts-hmac-sha1-96`, `23` = `rc4-hmac`) |

### 2.2 Lightweight Directory Access Protocol v3 (`LDAP` — Default: TCP Port `389`)

Need an **LDAPv3 TCP 389 `BindRequest`, `SearchRequest` & `invalidCredentials` (`49`) directory lookup pcap**? `LDAP` builds RFC 4511 ASN.1 BER `LDAPMessage` envelopes (`SEQUENCE 0x30`) containing a `messageID` and protocol operation choice (`BindRequest`, `BindResponse`, `SearchRequest`, `SearchResultEntry`, `SearchResultDone`, or `UnbindRequest`).
- **Complete RFC 4511 `SearchRequest` Encoding:** `SEARCH_REQ` encodes all 8 mandatory ASN.1 fields (`baseObject`, `scope`, `derefAliases`, `sizeLimit`, `timeLimit`, `typesOnly`, `filter`, and `attributes`) so Wireshark's BER dissector decodes every field without warnings.
- **Always write `BASE_DN`:** Use `BASE_DN "<dn>"` (never `DN`) to set the Distinguished Name on bind and search operations.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`BIND_REQ`** | `BIND_REQ` | Default if none set | `BindRequest` (ASN.1 tag `0x60`, LDAPv3, bind DN from `BASE_DN`, simple auth) |
| **`BIND_RES`** | `BIND_RES` | Off | `BindResponse` (ASN.1 tag `0x61`, carries `RESULT_CODE`) |
| **`SEARCH_REQ`** | `SEARCH_REQ` | Off | `SearchRequest` (ASN.1 tag `0x63`, carries `BASE_DN` and `FILTER`) |
| **`SEARCH_ENTRY`** | `SEARCH_ENTRY` | Off | `SearchResultEntry` (ASN.1 tag `0x64`, carries matched `BASE_DN` and attributes) |
| **`SEARCH_DONE`** | `SEARCH_DONE` | Off | `SearchResultDone` (ASN.1 tag `0x65`, carries completion `RESULT_CODE`) |
| **`UNBIND_REQ`** | `UNBIND_REQ` | Off | `UnbindRequest` (ASN.1 tag `0x42`, 0-length NULL body closing the session) |
| **`MSGID`** | `MSGID <number>` | `1` | LDAP message correlation ID |
| **`BASE_DN`** | `BASE_DN "<dn>"` | `"dc=example,dc=com"` | Distinguished Name for `BindRequest`, `SearchRequest`, or `SearchResultEntry` |
| **`FILTER`** | `FILTER "<expr>"` | `"(objectClass=*)"` | Search filter string for `SEARCH_REQ` |
| **`RESULT_CODE`** | `RESULT_CODE <number>` | `0` (`success`) | LDAP result code (`0` = `success`, `32` = `noSuchObject`, `49` = `invalidCredentials`) |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Attribute value string in `SEARCH_ENTRY` |

### Compilable Example: Active Directory Kerberos KDC Ticket Exchange & LDAPv3 Directory Query

```frameassembly
host ad_workstation { ip 10.45.1.100 }
host domain_ctrl    { ip 10.45.1.10 }

flow active_directory_auth_and_ldap(ws, dc) {
    // 1. Kerberos v5 AS-REQ / AS-REP (TGT acquisition) + TGS-REQ / TGS-REP (LDAP service ticket)
    ws -> dc kerberos as_req realm "CORP.EXAMPLE.COM" cname "jdoe" sname "krbtgt/CORP.EXAMPLE.COM" etype 18 wait 1ms
    ws <- dc kerberos as_rep realm "CORP.EXAMPLE.COM" cname "jdoe" sname "krbtgt/CORP.EXAMPLE.COM" etype 18 wait 1ms
    ws -> dc kerberos tgs_req realm "CORP.EXAMPLE.COM" cname "jdoe" sname "ldap/dc01.corp.example.com" etype 18 wait 1ms
    ws <- dc kerberos tgs_rep realm "CORP.EXAMPLE.COM" cname "jdoe" sname "ldap/dc01.corp.example.com" etype 18 wait 2ms

    // 2. LDAPv3 Bind -> Search group memberships -> Search Entry -> Search Done -> Unbind
    ws -> dc ldap bind_req msgid 1 base_dn "cn=jdoe,ou=Users,dc=corp,dc=example,dc=com" wait 1ms
    ws <- dc ldap bind_res msgid 1 result_code 0 wait 1ms
    ws -> dc ldap search_req msgid 2 base_dn "ou=Users,dc=corp,dc=example,dc=com" filter "(&(objectClass=user)(sAMAccountName=jdoe))" wait 1ms
    ws <- dc ldap search_entry msgid 2 base_dn "cn=jdoe,ou=Users,dc=corp,dc=example,dc=com" payload "memberOf: cn=NetAdmins,ou=Groups,dc=corp,dc=example,dc=com" wait 1ms
    ws <- dc ldap search_done msgid 2 result_code 0 wait 1ms
    ws -> dc ldap unbind_req msgid 3
}

compile {
    active_directory_auth_and_ldap(ad_workstation, domain_ctrl)
}
```

---

## 3. Network File Storage (`SMB`, `NFS`)

### 3.1 Server Message Block v2/v3 (`SMB` — Default: TCP Port `445`)

Need an **SMB2 / SMB3 TCP 445 `NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT` & UNC file share access pcap** for lateral-movement IDS or storage firewall testing? `SMB` builds Microsoft `[MS-SMB2]` packets prefixed with a 4-byte NetBIOS Session Service stream length header, a 64-byte SMB2 header (`\xFESMB` magic, 64-byte header length, `Status`, `Command`, `MessageId`, `TreeId`, `SessionId`, and 16-byte signature), and command-specific UTF-16LE share or file paths.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`COMMAND`** | `COMMAND "<name>"` | `"NEGOTIATE"` | SMB2 command (`"NEGOTIATE"` `0x00`, `"SESSION_SETUP"` `0x01`, `"LOGOFF"` `0x02`, `"TREE_CONNECT"` `0x03`, `"TREE_DISCONNECT"` `0x04`, `"CREATE"` `0x05`, `"CLOSE"` `0x06`, `"READ"` `0x08`, `"WRITE"` `0x09`) |
| **`STATUS`** | `STATUS <number>` | `0` (`STATUS_SUCCESS`) | 32-bit `NTSTATUS` code (`0` = `STATUS_SUCCESS`, `0xC0000016` = `MORE_PROCESSING_REQUIRED`, `0xC0000022` = `ACCESS_DENIED`, `0xC000006D` = `LOGON_FAILURE`) |
| **`SESSION_ID`** | `SESSION_ID <64-bit_id>` | `0` | 64-bit authenticated SMB2 `SessionId` |
| **`TREE_ID`** | `TREE_ID <number>` | `0` | 32-bit mounted share `TreeId` |
| **`MSGID`** | `MSGID <number>` | `0` | 64-bit monotonically increasing `MessageId` |
| **`SHARE`** | `SHARE "<unc_path>"` | `"\\\\localhost\\IPC$"`| UNC share path encoded as UTF-16LE in `TREE_CONNECT` requests |
| **`FILENAME`** | `FILENAME "<path>"` | `"file.txt"` | Target file or named pipe encoded as UTF-16LE in `CREATE` requests |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | File data payload for `READ` / `WRITE` operations |

### 3.2 Network File System (`NFS` — Default: TCP / UDP Port `2049`)

Need an **NFSv3 / NFSv4 TCP/UDP 2049 ONC-RPC `COMPOUND` NAS export mount & read/write pcap**? `NFS` builds RFC 1813 (NFSv3) and RFC 7530 / RFC 8881 (NFSv4) calls encapsulated inside RFC 5531 ONC-RPC v2 messages (with the 4-byte RPC Record Marking fragment header `0x80000000 | len` on TCP and 4-byte XDR string padding).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`VERS`** | `VERS <2\|3\|4>` | `4` | NFS version number (`2`, `3`, or `4`) in the ONC-RPC Call header (Program `100003`) |
| **`PROC`** | `PROC "<name>"` | `"COMPOUND"` | NFS procedure (`"NULL"`, `"COMPOUND"`, `"GETATTR"`, `"LOOKUP"`, `"READ"`, `"WRITE"`) |
| **`TAG`** | `TAG "<text>"` | `"fasm_nfs"` | NFSv4 `COMPOUND4args` UTF-8 tag string (XDR length-prefixed and 4-byte aligned) |
| **`PATH`** | `PATH "</export/...>"` | `"/export"` | Export or file path encoded into the XDR call body |
| **`XID`** | `XID <number>` | `0x12345678` | 32-bit ONC-RPC Transaction Identifier (`XID`) |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Additional XDR data or file read/write block bytes |

### Compilable Example: Enterprise NAS File Share Operations (`SMB` & `NFS`)

```frameassembly
host compute_node { ip 10.90.1.25 }
host nas_filer    { ip 10.90.1.10 }

flow nas_storage_operations(node, filer) {
    // 1. SMB2/3 dialect negotiate -> session setup -> tree connect -> file create & write
    node -> filer smb command "NEGOTIATE" msgid 0 wait 1ms
    node <- filer smb command "NEGOTIATE" status 0 msgid 0 wait 1ms
    node -> filer smb command "SESSION_SETUP" session_id 0x100001 msgid 1 wait 1ms
    node <- filer smb command "SESSION_SETUP" status 0 session_id 0x100001 msgid 1 wait 1ms
    node -> filer smb command "TREE_CONNECT" session_id 0x100001 msgid 2 share "\\\\nas01.corp\\vmstore" wait 1ms
    node <- filer smb command "TREE_CONNECT" status 0 session_id 0x100001 tree_id 10 msgid 2 wait 1ms
    node -> filer smb command "CREATE" session_id 0x100001 tree_id 10 msgid 3 filename "prod-db01.vhdx" wait 1ms
    node <- filer smb command "CREATE" status 0 session_id 0x100001 tree_id 10 msgid 3 wait 1ms
    node -> filer smb command "WRITE" session_id 0x100001 tree_id 10 msgid 4 payload "VHDX_HEADER_4096B" wait 1ms
    node <- filer smb command "WRITE" status 0 session_id 0x100001 tree_id 10 msgid 4 wait 2ms

    // 2. NFSv4 ONC-RPC NULL ping and COMPOUND read operation on TCP 2049
    node -> filer nfs vers 4 proc "NULL" xid 0x90010001 wait 1ms
    node <- filer nfs vers 4 proc "NULL" xid 0x90010001 wait 1ms
    node -> filer nfs vers 4 proc "COMPOUND" xid 0x90010002 tag "lookup_read" path "/exports/hpc/checkpoint.dat" wait 1ms
    node <- filer nfs vers 4 proc "COMPOUND" xid 0x90010002 tag "lookup_read" path "/exports/hpc/checkpoint.dat" payload "NFS4_CHECKPOINT_BLOCK"
}

compile {
    nas_storage_operations(compute_node, nas_filer)
}
```

---

## 4. In-Memory Caches & SQL Databases (`REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`)

### 4.1 Redis (`REDIS` — Default: TCP Port `6379`)

Need a **Redis TCP 6379 RESP2/RESP3 `SET` / `GET` / `AUTH` cache lookup pcap**? `REDIS` builds Redis Serialization Protocol client command arrays (`*<n>\r\n$<len>\r\n<arg>\r\n...`) and server replies (`+OK\r\n`, `-ERR ...\r\n`, `:<int>\r\n`, `$<len>\r\n<val>\r\n`).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Cmd** | `GET` \| `SET` | `"PING"` | Bare keyword setting `CMD "GET"` or `CMD "SET"` |
| **`CMD`** | `CMD "<verb>"` | `"PING"` | Explicit Redis command (`"PING"`, `"GET"`, `"SET"`, `"DEL"`, `"HSET"`, `"LPUSH"`, `"AUTH"`, `"INFO"`) |
| **`KEY`** | `KEY "<key>"` | Omitted | Appends the target key as the first command argument |
| **`ARGS`** | `ARGS "<space_sep>"` | Omitted | Splits space-separated arguments into individual RESP Bulk Strings |
| **`REPLY_TYPE`** | `REPLY_TYPE "<type>"` | Omitted (Command) | Emits a server reply (`"SIMPLE"` / `"STATUS"` `+`, `"ERROR"` / `"ERR"` `-`, `"INTEGER"` / `"INT"` `:`, `"BULK"` `$`, `"ARRAY"` `*`) |
| **`VALUE`** | `VALUE "<val>"` | `"OK"` | Reply value or second argument for `SET` commands |

### 4.2 Memcached (`MEMCACHED` — Default: TCP / UDP Port `11211`)

Need a **Memcached TCP/UDP 11211 ASCII & Binary (`0x80`) cache lookup or UDP reflection block pcap**? `MEMCACHED` builds both the Memcached ASCII text protocol (`set <key> <flags> <exptime> <bytes>\r\n<value>\r\n`, `get <key>\r\n`) and the 24-byte Memcached Binary Protocol (`0x80` request / `0x81` response magic when `OPCODE` is specified).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Cmd** | `GET` \| `SET` | `"get"` | Bare keyword setting `CMD "GET"` or `CMD "SET"` |
| **`CMD`** | `CMD "<verb>"` | `"get"` | ASCII command or reply (`"get"`, `"set"`, `"add"`, `"delete"`, `"stats"`, `"STORED"`, `"END"`) |
| **`KEY`** | `KEY "<key>"` | `"default_key"` | Cache item key |
| **`VALUE`** | `VALUE "<val>"` | `"default_val"` | Cache item data payload (automatically sets `<bytes>` in ASCII `set` commands) |
| **`FLAGS`** | `FLAGS <number>` | `0` | 32-bit client flags field for `set`/`add` operations |
| **`EXPTIME`** | `EXPTIME <seconds>` | `3600` | Expiration TTL in seconds |
| **`OPCODE`** | `OPCODE <0..255>` | Omitted (ASCII) | Switches packet to the 24-byte Binary Protocol (`0x00` Get, `0x01` Set, `0x04` Delete, `0x07` Quit) |
| **`OPAQUE`** | `OPAQUE <number>` | `0` | 32-bit correlation ID in the Binary Protocol header |
| **`CAS`** | `CAS <64-bit_id>` | `0` | 64-bit Compare-And-Swap version check |

### 4.3 MySQL / MariaDB (`MYSQL` — Default: TCP Port `3306`)

Need a **MySQL / MariaDB TCP 3306 Wire v10 `HandshakeV10` login, `COM_QUERY` & error `1045`/`1062` database firewall pcap**? `MYSQL` builds MySQL Client/Server Wire Protocol v10 packets with 3-byte little-endian payload length and 1-byte sequence ID headers.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`GREETING`** | `GREETING` | Default if `SERVER_VERSION` | Emits Server `HandshakeV10` (`0x0A`) with version string, thread ID, and auth-plugin salt |
| **`LOGIN`** | `LOGIN` | Auto if `USER` set | Emits Client `HandshakeResponse41` (`seq = 1`) with capability flags, `USER`, and `DB` |
| **`QUERY`** | `QUERY` | Default if `SQL` set | Emits Client `COM_QUERY` (`0x03`) carrying the `SQL` statement |
| **`OK`** | `OK` | Off | Emits Server `OK_Packet` (`0x00`, affected rows, last insert ID, status flags) |
| **`ERR`** | `ERR` | Auto if `ERRCODE` set | Emits Server `ERR_Packet` (`0xFF`, 16-bit `ERRCODE`, `#HY000` SQLSTATE, and error message) |
| **`EOF`** | `EOF` | Off | Emits Server `EOF_Packet` (`0xFE`, warning count and status flags) |
| **`SERVER_VERSION`**| `SERVER_VERSION "<ver>"`| `"8.0.35"` | Null-terminated version banner in `GREETING` packets |
| **`USER`** | `USER "<username>"` | `"root"` | Database login username in `LOGIN` packets |
| **`DB`** | `DB "<schema>"` | Omitted | Initial database schema name in `LOGIN` packets |
| **`SQL`** | `SQL "<statement>"` | `"SELECT 1"` | SQL statement string for `QUERY` (`COM_QUERY`) packets |
| **`ERRCODE`** | `ERRCODE <0..65535>` | `1045` | 16-bit MySQL error code (`1045` = Access denied, `1062` = Duplicate entry, `1146` = Table doesn't exist) |

### 4.4 PostgreSQL (`POSTGRES` — Default: TCP Port `5432`)

Need a **PostgreSQL TCP 5432 Wire v3.0 `StartupMessage`, SQL `Query` & `ErrorResponse` database audit pcap**? `POSTGRES` builds PostgreSQL Wire Protocol v3.0 (`0x00030000` / `196608`) `StartupMessage` frames and 1-byte tagged messages (`'Q'` Query, `'R'` AuthenticationOk, `'C'` CommandComplete, `'Z'` ReadyForQuery, `'E'` ErrorResponse). Multiple server response tags (such as `auth_ok ready_for_query` or `command_complete ready_for_query`) can be combined into a single TCP frame just like a real PostgreSQL server.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`STARTUP`** | `STARTUP` | Auto if `USER`/`DB` set | Emits untagged v3.0 `StartupMessage` (`0x00030000`) with `user` and `database` parameters |
| **`QUERY`** | `QUERY` | Default if `SQL` set | Emits Client `'Q'` (`Query`) message with NUL-terminated `SQL` string |
| **`AUTH_OK`** | `AUTH_OK` | Off | Emits Server `'R'` (`AuthenticationOk`, length `8`, auth code `0`) |
| **`COMMAND_COMPLETE`**| `COMMAND_COMPLETE` | Off | Emits Server `'C'` (`CommandComplete`, e.g., `"SELECT 1\0"` or `PAYLOAD` tag) |
| **`READY_FOR_QUERY`**| `READY_FOR_QUERY` | Off | Emits Server `'Z'` (`ReadyForQuery`, length `5`, idle status `'I'`) |
| **`ERROR_RESPONSE`**| `ERROR_RESPONSE` | Off | Emits Server `'E'` (`ErrorResponse` with severity `ERROR`, SQLSTATE `42601`, and message) |
| **`USER`** | `USER "<role>"` | `"postgres"` | Database role name in `STARTUP` packets |
| **`DB`** | `DB "<dbname>"` | `"postgres"` | Target database name in `STARTUP` packets |
| **`SQL`** | `SQL "<statement>"` | `"SELECT 1;"` | SQL query text in `QUERY` (`'Q'`) packets |
| **`PAYLOAD`** | `PAYLOAD "<tag>"` | `"SELECT 1"` | Custom command tag for `COMMAND_COMPLETE` or error text for `ERROR_RESPONSE` |

### Compilable Example: Cache & Relational Database Tier (`REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`)

```frameassembly
host app_worker   { ip 10.110.1.50 }
host data_cluster { ip 10.110.1.10 }

flow cache_and_sql_tier(app, db) {
    // 1. Redis RESP2 SET and GET cache lookup (TCP 6379)
    app -> db redis cmd "SET" args "session:9042 active EX 300" wait 1ms
    app <- db redis reply_type "SIMPLE" value "OK" wait 1ms
    app -> db redis get key "session:9042" wait 1ms
    app <- db redis reply_type "BULK" value "active" wait 2ms

    // 2. Memcached ASCII set and Binary protocol (0x80) get (TCP 11211)
    app -> db memcached set key "ratelimit:198.51.100.9" flags 0 exptime 60 value "14" wait 1ms
    app <- db memcached cmd "STORED" wait 1ms
    app -> db memcached get key "ratelimit:198.51.100.9" opcode 0x00 opaque 701 cas 1001 wait 2ms

    // 3. MySQL v10 Greeting -> Login -> INSERT Query -> Duplicate Key Error 1062 (TCP 3306)
    app <- db mysql greeting server_version "8.4.2-Enterprise" wait 1ms
    app -> db mysql login user "orders_svc" db "commerce" wait 1ms
    app <- db mysql ok wait 1ms
    app -> db mysql query sql "INSERT INTO orders (id, total_cents) VALUES (9001, 14999);" wait 1ms
    app <- db mysql err errcode 1062 payload "Duplicate entry '9001' for key 'orders.PRIMARY'" wait 2ms

    // 4. PostgreSQL v3.0 Startup -> AuthOk + ReadyForQuery -> Transaction -> CommandComplete (TCP 5432)
    app -> db postgres startup user "ledger_svc" db "ledger" wait 1ms
    app <- db postgres auth_ok ready_for_query wait 1ms
    app -> db postgres query sql "BEGIN; UPDATE accounts SET balance = balance - 14999 WHERE id = 42; COMMIT;" wait 1ms
    app <- db postgres command_complete ready_for_query payload "COMMIT"
}

compile {
    cache_and_sql_tier(app_worker, data_cluster)
}
```

---

## 5. Message Brokers & IoT Telemetry (`MQTT`, `COAP`, `AMQP`)

### 5.1 MQTT v3.1.1 (`MQTT` — Default: TCP Port `1883`)

Need an **MQTT v3.1.1 TCP 1883 `CONNECT` / `CONNACK` / `SUBSCRIBE` / `PUBLISH` (`QoS 0..2`, `RETAIN`) IoT broker pcap**? `MQTT` builds OASIS MQTT v3.1.1 control packets with 1-byte Fixed Headers (4-bit packet type, `DUP`, 2-bit `QoS`, and `RETAIN` bit), RFC-compliant variable-length Remaining Length encoding, Variable Headers, and payloads.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Packet Type Flag** | `CONNECT` \| `CONNACK` \| `PUBLISH` \| `PUBACK` \| `SUBSCRIBE` \| `SUBACK` \| `PINGREQ` \| `PINGRESP` \| `DISCONNECT` | `PUBLISH` (or `CONNECT` if `CLIENT_ID` set) | Selects the 4-bit MQTT Control Packet Type (`1..14`) |
| **`CLIENT_ID`** | `CLIENT_ID "<id>"` | `"fasm-mqtt"` | UTF-8 length-prefixed Client Identifier in `CONNECT` packets |
| **`KEEPALIVE`** | `KEEPALIVE <seconds>` | `60` | 16-bit Keep Alive timer in seconds in `CONNECT` packets |
| **`RETURN_CODE`** | `RETURN_CODE <0..255>` | `0` (`Accepted`) | Connect Return Code in `CONNACK` (`0` = Accepted, `4` = Bad user/pass, `5` = Not authorized) or granted QoS in `SUBACK` |
| **`TOPIC`** | `TOPIC "<topic>"` | `"test/topic"` | Publication topic in `PUBLISH` or topic filter in `SUBSCRIBE` |
| **`QOS`** | `QOS <0\|1\|2>` | `0` | Quality of Service level (`0` At most once, `1` At least once, `2` Exactly once) |
| **`RETAIN`** | `RETAIN [0\|1]` | Off | Sets the Fixed Header `RETAIN` bit (`0x01`) on `PUBLISH` packets |
| **`PKT_ID`** | `PKT_ID <0..65535>` | `1` | 16-bit Packet Identifier for `PUBLISH` (`QoS > 0`), `PUBACK`, `SUBSCRIBE`, and `SUBACK` |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Message body published to `TOPIC` |

### 5.2 Constrained Application Protocol (`COAP` — Default: UDP Port `5683`)

Need a **CoAP UDP 5683 `CON`/`NON`/`ACK`/`RST` IoT sensor REST call & CBOR/JSON payload pcap**? `COAP` builds RFC 7252 4-byte binary CoAP headers (`Version = 1`, 2-bit Type, Token Length, 8-bit `c.dd` Code byte `(class << 5) | detail`, and 16-bit `Message ID`), variable-length Token, delta-encoded `Uri-Path` (Option `11`) and `Content-Format` (Option `12`) options, and the `0xFF` payload marker.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Message Type** | `CON` \| `NON` \| `ACK` \| `RST` | `CON` | 2-bit CoAP Type (`0` Confirmable, `1` Non-confirmable, `2` Acknowledgment, `3` Reset) |
| **Shorthand Code** | `GET` \| `POST` \| `PUT` \| `DELETE` \| `CREATED` \| `CHANGED` \| `NOT_FOUND` | `GET` (`0.01`) | Sets the CoAP method/response code (`GET`=`0.01`, `POST`=`0.02`, `PUT`=`0.03`, `DELETE`=`0.04`, `CREATED`=`2.01`, `CHANGED`=`2.04`, `NOT_FOUND`=`4.04`) |
| **`CODE`** | `CODE "<c.dd>"` | `"0.01"` | Dotted CoAP code string (`"0.01"` GET, `"0.02"` POST, `"2.04"` Changed, `"2.05"` Content, `"4.04"` Not Found) |
| **`MSGID`** | `MSGID <0..65535>` | `1` | 16-bit Message ID used to match `CON` requests with `ACK`/`RST` replies |
| **`TOKEN`** | `TOKEN <number\|"<text>">` | Omitted (0-len) | Client/server correlation token (32-bit integer/hex value or text string) |
| **`URI_PATH`** | `URI_PATH "<path>"` | Omitted | Slash-separated path split into delta-encoded Option `11` (`Uri-Path`) segments |
| **`CONTENT_FORMAT`**| `CONTENT_FORMAT <0..65535>` | Omitted | CoAP Option `12` media type (`0` = `text/plain`, `40` = `application/link-format`, `50` = `application/json`, `60` = `application/cbor`) |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Prepends `0xFF` payload marker followed by payload bytes |

### 5.3 Advanced Message Queuing Protocol (`AMQP` — Default: TCP Port `5672`)

Need an **AMQP 0-9-1 TCP 5672 RabbitMQ `Connection.Start`, `Channel.Open`, `Basic.Publish` & `Heartbeat` message broker pcap**? `AMQP` builds AMQP 0-9-1 protocol handshake headers (`'AMQP\x00\x00\x09\x01'`) and general frames (1-byte Frame Type, 16-bit Channel, 32-bit Payload Size, Class/Method IDs, and trailing `0xCE` frame-end marker).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`PROTOCOL_HEADER`** | `PROTOCOL_HEADER` | Off | Emits the 8-byte `'AMQP\x00\x00\x09\x01'` connection preface |
| **`CONNECTION_START`**| `CONNECTION_START` | Off | Method Frame (Class `10`, Method `10` `Connection.Start`, version `0.9`) |
| **`CHANNEL_OPEN`** | `CHANNEL_OPEN` | Off | Method Frame (Class `20`, Method `10` `Channel.Open`) |
| **`BASIC_PUBLISH`** | `BASIC_PUBLISH` | Default if none set | Method Frame (Class `60`, Method `40` `Basic.Publish`) with `EXCHANGE` and `ROUTING_KEY` |
| **`BASIC_DELIVER`** | `BASIC_DELIVER` | Off | Method Frame (Class `60`, Method `60` `Basic.Deliver`) |
| **`HEARTBEAT`** | `HEARTBEAT` | Off | Frame Type `8` (`Heartbeat` on Channel `0`, 0-byte body + `0xCE`) |
| **`CHANNEL`** | `CHANNEL <0..65535>` | `1` (`0` for conn/hb) | 16-bit AMQP virtual channel number |
| **`EXCHANGE`** | `EXCHANGE "<name>"` | `""` (Default exch) | Short-string Exchange name in `BASIC_PUBLISH` / `BASIC_DELIVER` |
| **`ROUTING_KEY`** | `ROUTING_KEY "<key>"` | `"default"` | Short-string Routing Key in `BASIC_PUBLISH` / `BASIC_DELIVER` |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Appended message body bytes before the `0xCE` frame-end byte |

### Compilable Example: IoT Edge Gateway & Enterprise Message Broker Pipeline (`MQTT`, `COAP`, `AMQP`)

```frameassembly
host iot_gateway { ip 192.168.140.10 }
host msg_broker  { ip 192.168.140.1 }

flow messaging_and_iot_pipeline(edge, brk) {
    // 1. MQTT v3.1.1 Connect -> ConnAck -> Subscribe -> Publish QoS 1 Retain -> PubAck -> Ping -> Disconnect
    edge -> brk mqtt connect client_id "gw-floor2-01" keepalive 60 wait 1ms
    edge <- brk mqtt connack return_code 0 wait 1ms
    edge -> brk mqtt subscribe pkt_id 1 topic "plant/floor2/cmd/#" qos 1 wait 1ms
    edge <- brk mqtt suback pkt_id 1 return_code 1 wait 1ms
    edge -> brk mqtt publish pkt_id 10 topic "plant/floor2/temp" qos 1 retain payload "{\"sensor\":\"T-104\",\"temp_c\":23.8}" wait 1ms
    edge <- brk mqtt puback pkt_id 10 wait 1ms
    edge -> brk mqtt pingreq wait 1ms
    edge <- brk mqtt pingresp wait 1ms
    edge -> brk mqtt disconnect wait 2ms

    // 2. CoAP Confirmable POST sensor telemetry with JSON content-format (50) and 2.04 Changed ACK
    edge -> brk coap con code "0.02" msgid 401 token 0x99aabb01 uri_path "sensors/vibration" content_format 50 payload "{\"rms_mm_s\":1.42}" wait 1ms
    edge <- brk coap ack code "2.04" msgid 401 token 0x99aabb01 wait 2ms

    // 3. AMQP 0-9-1 Protocol Header -> Connection.Start -> Channel.Open -> Basic.Publish -> Heartbeat
    edge -> brk amqp protocol_header wait 1ms
    edge <- brk amqp connection_start channel 0 wait 1ms
    edge -> brk amqp channel_open channel 1 wait 1ms
    edge -> brk amqp basic_publish channel 1 exchange "ot.telemetry" routing_key "floor2.alerts" payload "{\"severity\":\"INFO\",\"msg\":\"Vibration normal\"}" wait 1ms
    edge <- brk amqp basic_deliver channel 1 exchange "ot.telemetry" routing_key "floor2.alerts" payload "{\"ack\":true}" wait 1ms
    edge -> brk amqp heartbeat channel 0
}

compile {
    messaging_and_iot_pipeline(iot_gateway, msg_broker)
}
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — `.fasm` file anatomy, automatic defaults vs. explicit overrides, and step-by-step Wireshark workflows.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — End-to-end recipes for firewall ACL testing, IDS/IPS validation, and database/storage segmentation.
- [**Layer 4 Transport Protocols (`l4_transports.md`)**](l4_transports.md) — Shared 4-tuple `TCP` state tracking, `UDP`, and `transport tcp` / `transport udp` switching for `KERBEROS`, `NFS`, and `MEMCACHED`.
- [**Layer 7 Web, Cloud-Native, Transport Security, VoIP & Remote Access (`l7_web_and_cloud.md`)**](l7_web_and_cloud.md) — `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, and `SSDP`.
- [**Layer 7 Industrial Control Systems & SCADA/OT (`l7_industrial_ot.md`)**](l7_industrial_ot.md) — `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, and `OPCUA`.
- [**Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — End-to-end enterprise, data center, and industrial architectures.
