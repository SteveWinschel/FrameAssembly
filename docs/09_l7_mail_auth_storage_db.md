# Layer 7 — Mail, Identity, Storage, Databases & Message Brokers

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

[**Active Directory**](#1-kerberoasting-and-ldap-spn-sweeps-kerberos-ldap) • [**File Shares**](#2-file-share-lateral-movement-and-exports-smb-nfs) • [**Mail**](#3-mail-gateway-filters-and-cleartext-logins-smtp-imap-pop3) • [**Databases & Caches**](#4-sql-dlp-and-unauthenticated-cache-probes-postgres-mysql-redis-memcached) • [**Brokers & IoT**](#5-iot-and-message-broker-acls-mqtt-coap-amqp) • [**Reverse**](#turning-an-existing-capture-back-into-code)

Testing firewall rules, DLP policies, or IDS signatures for Active Directory, file shares, databases, and mail gateways usually comes with an absurd amount of collateral damage. Nobody wants to babysit a 24 GB Windows Server Domain Controller VM just to produce one Kerberos `TGS-REQ`, get their lab IP onto the Spamhaus blacklist while testing an `smtp` attachment rule, or hand-encode ASN.1 DER and UTF-16LE byte offsets in Python at 2 a.m.

FrameAssembly compiles all **14 protocols in this guide** into `.pcap` / `.pcapng` files in milliseconds, with no server infrastructure involved. If you then replay a fake `SELECT password_hash FROM users` or a `\\ADMIN$` mount onto a SPAN port with `tcpreplay` to check whether anyone in the SOC is actually watching the monitor, whatever HR schedules afterward is on you.

Every snippet below is a complete file: save it, run `frameassembly <file>.frasm`, and feed the `.pcap` to **Suricata**, **Zeek**, or **Wireshark** / **`tshark`**.

## 1. Kerberoasting and LDAP SPN Sweeps (`kerberos`, `ldap`)

Rules for pre-authentication failures, RC4-HMAC (`etype 23`) ticket requests, and directory-wide `servicePrincipalName` enumeration normally need a whole Windows lab forest to trigger. Here the ticket exchange takes five lines, and the compiler does the ASN.1 DER/BER envelopes.

```frameassembly
host workstation { ip 10.20.5.101 mac 00:50:56:20:05:65 }
host dc01        { ip 10.20.1.10  mac 00:50:56:20:01:0a }

flow kerberoast(ws, dc) {
    // Pre-auth failure, then an RC4-HMAC (etype 23) TGS request for a SQL service account
    ws -> dc kerberos asreq realm "CORP.LOCAL" cname "jdoe" sname "krbtgt/CORP.LOCAL" etype 18 wait 1ms
    ws <- dc kerberos krberror realm "CORP.LOCAL" cname "jdoe" sname "krbtgt/CORP.LOCAL" wait 2ms
    ws -> dc kerberos tgsreq realm "CORP.LOCAL" cname "jdoe" sname "mssqlsvc/sql01.corp.local" etype 23 wait 2ms
    ws <- dc kerberos tgsrep realm "CORP.LOCAL" cname "jdoe" sname "mssqlsvc/sql01.corp.local" etype 23
}

compile { kerberoast(workstation, dc01) }
```

The same host pair can sweep the directory over TCP 389. The three-way handshake is there because directory-aware firewalls drop a `bindreq` that shows up without one.

```frameassembly
host workstation { ip 10.20.5.101 mac 00:50:56:20:05:65 }
host dc01        { ip 10.20.1.10  mac 00:50:56:20:01:0a }

flow spn_sweep(ws, dc) {
    ws -> dc tcp syn srcport 51389 dstport 389 win 64240 mss 1460 wait 1ms
    ws <- dc tcp syn ack win 64240 mss 1460 wait 1ms
    ws -> dc tcp ack wait 1ms
    ws -> dc ldap bindreq msgid 1 basedn "cn=jdoe,ou=Users,dc=corp,dc=local" wait 1ms
    ws <- dc ldap bindres msgid 1 resultcode 0 wait 1ms
    ws -> dc ldap searchreq msgid 2 basedn "dc=corp,dc=local" filter "(servicePrincipalName=*)" wait 2ms
    ws <- dc ldap searchdone msgid 2 resultcode 0
}

compile { spn_sweep(workstation, dc01) }
```

```console
$ frameassembly ad_audit.frasm ad_audit.pcap && suricata -r ad_audit.pcap -k none
```

| Keyword | Port & override | Modifiers | Defaults & wire behavior |
| :--- | :--- | :--- | :--- |
| **`kerberos`** (RFC 4120) | UDP `88`; `transport tcp` for TCP `88` | `asreq` \| `asrep` \| `tgsreq` \| `tgsrep` \| `krberror`, `realm "<REALM>"`, `cname "<principal>"`, `sname "<service/host>"`, `etype <u32>`, `transport tcp` | Defaults to `asreq`, `realm "CORP.LOCAL"`, `cname "user"`, `sname "krbtgt"`, and `etype 18` (`aes256-cts-hmac-sha1-96`; use `etype 23` for `rc4-hmac`, `etype 17` for `aes128`). Output is ASN.1 DER `[APPLICATION 10..13, 30]`. A service principal containing `/` (such as `"cifs/filesrv.corp.local"`) is split into a multi-component `PrincipalName`. `krberror` carries error code `24` (`KDC_ERR_PREAUTH_FAILED`). |
| **`ldap`** (RFC 4511) | TCP `389`; `dstport 636` / `3268` | `bindreq` \| `bindres` \| `searchreq` \| `searchentry` \| `searchdone` \| `unbindreq`, `msgid <u32>`, `basedn "<dn>"`, `filter "<expr>"`, `resultcode <u32>` | Defaults to `bindreq` with `msgid 1` and `basedn "dc=corp,dc=local"`. Output is an ASN.1 BER `LDAPMessage` (`0x30`). Giving `filter` selects `searchreq` (`wholeSubtree`) and strips the filter into its BER form. Giving `resultcode` (`0` success, `49` invalidCredentials) selects `bindres` unless `searchdone` is set. |

## 2. File Share Lateral Movement and Exports (`smb`, `nfs`)

SMB2 `ADMIN$` and `IPC$` tree connects are the classic lateral-movement tell. Building one by hand means a NetBIOS length prefix, a 64-byte `\xFESMB` header, and UTF-16LE share paths. Here it is one string, with backslashes escaped.

```frameassembly
host workstation { ip 10.20.5.101 mac 00:50:56:20:05:65 }
host file_srv    { ip 10.20.1.50  mac 00:50:56:20:01:32 }

flow admin_share_probe(ws, fs) {
    ws -> fs tcp syn srcport 51445 dstport 445 win 64240 mss 1460 wait 1ms
    ws <- fs tcp syn ack win 64240 mss 1460 wait 1ms
    ws -> fs tcp ack wait 1ms
    ws -> fs smb negotiate msgid 0 wait 1ms
    ws -> fs smb sessionsetup msgid 1 sessionid 0x0001000000000001 wait 1ms
    ws -> fs smb treeconnect msgid 2 sessionid 0x0001000000000001 share "\\\\10.20.1.50\\ADMIN$" wait 2ms
    ws <- fs smb treeconnect msgid 2 sessionid 0x0001000000000001 treeid 1 status 0xc0000022
}

compile { admin_share_probe(workstation, file_srv) }
```

The reply above is `STATUS_ACCESS_DENIED` (`0xc0000022`), which is what a healthy file server says to a workstation that has no business there. For NFS, one line asks a backup server what it is exporting.

```frameassembly
host app_node { ip 10.30.1.15 mac 00:1a:2b:30:01:15 }
host nas      { ip 10.30.2.60 mac 00:1a:2b:30:02:60 }

flow export_probe(a, b) {
    a -> b nfs vers 4 compound xid 0x99887766 tag "export_probe" path "/srv/backups"
}

compile { export_probe(app_node, nas) }
```

| Keyword | Port & override | Modifiers | Defaults & wire behavior |
| :--- | :--- | :--- | :--- |
| **`smb`** (MS-SMB2) | TCP `445`; `dstport 139` | `negotiate` \| `sessionsetup` \| `treeconnect` \| `create` \| `treedisconnect` \| `command "<logoff\|close\|read\|write>"`, `status <u32>`, `treeid <u32>`, `sessionid <u64>`, `msgid <u64>`, `share "<unc_path>"`, `filename "<file>"` | Wire framing is a 4-byte NetBIOS length, a 64-byte `\xFESMB` header, and UTF-16LE share/file paths. Selects `treeconnect` when `share` is set, `create` when `filename` is set, and `negotiate` (`0x0202` dialect) otherwise. Always escape backslashes inside double-quoted UNC paths (`share "\\\\10.0.0.50\\IPC$"`). |
| **`nfs`** (RFC 1813 / RFC 7530 over ONC-RPC v2) | TCP `2049`; `transport udp` | `compound` \| `proc "<null\|getattr\|lookup\|read\|write\|compound>"`, `vers <2\|3\|4>`, `xid <u32>`, `tag "<str>"`, `path "<export_path>"`, `transport udp` | Wire framing is a 4-byte RPC record marker, a 40-byte ONC-RPC v2 Call (program `100003`), and XDR padding. Defaults to `vers 4`, `proc "lookup"`, and `xid 0x12345678`. Use `xid` (not `txid`) for the ONC-RPC transaction ID. |

## 3. Mail Gateway Filters and Cleartext Logins (`smtp`, `imap`, `pop3`)

Checking that an inspection appliance catches a spoofed `MAIL FROM`, a blocked attachment extension, or a legacy cleartext login should not require `nc` typos or a live relay. TCP `SEQ`/`ACK` bookkeeping and CRLF line endings are handled for you.

```frameassembly
host ext_mta { ip 198.51.100.25 mac 00:11:22:33:44:25 }
host mail_gw { ip 10.10.25.10   mac aa:bb:cc:dd:ee:10 }

flow smtp_filter_check(mta, gw) {
    mta <- gw smtp code 220 reply "mx01.example.com ESMTP Postfix" wait 2ms
    mta -> gw smtp ehlo "mailer.suspicious-sender.test" wait 1ms
    mta -> gw smtp mailfrom "<ceo-urgent@suspicious-sender.test>" wait 1ms
    mta -> gw smtp rcptto "<finance@example.com>" wait 1ms
    mta -> gw smtp cmd "DATA" wait 1ms
    mta <- gw smtp code 354 reply "End data with <CR><LF>.<CR><LF>" wait 1ms
    mta -> gw smtp cmd "Subject:" param "Urgent Wire Transfer" body "Please open invoice_q4.scr immediately." wait 3ms
    mta <- gw smtp code 550 reply "5.7.1 Message rejected by attachment policy"
}

compile { smtp_filter_check(ext_mta, mail_gw) }
```

Then check that nobody on the legacy subnet is still logging in over `imap` and `pop3` in the clear.

```frameassembly
host legacy_c { ip 10.10.50.88 mac 00:11:22:33:44:88 }
host mail_gw  { ip 10.10.25.10 mac aa:bb:cc:dd:ee:10 }

flow cleartext_mailbox_probe(c, gw) {
    c -> gw imap tag "A001" cmd "LOGIN" arg "finance@example.com Winter2026!" wait 2ms
    c <- gw imap tag "A001" status "NO" response "Cleartext authentication disabled" wait 2ms
    c -> gw pop3 cmd "USER" arg "finance@example.com" wait 2ms
    c <- gw pop3 err response "Plaintext POP3 prohibited; use port 995"
}

compile { cleartext_mailbox_probe(legacy_c, mail_gw) }
```

```console
$ frameassembly mail_test.frasm mail_test.pcap && tshark -r mail_test.pcap -Y "smtp || imap || pop"
```

| Keyword | Port & override | Modifiers | Defaults & wire behavior |
| :--- | :--- | :--- | :--- |
| **`smtp`** (RFC 5321) | TCP `25`; `dstport 587` / `465` | `ehlo ["<domain>"]` \| `helo ["<domain>"]` \| `mailfrom ["<addr>"]` \| `rcptto ["<addr>"]` \| `quit` \| `cmd "<verb>"`, `param "<arg>"`, `code <u16>`, `reply "<text>"`, `body "<mime_body>"` | CRLF-terminated command and status lines. With no fields it sends `"EHLO localhost\r\n"`. `data` is a cross-layer token, so write `smtp cmd "DATA"` for the `DATA` line. A `body "..."` automatically appends the `\r\n.\r\n` end-of-data sequence. |
| **`imap`** (RFC 3501 / RFC 9051) | TCP `143`; `dstport 993` | `tag "<tag>"`, `cmd "<verb>"`, `arg "<str>"`, `status "<OK\|NO\|BAD>"`, `response "<text>"` | Tagged, untagged (`*`), and completion lines. `tag` defaults to `"A01"` and `cmd` to `"NOOP"`. With `status`, it emits `<tag> <status> <response>\r\n`. A `response` with no `cmd` or `status` emits an untagged `* OK <response>\r\n`. |
| **`pop3`** (RFC 1939) | TCP `110`; `dstport 995` | `cmd "<verb>"`, `arg "<str>"`, `ok` \| `err`, `response "<text>"` | Client commands default to `USER\r\n`. `ok` emits `+OK <response>\r\n` and `err` emits `-ERR <response>\r\n`. |

## 4. SQL DLP and Unauthenticated Cache Probes (`postgres`, `mysql`, `redis`, `memcached`)

Database Activity Monitors and internal segmentation firewalls are tedious to test because binary database protocols reject raw ASCII on TCP 5432 or 3306. The compiler builds valid PostgreSQL v3.0 frames, little-endian MySQL v10 packets, RESP bulk-string arrays, and Memcached requests, so your DLP rule sees what a real client would send.

```frameassembly
host app_node { ip 10.30.1.15 mac 00:1a:2b:30:01:15 }
host data_srv { ip 10.30.2.40 mac 00:1a:2b:30:02:40 }

flow sql_exfil_probe(app, db) {
    app -> db tcp syn srcport 55432 dstport 5432 win 65535 mss 1460 wait 1ms
    app <- db tcp syn ack win 65535 mss 1460 wait 1ms
    app -> db tcp ack wait 1ms
    app -> db postgres startup user "readonly_reporting" db "customers" wait 1ms
    app <- db postgres authok wait 1ms
    app <- db postgres readyforquery wait 1ms
    app -> db postgres query sql "SELECT email, password_hash FROM users WHERE '1'='1';" wait 2ms
    app <- db postgres errorresponse sql "permission denied for table users"
}

compile { sql_exfil_probe(app_node, data_srv) }
```

MySQL gets the server greeting and a rejected root login (error 1045). Redis and Memcached get the two probes that every internet-facing cache eventually receives anyway.

```frameassembly
host app_node { ip 10.30.1.15 mac 00:1a:2b:30:01:15 }
host data_srv { ip 10.30.2.40 mac 00:1a:2b:30:02:40 }

flow cache_and_mysql_probe(app, db) {
    app <- db mysql greeting serverversion "8.0.36" wait 1ms
    app -> db mysql login user "root" db "production" wait 1ms
    app <- db mysql err errcode 1045 wait 2ms
    app -> db redis cmd "CONFIG" args "GET" args "dir" wait 1ms
    app <- db redis replytype "err" value "NOAUTH Authentication required" wait 1ms
    app -> db transport udp memcached cmd "stats"
}

compile { cache_and_mysql_probe(app_node, data_srv) }
```

```console
$ frameassembly show db_audit.frasm
$ frameassembly db_audit.frasm db_audit.pcap && zeek -C -r db_audit.pcap
```

| Keyword | Port & override | Modifiers | Defaults & wire behavior |
| :--- | :--- | :--- | :--- |
| **`postgres`** (Frontend/Backend v3.0) | TCP `5432`; custom `dstport` | `startup` \| `query` \| `authok` \| `commandcomplete` \| `readyforquery` \| `errorresponse`, `user "<role>"`, `db "<database>"`, `sql "<statement_or_msg>"` | `StartupMessage` (`0x00030000`, no type byte) plus `'Q'` / `'R'` / `'C'` / `'Z'` / `'E'` tagged messages. Emit **one** message type per statement (`authok` on one `<-` line, `readyforquery` on the next) so each wire message gets its own length header. On `commandcomplete`, `sql` sets the completion tag (default `"SELECT 1"`). On `errorresponse`, `sql` sets the SQLSTATE `28P01` error text. |
| **`mysql`** (Wire Protocol v10) | TCP `3306`; custom `dstport` | `greeting` \| `login` \| `query` \| `ok` \| `err` \| `eof`, `serverversion "<ver>"`, `user "<user>"`, `db "<schema>"`, `sql "<statement>"`, `errcode <u16>` | 3-byte little-endian length plus sequence ID. `greeting` is a server-to-client `HandshakeV10` (`serverversion` default `"8.0.35"`). `login` is `HandshakeResponse41` (`user` default `"root"`). `query` is `COM_QUERY` (`0x03`). `err` emits `#28000Access denied` (`errcode` default `1045`). |
| **`redis`** (RESP2 / RESP3) | TCP `6379`; `dstport 26379` | `get` \| `set` \| `cmd "<verb>"`, `key "<key>"`, `args "<arg>"` (repeatable), `replytype "<simple\|status\|ok\|error\|err\|integer\|int\|bulk>"`, `value "<val>"` | RESP `*<argc>\r\n$<len>\r\n` bulk-string arrays and typed replies. Repeat `args` to build multi-argument arrays (`redis cmd "HSET" key "user:1" args "role" value "admin"`). No modifiers at all sends `*1\r\n$4\r\nPING\r\n`. |
| **`memcached`** (ASCII & Binary) | TCP `11211`; `transport udp` | `get` \| `set` \| `cmd "<verb>"`, `key "<key>"`, `value "<val>"`, `flags <u32>`, `exptime <u32>`, `opcode <u8>`, `opaque <u32>`, `cas <u64>`, `transport udp` | ASCII commands (`get`, `set`, `delete`, `stats`, `version`, `flush_all`) by default. Switches to the 24-byte `0x80` Binary Protocol header as soon as `opcode`, `opaque`, or `cas` appears. |

## 5. IoT and Message Broker ACLs (`mqtt`, `coap`, `amqp`)

Whether an edge gateway publishes retained `mqtt` readings, polls `coap` over UDP, or pushes events through `amqp` exchanges, you can verify DMZ broker rules without standing up Mosquitto or RabbitMQ.

```frameassembly
host edge_gw { ip 10.60.10.12 mac 00:1e:c0:60:10:12 }
host broker  { ip 10.60.1.5   mac 00:1e:c0:60:01:05 }

flow mqtt_publish(gw, brk) {
    gw -> brk tcp syn srcport 51883 dstport 1883 win 64240 mss 1460 wait 1ms
    gw <- brk tcp syn ack win 64240 mss 1460 wait 1ms
    gw -> brk tcp ack wait 1ms
    gw -> brk mqtt connect clientid "turbine-gw-12" keepalive 60 wait 1ms
    gw <- brk mqtt connack returncode 0 wait 1ms
    gw -> brk mqtt publish topic "plant/line4/temp" qos 1 retain pktid 7 payload "{\"celsius\":84.2}" wait 2ms
    gw <- brk mqtt puback pktid 7
}

compile { mqtt_publish(edge_gw, broker) }
```

CoAP and AMQP need no handshake lines for a rule test, since each statement is one frame on the protocol's well-known port.

```frameassembly
host edge_gw { ip 10.60.10.12 mac 00:1e:c0:60:10:12 }
host broker  { ip 10.60.1.5   mac 00:1e:c0:60:01:05 }

flow coap_and_amqp(gw, brk) {
    gw -> brk coap con get msgid 0x2201 token 0x0a0b0c0d uripath "sensors/pressure" contentformat 50 wait 2ms
    gw <- brk coap ack code "2.05" msgid 0x2201 token 0x0a0b0c0d contentformat 50 payload "{\"bar\":6.4}" wait 2ms
    gw -> brk amqp protocolheader wait 1ms
    gw <- brk amqp connectionstart wait 1ms
    gw -> brk amqp channelopen channel 1 wait 1ms
    gw -> brk amqp basicpublish channel 1 exchange "telemetry.events" routingkey "alerts.high_temp" payload "{\"unit\":12}"
}

compile { coap_and_amqp(edge_gw, broker) }
```

| Keyword | Port & override | Modifiers | Defaults & wire behavior |
| :--- | :--- | :--- | :--- |
| **`mqtt`** (OASIS v3.1.1) | TCP `1883`; `dstport 8883` | `connect` \| `connack` \| `publish` \| `puback` \| `subscribe` \| `suback` \| `pingreq` \| `pingresp` \| `disconnect` \| `pkttype "<type>"`, `clientid "<id>"`, `topic "<topic>"`, `qos <0..2>`, `retain [0\|1]`, `pktid <u16>`, `keepalive <u16>`, `returncode <u8>` | Fixed header flags (`QoS`, `RETAIN`), Remaining Length, and packet IDs. Defaults to `connect` with `clientid "client-01"` and `keepalive 60`. Attach message bodies with `payload "..."` or `hexpayload "..."`. |
| **`coap`** (RFC 7252) | UDP `5683`; `dstport 5684` | `con` \| `non` \| `ack` \| `rst` \| `msgtype "<type>"`, `get` \| `post` \| `put` \| `delete` \| `created` \| `changed` \| `notfound` \| `code "<c.dd>"`, `msgid <u16>`, `token <u32\|"<hex>">`, `uripath "<path>"`, `contentformat <u16>` | 4-byte header, `c.dd` code packing, and Option `11`/`12` delta encoding. Inside a `coap` statement, `ack` and `rst` set the CoAP message type, not TCP flags. Use dotted codes such as `"2.05"` (Content), `"2.01"` (Created), or `"4.04"` (Not Found). `payload "..."` appends the `0xFF` payload marker. |
| **`amqp`** (0-9-1) | TCP `5672`; `dstport 5671` | `protocolheader` \| `connectionstart` \| `channelopen` \| `basicpublish` \| `basicdeliver` \| `heartbeat`, `channel <u16>`, `exchange "<name>"`, `routingkey "<key>"` | With no frame flag it emits the 8-byte `AMQP\x00\x00\x09\x01` preface. Otherwise it wraps `Connection.Start` (`10,10`), `Channel.Open` (`20,10`), `Basic.Publish` (`60,40`), `Basic.Deliver` (`60,60`), or `Heartbeat` frames with the mandatory `0xCE` end byte. |

## Turning an Existing Capture Back into Code

Got a `.pcap` from a real LDAP, SMB, Postgres, MySQL, Redis, or MQTT session? Decompile it, scrub the credentials, and recompile:

```console
$ frameassembly reverse db_audit.pcap sanitized_db_audit.frasm
$ frameassembly sanitized_db_audit.frasm sanitized_db_audit.pcap
```
