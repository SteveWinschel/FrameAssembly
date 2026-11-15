# Layer 7 — Mail, Identity, Storage, Databases & Message Brokers

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

[**Active Directory**](#1-kerberoasting-and-ldap-spn-sweeps-kerberos-ldap) • [**File Shares**](#2-file-share-lateral-movement-and-exports-smb-nfs) •
[**Mail**](#3-mail-gateway-filters-and-cleartext-logins-smtp-imap-pop3) • [**Databases & Caches**](#4-sql-dlp-and-unauthenticated-cache-probes-postgres-mysql-redis-memcached) •
[**Brokers & IoT**](#5-iot-and-message-broker-acls-mqtt-coap-amqp) • [**Reverse**](#turning-an-existing-capture-back-into-code)

Testing firewall rules, DLP policies, or IDS signatures for Active Directory, file shares, databases, and mail gateways usually comes with an absurd amount of collateral damage. Nobody
wants to babysit a 24 GB Windows Server Domain Controller VM just to produce one Kerberos `TGS-REQ`, get their lab IP onto the Spamhaus blacklist while testing an `smtp` attachment
rule, or hand-encode ASN.1 DER and UTF-16LE byte offsets in Python at 2 a.m.

FrameAssembly compiles all **14 protocols in this guide** into `.pcap` / `.pcapng` files in milliseconds, with no server infrastructure involved. If you then replay a fake
`SELECT password_hash FROM users` or a `\\ADMIN$` mount onto a SPAN port with `tcpreplay` to check whether anyone in the SOC is actually watching the monitor, whatever HR schedules
afterward is on you.

Every snippet below is a complete file: save it, run `frameassembly <file>.frasm`, and feed the `.pcap` to **Suricata**, **Zeek**, or **Wireshark** / **`tshark`**.

## 1. Kerberoasting and LDAP SPN Sweeps (`kerberos`, `ldap`)

Rules for pre-authentication failures, RC4-HMAC (`etype 23`) ticket requests, and directory-wide `servicePrincipalName` enumeration normally need a whole Windows lab forest to trigger.
Here the ticket exchange takes five lines, and the compiler does the ASN.1 DER/BER envelopes.

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
| **`kerberos`** | UDP `88`; `transport tcp` | `asreq`, `asrep`, `tgsreq`, `tgsrep`, `krberror`, `realm`, `cname`, `sname`, `etype <u32>` | Default `asreq`, `etype 18` (`23` RC4); ASN.1 DER |
| **`ldap`** | TCP `389`; `dstport 636`/`3268` | `bindreq`, `bindres`, `searchreq`, `searchentry`, `searchdone`, `unbindreq`, `msgid`, `basedn`, `filter`, `resultcode` | BER `LDAPMessage` (`0x30`) |

## 2. File Share Lateral Movement and Exports (`smb`, `nfs`)

SMB2 `ADMIN$` and `IPC$` tree connects are the classic lateral-movement tell. Building one by hand means a NetBIOS length prefix, a 64-byte `\xFESMB` header, and UTF-16LE share paths.
Here it is one string, with backslashes escaped.

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

The reply above is `STATUS_ACCESS_DENIED` (`0xc0000022`), which is what a healthy file server says to a workstation that has no business there. For NFS, one line asks a backup server
what it is exporting.

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
| **`smb`** | TCP `445` (`139`) | `negotiate`, `sessionsetup`, `treeconnect`, `create`, `treedisconnect`, `command`, `status`, `treeid`, `sessionid`, `msgid`, `share`, `filename` | `\xFESMB` |
| **`nfs`** | TCP `2049`; `transport udp` | `compound`, `proc`, `vers <2\|3\|4>`, `xid`, `tag`, `path` | ONC-RPC v2 (`100003`); default `vers 4`, `proc "lookup"` |

## 3. Mail Gateway Filters and Cleartext Logins (`smtp`, `imap`, `pop3`)

Checking that an inspection appliance catches a spoofed `MAIL FROM`, a blocked attachment extension, or a legacy cleartext login should not require `nc` typos or a live relay. TCP
`SEQ` /`ACK` bookkeeping and CRLF line endings are handled for you.

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
| **`smtp`** | TCP `25` (`587`/`465`) | `ehlo`, `helo`, `mailfrom`, `rcptto`, `quit`, `cmd`, `param`, `code`, `reply`, `body` | CRLF lines; `smtp cmd "DATA"`; `body` adds `\r\n.\r\n` |
| **`imap`** | TCP `143`; `dstport 993` | `tag "<tag>"`, `cmd "<verb>"`, `arg "<str>"`, `status "<OK\|NO\|BAD>"`, `response "<text>"` | Default `A01 NOOP\r\n`; `status` emits `<tag> <status> ...` |
| **`pop3`** | TCP `110`; `dstport 995` | `cmd "<verb>"`, `arg "<str>"`, `ok` \| `err`, `response "<text>"` | Default `USER\r\n`; `ok` -> `+OK ...`, `err` -> `-ERR ...` |

## 4. SQL DLP and Unauthenticated Cache Probes (`postgres`, `mysql`, `redis`, `memcached`)

Database Activity Monitors and internal segmentation firewalls are tedious to test because binary database protocols reject raw ASCII on TCP 5432 or 3306. The compiler builds valid
PostgreSQL v3.0 frames, little-endian MySQL v10 packets, RESP bulk-string arrays, and Memcached requests, so your DLP rule sees what a real client would send.

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
| **`postgres`** | TCP `5432` | `startup`, `query`, `authok`, `commandcomplete`, `readyforquery`, `errorresponse`, `user`, `db`, `sql` | v3.0 frames (`'Q'`/`'R'`/`'C'`/`'Z'`/`'E'`) |
| **`mysql`** | TCP `3306` | `greeting`, `login`, `query`, `ok`, `err`, `eof`, `serverversion`, `user`, `db`, `sql`, `errcode <u16>` | 3B LE length + seq ID; `err` defaults to `1045` (`#28000`) |
| **`redis`** | TCP `6379`; `dstport 26379` | `get`, `set`, `cmd`, `key`, `args` (repeatable), `replytype`, `value` | RESP bulk-string arrays (`*<argc>\r\n`); bare `redis` -> `PING` |
| **`memcached`** | TCP `11211`; `transport udp` | `get`, `set`, `cmd`, `key`, `value`, `flags`, `exptime`, `opcode`, `opaque`, `cas` | ASCII default; `0x80` Binary w/ `opcode`/`opaque`/`cas` |

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
| **`mqtt`** *(ops)* | TCP `1883` (`8883`) | `connect`, `connack`, `publish`, `puback`, `subscribe`, `suback`, `pingreq`, `pingresp`, `disconnect`, `pkttype` | OASIS v3.1.1 |
| **`mqtt`** *(fields)* | `payload`/`hexpayload` | `clientid`, `topic`, `qos <0..2>`, `retain`, `pktid <u16>`, `keepalive <u16>`, `returncode <u8>` | Default `connect` (`keepalive 60`) |
| **`coap`** *(ops)* | UDP `5683` (`5684`) | `con`, `non`, `ack`, `rst`, `msgtype`, `get`, `post`, `put`, `delete`, `created`, `changed`, `notfound`, `code` | RFC 7252 4B hdr |
| **`coap`** *(fields)* | `payload` (`0xFF` marker) | `msgid <u16>`, `token <u32\|"<hex>">`, `uripath "<path>"`, `contentformat <u16>` | Dotted codes (`"2.05"`, `"4.04"`) |
| **`amqp`** | TCP `5672` (`5671`) | `protocolheader`, `connectionstart`, `channelopen`, `basicpublish`, `basicdeliver`, `heartbeat`, `channel`, `exchange`, `routingkey` | AMQP 0-9-1 |

## Turning an Existing Capture Back into Code

Got a `.pcap` from a real LDAP, SMB, Postgres, MySQL, Redis, or MQTT session? Decompile it, scrub the credentials, and recompile:

```console
$ frameassembly reverse db_audit.pcap sanitized_db_audit.frasm
$ frameassembly sanitized_db_audit.frasm sanitized_db_audit.pcap
```
