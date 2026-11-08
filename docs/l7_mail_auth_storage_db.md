# Layer 7 — Mail, Identity, Storage, Databases & Message Brokers

[**Use Cases**](#enterprise-and-secops-testing-use-cases) • [**Mail (`SMTP`, `IMAP`, `POP3`)**](#mail-protocols-smtp-imap-pop3) • [**Identity (`Kerberos`, `LDAP`)**](#identity-and-directory-protocols-kerberos-ldap) • [**Storage (`SMB`, `NFS`)**](#network-file-storage-smb-nfs) • [**Databases & Caches**](#databases-and-caches-postgres-mysql-redis-memcached) • [**Brokers (`MQTT`, `CoAP`, `AMQP`)**](#message-brokers-and-iot-queues-mqtt-coap-amqp) • [**Docs Hub**](../README.md)

Testing enterprise firewall rules, DLP policies, or IDS signatures for Active Directory, file shares, databases, and mail gateways usually involves an absurd amount of collateral damage. Nobody wants to babysit a 24 GB Windows Server Domain Controller VM just to generate one Kerberos `TGS-REQ`, get their lab IP blacklisted on Spamhaus testing an `SMTP` attachment rule, or hand-encode ASN.1 DER and UTF-16LE byte offsets in Python.

And if you just want to replay a fake `SELECT password_hash FROM users` or an `ADMIN$` share mount across a SPAN port with `tcpreplay` to see whether the SOC is actually looking at the dashboard -> FrameAssembly compiles all **14 enterprise Layer 7 protocols** into `.pcap` / `.pcapng` files in milliseconds without needing any server infrastructure (as usual, what you replay onto your coworker's segment is between you and HR) :)

## Enterprise and SecOps Testing Use Cases

### 1. Test Active Directory & Lateral Movement Detections Without a Domain Controller (`Kerberos`, `LDAP`, `SMB`)
Validating **Suricata**, **Zeek**, or NDR rules for Kerberos pre-authentication failures, RC4-HMAC (`etype 23`) Kerberoasting, LDAP SPN enumeration, or `SMB2` `ADMIN$` lateral movement normally requires spinning up an entire Windows lab forest. FrameAssembly encodes the ASN.1 DER/BER envelopes, NetBIOS framing, 64-byte `\xFESMB` headers, and UTF-16LE UNC paths directly from a few lines of `.fasm`:

```frameassembly
host workstation { ip 10.20.5.101 mac 00:50:56:20:05:65 }
host dc_01       { ip 10.20.1.10  mac 00:50:56:20:01:0a }
host file_srv    { ip 10.20.1.50  mac 00:50:56:20:01:32 }

flow ad_lateral_movement(ws, dc, fs) {
    // Kerberos pre-auth failure followed by an RC4-HMAC (etype 23) Kerberoast TGS request
    ws -> dc kerberos as_req realm "CORP.LOCAL" cname "jdoe" sname "krbtgt/CORP.LOCAL" etype 18 wait 1ms
    ws <- dc kerberos krb_error realm "CORP.LOCAL" cname "jdoe" sname "krbtgt/CORP.LOCAL" wait 2ms
    ws -> dc kerberos tgs_req realm "CORP.LOCAL" cname "jdoe" sname "mssqlsvc/sql01.corp.local" etype 23 wait 2ms
    ws <- dc kerberos tgs_rep realm "CORP.LOCAL" cname "jdoe" sname "mssqlsvc/sql01.corp.local" etype 23 wait 2ms

    // Stateful LDAP directory SPN enumeration over TCP 389
    ws -> dc tcp syn srcport 51389 dstport 389 win 64240 mss 1460 wait 1ms
    ws <- dc tcp syn ack win 64240 mss 1460 wait 1ms
    ws -> dc tcp ack wait 1ms
    ws -> dc ldap bind_req msgid 1 base_dn "cn=jdoe,ou=Users,dc=corp,dc=local" wait 1ms
    ws <- dc ldap bind_res msgid 1 result_code 0 wait 1ms
    ws -> dc ldap search_req msgid 2 base_dn "dc=corp,dc=local" filter "(servicePrincipalName=*)" wait 2ms
    ws <- dc ldap search_done msgid 2 result_code 0 wait 1ms

    // SMB2 administrative share probe on TCP 445 (rejected with STATUS_ACCESS_DENIED)
    ws -> fs tcp syn srcport 51445 dstport 445 win 64240 mss 1460 wait 1ms
    ws <- fs tcp syn ack win 64240 mss 1460 wait 1ms
    ws -> fs tcp ack wait 1ms
    ws -> fs smb negotiate msgid 0 wait 1ms
    ws -> fs smb session_setup msgid 1 session_id 0x0001000000000001 wait 1ms
    ws -> fs smb tree_connect msgid 2 session_id 0x0001000000000001 share "\\\\10.20.1.50\\ADMIN$" wait 2ms
    ws <- fs smb tree_connect msgid 2 session_id 0x0001000000000001 tree_id 1 status 0xc0000022
}

compile { ad_lateral_movement(workstation, dc_01, file_srv) }
```

```console
$ frameassembly ad_audit.fasm -o ad_audit.pcap && suricata -r ad_audit.pcap -k none
```

### 2. Verify Mail Gateway Filters & Cleartext Auth Policies Without Fighting Postfix (`SMTP`, `IMAP`, `POP3`)
Checking whether an inspection appliance catches spoofed `MAIL FROM` envelopes, blocked attachment extensions, or legacy cleartext `IMAP` / `POP3` logins shouldn't require `nc` typos or live mail relays. FrameAssembly tracks TCP `SEQ`/`ACK` state automatically across the full `SMTP` conversation and formats CRLF-terminated mailbox sessions out of the box:

```frameassembly
host ext_mta  { ip 198.51.100.25 mac 00:11:22:33:44:25 }
host mail_gw  { ip 10.10.25.10   mac aa:bb:cc:dd:ee:10 }
host legacy_c { ip 10.10.50.88   mac 00:11:22:33:44:88 }

flow smtp_filter_check(mta, gw) {
    mta -> gw tcp syn srcport 52025 dstport 25 win 65535 mss 1460 wait 1ms
    mta <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    mta -> gw tcp ack wait 1ms
    mta <- gw smtp code 220 reply "mx01.example.com ESMTP Postfix" wait 2ms
    mta -> gw smtp ehlo "mailer.suspicious-sender.test" wait 1ms
    mta <- gw smtp code 250 reply "mx01.example.com" wait 1ms
    mta -> gw smtp mail_from "<ceo-urgent@suspicious-sender.test>" wait 1ms
    mta <- gw smtp code 250 reply "2.1.0 Ok" wait 1ms
    mta -> gw smtp rcpt_to "<finance@example.com>" wait 1ms
    mta <- gw smtp code 250 reply "2.1.5 Ok" wait 1ms
    mta -> gw smtp cmd "DATA" wait 1ms
    mta <- gw smtp code 354 reply "End data with <CR><LF>.<CR><LF>" wait 1ms
    mta -> gw smtp cmd "Subject:" param "Urgent Wire Transfer" body "Please open invoice_q4.scr immediately." wait 3ms
    mta <- gw smtp code 550 reply "5.7.1 Message rejected by attachment policy" wait 2ms
    mta -> gw smtp quit
}

flow cleartext_mailbox_probe(c, gw) {
    c -> gw imap tag "A001" cmd "LOGIN" arg "finance@example.com Winter2026!" wait 2ms
    c <- gw imap tag "A001" status "NO" response "Cleartext authentication disabled" wait 2ms
    c -> gw pop3 cmd "USER" arg "finance@example.com" wait 2ms
    c <- gw pop3 err response "Plaintext POP3 prohibited; use port 995"
}

compile {
    smtp_filter_check(ext_mta, mail_gw)
    cleartext_mailbox_probe(legacy_c, mail_gw)
}
```

```console
$ frameassembly mail_test.fasm -o mail_test.pcap && tshark -r mail_test.pcap -Y "smtp || imap || pop"
```

### 3. Audit Database Activity Monitors, SQLi Rules & Exposed Caches (`PostgreSQL`, `MySQL`, `Redis`, `Memcached`, `NFS`)
Database Activity Monitoring (DAM) sensors and internal segmentation firewalls are notoriously annoying to test because binary database protocols reject raw ASCII strings on TCP 5432 or 3306. FrameAssembly builds valid PostgreSQL v3.0 frontend/backend frames, little-endian MySQL v10 packets, RESP bulk-string arrays, Memcached UDP/binary requests, and ONC-RPC v2 `NFS` calls:

```frameassembly
host app_node { ip 10.30.1.15 mac 00:1a:2b:30:01:15 }
host data_srv { ip 10.30.2.40 mac 00:1a:2b:30:02:40 }

flow db_and_cache_audit(app, db) {
    // PostgreSQL v3.0 startup + suspicious SQL query inspection
    app -> db tcp syn srcport 55432 dstport 5432 win 65535 mss 1460 wait 1ms
    app <- db tcp syn ack win 65535 mss 1460 wait 1ms
    app -> db tcp ack wait 1ms
    app -> db postgres startup user "readonly_reporting" db "customers" wait 1ms
    app <- db postgres auth_ok wait 1ms
    app <- db postgres ready_for_query wait 1ms
    app -> db postgres query sql "SELECT email, password_hash FROM users WHERE '1'='1';" wait 2ms
    app <- db postgres error_response sql "permission denied for table users" wait 2ms

    // MySQL v10 server greeting + unauthorized root login rejection (Error 1045)
    app <- db mysql greeting server_version "8.0.36" wait 1ms
    app -> db mysql login user "root" db "production" wait 1ms
    app <- db mysql err errcode 1045 wait 2ms

    // Unauthenticated Redis CONFIG probe, UDP Memcached stats & NFSv4 export check
    app -> db redis cmd "CONFIG" args "GET" args "dir" wait 1ms
    app <- db redis reply_type "ERR" value "NOAUTH Authentication required" wait 1ms
    app -> db transport udp memcached cmd "stats" wait 1ms
    app -> db nfs vers 4 compound xid 0x99887766 tag "export_probe" path "/srv/backups"
}

compile { db_and_cache_audit(app_node, data_srv) }
```

```console
$ frameassembly show db_audit.fasm
$ frameassembly db_audit.fasm -o db_audit.pcap && zeek -C -r db_audit.pcap
```

### 4. Validate IoT & Microservice Broker ACLs (`MQTT`, `CoAP`, `AMQP`)
Whether an edge gateway is publishing retained `MQTT` sensor readings, polling `CoAP` over UDP, or routing events across `AMQP 0-9-1` exchanges, you can verify DMZ broker rules without deploying Mosquitto or RabbitMQ:

```frameassembly
host edge_gw { ip 10.60.10.12 mac 00:1e:c0:60:10:12 }
host broker  { ip 10.60.1.5   mac 00:1e:c0:60:01:05 }

flow broker_pipeline(gw, brk) {
    // MQTT v3.1.1 connect + retained QoS 1 publish
    gw -> brk tcp syn srcport 51883 dstport 1883 win 64240 mss 1460 wait 1ms
    gw <- brk tcp syn ack win 64240 mss 1460 wait 1ms
    gw -> brk tcp ack wait 1ms
    gw -> brk mqtt connect client_id "turbine-gw-12" keepalive 60 wait 1ms
    gw <- brk mqtt connack return_code 0 wait 1ms
    gw -> brk mqtt publish topic "plant/line4/temp" qos 1 retain pkt_id 7 payload "{\"celsius\":84.2}" wait 2ms
    gw <- brk mqtt puback pkt_id 7 wait 1ms

    // CoAP confirmable GET + 2.05 Content ACK on UDP 5683
    gw -> brk coap con get msgid 0x2201 token 0x0a0b0c0d uri_path "sensors/pressure" content_format 50 wait 2ms
    gw <- brk coap ack code "2.05" msgid 0x2201 token 0x0a0b0c0d content_format 50 payload "{\"bar\":6.4}" wait 2ms

    // AMQP 0-9-1 preface, channel open, and Basic.Publish on TCP 5672
    gw -> brk amqp protocol_header wait 1ms
    gw <- brk amqp connection_start wait 1ms
    gw -> brk amqp channel_open channel 1 wait 1ms
    gw -> brk amqp basic_publish channel 1 exchange "telemetry.events" routing_key "alerts.high_temp" payload "{\"unit\":12}"
}

compile { broker_pipeline(edge_gw, broker) }
```

## Protocol Summary Matrix (14 Protocols)

| Protocol | Keyword | Default L4 & Port | Dual-Transport Override | Wire Framing Handled Automatically |
| :--- | :--- | :--- | :--- | :--- |
| **SMTP** | `smtp` | TCP `25` | `dstport 587` / `465` | CRLF command/status lines + `\r\n.\r\n` `DATA` terminator on `body` |
| **IMAP** | `imap` | TCP `143` | `dstport 993` | Tagged (`A01`), untagged (`*`), and completion (`OK`/`NO`/`BAD`) lines |
| **POP3** | `pop3` | TCP `110` | `dstport 995` | `+OK` / `-ERR` server indicators + CRLF client verbs |
| **Kerberos v5** | `kerberos` | UDP `88` | `transport tcp` | RFC 4120 ASN.1 DER `[APPLICATION 10..13, 30]` + SPN slash splitting |
| **LDAP v3** | `ldap` | TCP `389` | `dstport 636` / `3268` | RFC 4511 ASN.1 BER `LDAPMessage` (`0x30`) + search filter stripping |
| **SMB2 / SMB3** | `smb` | TCP `445` | `dstport 139` | 4B NetBIOS length + 64B `\xFESMB` header + UTF-16LE share/file paths |
| **NFS v2/v3/v4** | `nfs` | TCP `2049` | `transport udp` | 4B RPC Record Marking + 40B ONC-RPC v2 Call (`100003`) + XDR padding |
| **Redis (RESP)** | `redis` | TCP `6379` | `dstport 26379` | RESP `*<argc>\r\n$<len>\r\n` bulk-string arrays & typed server replies |
| **Memcached** | `memcached` | TCP `11211` | `transport udp` | ASCII text commands or 24-byte `0x80` Binary Protocol (`opcode`/`opaque`/`cas`) |
| **MySQL v10** | `mysql` | TCP `3306` | Custom `dstport` | 3B little-endian length + seq ID + `HandshakeV10` / `COM_QUERY` / `ERR` |
| **PostgreSQL v3** | `postgres` | TCP `5432` | Custom `dstport` | Unprefixed `0x00030000` `StartupMessage` + `'Q'`/`'R'`/`'C'`/`'Z'`/`'E'` tags |
| **MQTT v3.1.1** | `mqtt` | TCP `1883` | `dstport 8883` | Fixed header flags (`QoS`, `RETAIN`) + Remaining Length + packet IDs |
| **CoAP** | `coap` | UDP `5683` | `dstport 5684` | 4B RFC 7252 header + `c.dd` code packing + Option `11`/`12` delta encoding |
| **AMQP 0-9-1** | `amqp` | TCP `5672` | `dstport 5671` | `AMQP\x00\x00\x09\x01` header + Method/Heartbeat frames + `0xCE` end byte |

## Detailed Syntax Reference

### Mail Protocols (`SMTP`, `IMAP`, `POP3`)

* **`smtp` (RFC 5321 — Default TCP `25`)**
  * **Syntax:** `smtp [ehlo ["<domain>"] | helo ["<domain>"] | mail_from ["<addr>"] | rcpt_to ["<addr>"] | quit | cmd "<verb>"] [param "<arg>"] [code <u16>] [reply "<text>"] [body "<mime_body>"]`
  * **Defaults & Gotchas:** Emits `"EHLO localhost\r\n"` when no fields are given. Because `data` is a cross-layer token, write `smtp cmd "DATA"` to send the `DATA` command line; supplying `body "..."` automatically appends the mandatory `\r\n.\r\n` end-of-data sequence. For message submission or implicit TLS port checks, add `dstport 587` or `dstport 465`.
* **`imap` (RFC 3501 / RFC 9051 — Default TCP `143`)**
  * **Syntax:** `imap [tag "<tag>"] [cmd "<verb>"] [arg "<str>"] [status "<OK|NO|BAD>"] [response "<text>"]`
  * **Defaults & Gotchas:** `tag` defaults to `"A01"` (`cmd` defaults to `"NOOP"`). If `status` is specified, emits `<tag> <status> <response>\r\n`; if `response` is given without `cmd` or `status`, emits untagged `* OK <response>\r\n`.
* **`pop3` (RFC 1939 — Default TCP `110`)**
  * **Syntax:** `pop3 [cmd "<verb>"] [arg "<str>"] [ok | err] [response "<text>"]`
  * **Defaults & Gotchas:** Client commands default to `USER\r\n`. Use `ok` for `+OK <response>\r\n` and `err` for `-ERR <response>\r\n`.

### Identity and Directory Protocols (`Kerberos`, `LDAP`)

* **`kerberos` (RFC 4120 — Default UDP `88`, `transport tcp` for TCP `88`)**
  * **Syntax:** `kerberos [as_req | as_rep | tgs_req | tgs_rep | krb_error] [realm "<REALM>"] [cname "<principal>"] [sname "<service/host>"] [etype <u32>] [transport tcp]`
  * **Defaults & Gotchas:** Defaults to `as_req`, `realm "CORP.LOCAL"`, `cname "user"`, `sname "krbtgt"`, and `etype 18` (`aes256-cts-hmac-sha1-96`; use `etype 23` for `rc4-hmac` or `etype 17` for `aes128`). Service principals containing `/` (such as `"cifs/filesrv.corp.local"`) are automatically split into multi-component ASN.1 DER `PrincipalName` sequences. `krb_error` emits error code `24` (`KDC_ERR_PREAUTH_FAILED`).
* **`ldap` (RFC 4511 — Default TCP `389`)**
  * **Syntax:** `ldap [bind_req | bind_res | search_req | search_entry | search_done | unbind_req] [msgid <u32>] [base_dn "<dn>"] [filter "<expr>"] [result_code <u32>]`
  * **Defaults & Gotchas:** Defaults to `bind_req` (`msgid 1`, `base_dn "dc=corp,dc=local"`). Providing `filter` automatically selects `search_req` (`wholeSubtree`), and providing `result_code` (e.g., `0` `success`, `49` `invalidCredentials`) selects `bind_res` unless `search_done` is set.

### Network File Storage (`SMB`, `NFS`)

* **`smb` (MS-SMB2 — Default TCP `445`)**
  * **Syntax:** `smb [negotiate | session_setup | tree_connect | create | tree_disconnect | command "<LOGOFF|CLOSE|READ|WRITE>"] [status <u32>] [tree_id <u32>] [session_id <u64>] [msgid <u64>] [share "<unc_path>"] [filename "<file>"]`
  * **Defaults & Gotchas:** Automatically selects `tree_connect` when `share` is set, `create` when `filename` is set, or `negotiate` (`0x0202` dialect) otherwise. Always escape backslashes inside double-quoted UNC paths (`share "\\\\10.0.0.50\\IPC$"`).
* **`nfs` (RFC 1813 / RFC 7530 over ONC-RPC v2 — Default TCP `2049`, `transport udp` supported)**
  * **Syntax:** `nfs [compound | proc "<NULL|GETATTR|LOOKUP|READ|WRITE|COMPOUND>"] [vers <2|3|4>] [xid <u32>] [tag "<str>"] [path "<export_path>"] [transport udp]`
  * **Defaults & Gotchas:** Defaults to `vers 4`, `proc "LOOKUP"`, and `xid 0x12345678`. Use `xid` (not `txid`) to set the ONC-RPC transaction ID.

### Databases and Caches (`Postgres`, `MySQL`, `Redis`, `Memcached`)

* **`postgres` (Frontend/Backend v3.0 — Default TCP `5432`)**
  * **Syntax:** `postgres [startup | query | auth_ok | command_complete | ready_for_query | error_response] [user "<role>"] [db "<database>"] [sql "<statement_or_msg>"]`
  * **Defaults & Gotchas:** Emit **one** message type per statement line (`auth_ok` on one `<-` frame, `ready_for_query` on the next `<-` frame) so each wire message gets its own length header. On `command_complete`, `sql` sets the completion tag (default `"SELECT 1"`); on `error_response`, `sql` sets the SQLSTATE `28P01` error text.
* **`mysql` (Client/Server Wire Protocol v10 — Default TCP `3306`)**
  * **Syntax:** `mysql [greeting | login | query | ok | err | eof] [server_version "<ver>"] [user "<user>"] [db "<schema>"] [sql "<statement>"] [errcode <u16>]`
  * **Defaults & Gotchas:** `greeting` builds a server-to-client `HandshakeV10` (`server_version` default `"8.0.35"`), `login` builds `HandshakeResponse41` (`user` default `"root"`), `query` sends `COM_QUERY` (`0x03`), and `err` emits `#28000Access denied` (`errcode` default `1045`).
* **`redis` (RESP2 / RESP3 — Default TCP `6379`)**
  * **Syntax:** `redis [get | set | cmd "<verb>"] [key "<key>"] [args "<arg>"...] [reply_type "<SIMPLE|STATUS|OK|ERROR|ERR|INTEGER|INT|BULK>"] [value "<val>"]`
  * **Defaults & Gotchas:** `args` can be repeated multiple times on the same statement to build multi-argument RESP arrays (`redis cmd "HSET" key "user:1" args "role" value "admin"`). Omitting all modifiers sends `*1\r\n$4\r\nPING\r\n`.
* **`memcached` (ASCII & Binary Protocol — Default TCP `11211`, `transport udp` supported)**
  * **Syntax:** `memcached [get | set | cmd "<verb>"] [key "<key>"] [value "<val>"] [flags <u32>] [exptime <u32>] [opcode <u8>] [opaque <u32>] [cas <u64>] [transport udp]`
  * **Defaults & Gotchas:** Emits ASCII commands (`get`, `set`, `delete`, `stats`, `version`, `flush_all`) by default, and switches automatically to the 24-byte `0x80` Binary Protocol header whenever `opcode`, `opaque`, or `cas` is present.

### Message Brokers and IoT Queues (`MQTT`, `CoAP`, `AMQP`)

* **`mqtt` (OASIS MQTT v3.1.1 — Default TCP `1883`)**
  * **Syntax:** `mqtt [connect | connack | publish | puback | subscribe | suback | pingreq | pingresp | disconnect | pkt_type "<type>"] [client_id "<id>"] [topic "<topic>"] [qos <0..2>] [retain [0|1]] [pkt_id <u16>] [keepalive <u16>] [return_code <u8>]`
  * **Defaults & Gotchas:** Defaults to `connect` (`client_id "client-01"`, `keepalive 60`). Attach published message payloads with `payload "..."` or `hexpayload "..."`.
* **`coap` (RFC 7252 — Default UDP `5683`)**
  * **Syntax:** `coap [con | non | ack | rst | msg_type "<type>"] [get | post | put | delete | code "<c.dd>"] [msgid <u16>] [token <u32|"<hex>">] [uri_path "<path>"] [content_format <u16>]`
  * **Defaults & Gotchas:** Inside a `coap` statement, `ack` and `rst` set the CoAP header message type rather than TCP flags. Use dotted `code "2.05"` (`Content`), `code "2.01"` (`Created`), or `code "4.04"` (`Not Found`) for RFC 7252 response codes, and `payload "..."` to append the `0xFF` payload marker.
* **`amqp` (AMQP 0-9-1 — Default TCP `5672`)**
  * **Syntax:** `amqp [protocol_header | connection_start | channel_open | basic_publish | basic_deliver | heartbeat] [channel <u16>] [exchange "<name>"] [routing_key "<key>"]`
  * **Defaults & Gotchas:** Emits the 8-byte `AMQP\x00\x00\x09\x01` preface when no frame flag is specified, or wraps `Connection.Start` (`10,10`), `Channel.Open` (`20,10`), `Basic.Publish` (`60,40`), `Basic.Deliver` (`60,60`), and `Heartbeat` frames with the mandatory `0xCE` frame-end byte.

## Reversing Existing Mail, Auth, Storage, Database & Broker Captures (`frameassembly reverse`)

```console
# Convert an existing LDAP, SMB, Postgres, MySQL, Redis, or MQTT .pcap / .pcapng capture into editable .fasm code
$ frameassembly reverse db_audit.pcap -o sanitized_db_audit.fasm
$ frameassembly sanitized_db_audit.fasm -o sanitized_db_audit.pcap
```

## Related Guides

* [**Layer 7 Infrastructure & Telemetry (`docs/l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — `DNS`, `DHCP`, `RADIUS`, `TACACS+`, `Syslog`, `NetFlow`, and `IPFIX`.
* [**Layer 7 Web, Cloud & VoIP (`docs/l7_web_and_cloud.md`)**](l7_web_and_cloud.md) — `HTTP/1.1`, `HTTP/2`, `gRPC`, `TLS`, `QUIC`, `SSH`, `FTP`, and `SIP`.
* [**Layer 4 Transports (`docs/l4_transports.md`)**](l4_transports.md) — Stateful 4-tuple `TCP` handshakes, `UDP`, and `SCTP`.