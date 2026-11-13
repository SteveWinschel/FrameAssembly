# Layer 7 — Web, Cloud, Transport Security, VoIP & Remote Access

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

`curl` can only show you a `grpc-status: 14 UNAVAILABLE` if you already have a backend that fails in exactly that way, at exactly that moment. The same goes for a WAF block page, a masked WebSocket frame, or a TLS `ClientHello` for a domain your proxy is supposed to refuse. Spinning up the real service to get one failure is the slow way to get one packet.

The other half of this page is the opposite problem: protocols you never want to enable on a real device. Turning on `telnetd` on a core switch "just for five minutes to test Suricata" is the opening paragraph of a lot of postmortems. Here the sensor sees the cleartext login, the switch never runs the service, and nobody has to write the document.

Each section covers one problem with short `flow(a, b)` snippets you can reuse, and one cheat-sheet table beneath the group. Every TCP-based statement (`http`, `http2`, `grpc`, `websocket`, `tls`, `ssh`, `telnet`, `ftp`, `whois`, `rtsp`, and `sip` with `transport tcp`) emits a `psh ack` segment, swaps ports on `<-` replies, and advances the TCP sequence and acknowledgment numbers by the exact payload length. Open the connection with a `tcp syn` handshake when you want the capture to start properly.

```console
$ frameassembly show waf_check.frasm
$ frameassembly waf_check.frasm waf_check.pcap && suricata -r waf_check.pcap -k none
```

## 1. WAF Rules, `grpc` Failures and Masked `websocket` Streams

### Make the WAF Say No

A tracked handshake, a classic SQL injection in a login POST, and the `403` a WAF would answer with. `body` sets `Content-Length` for you:

```frameassembly
host scanner { ip 198.51.100.42 mac 00:0c:29:11:22:33 }
host waf_gw  { ip 203.0.113.10  mac 00:1b:21:aa:bb:cc }

flow waf_sqli_block(c, gw) {
    c -> gw tcp syn srcport 53080 dstport 80 win 65535 mss 1460 wait 1ms
    c <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    c -> gw tcp ack wait 1ms
    c -> gw http post uri "/api/login" hosthdr "portal.example.com" contenttype "application/json" body "{\"user\":\"admin' OR 1=1--\"}" wait 2ms
    c <- gw http status 403 reason "Forbidden" contenttype "application/json" body "{\"blocked\":\"sqli_rule_942100\"}"
}

compile { waf_sqli_block(scanner, waf_gw) }
```

### Reverse-Proxy Headers

Envoy, Nginx, and HAProxy all rewrite headers on the way through. Use repeated `header "<K>" "<V>"` modifiers to check what your logging pipeline sees in `X-Forwarded-For` and `X-Request-Id`:

```frameassembly
host api_gw  { ip 10.120.1.10 mac 00:1b:21:10:01:0a }
host app_svc { ip 10.120.1.50 mac 00:1b:21:10:01:32 }

flow proxied_order(gw, svc) {
    gw -> svc http post uri "/v1/orders" version "1.1" hosthdr "api.corp.example" useragent "Envoy/1.31" contenttype "application/json" header "X-Request-Id" "req-4092" header "X-Forwarded-For" "198.51.100.7" body "{\"sku\":\"RTR-9000\",\"qty\":2}" wait 1ms
    gw <- svc http version "1.1" status 201 reason "Created" contenttype "application/json" header "X-Request-Id" "req-4092" body "{\"order_id\":8801,\"status\":\"confirmed\"}"
}

compile { proxied_order(api_gw, app_svc) }
```

### HTTP/2 Connection Lifecycle

The 24-byte connection preface, a `SETTINGS` exchange, one request on stream 1, and a graceful `goaway`. Stream `0` is connection control, odd numbers are client streams:

```frameassembly
host api_gw  { ip 10.120.1.10 mac 00:1b:21:10:01:0a }
host app_svc { ip 10.120.1.50 mac 00:1b:21:10:01:32 }

flow h2_lifecycle(gw, svc) {
    gw -> svc http2 preface wait 1ms
    gw -> svc http2 settings streamid 0 wait 1ms
    gw <- svc http2 settings streamid 0 wait 1ms
    gw -> svc http2 headers streamid 1 payload ":method GET :path /v2/inventory" wait 1ms
    gw <- svc http2 data streamid 1 payload "{\"in_stock\":true}" wait 1ms
    gw <- svc http2 goaway streamid 0 wait 2ms
}

compile { h2_lifecycle(api_gw, app_svc) }
```

### A `grpc` Service That Is Down

The request and the failure a service mesh reports when the upstream resets, on TCP port 50051. `grpcstatus 14` is UNAVAILABLE, the one that is hard to reproduce on demand:

```frameassembly
host api_gw  { ip 10.120.1.10 mac 00:1b:21:10:01:0a }
host app_svc { ip 10.120.1.50 mac 00:1b:21:10:01:32 }

flow grpc_unavailable(gw, svc) {
    gw -> svc grpc service "inventory.v1.StockService" method "ReserveItems" payload "PROTOBUF_RESERVE_REQ" wait 1ms
    gw <- svc grpc service "inventory.v1.StockService" method "ReserveItems" grpcstatus 14 payload "upstream_reset" wait 2ms
}

compile { grpc_unavailable(api_gw, app_svc) }
```

### Masked `websocket` Frames

RFC 6455 requires every client frame to be XOR-masked with a 32-bit key. Generators that skip the mask produce frames that proxies drop on sight, which makes for a confusing test. `maskkey` sets the key, and server frames are sent unmasked:

```frameassembly
host api_gw  { ip 10.120.1.10 mac 00:1b:21:10:01:0a }
host app_svc { ip 10.120.1.50 mac 00:1b:21:10:01:32 }

flow ws_session(gw, svc) {
    gw -> svc websocket text finbit 1 maskkey 0x37fa213d payload "{\"subscribe\":\"orders\"}" wait 1ms
    gw <- svc websocket opcode "text" finbit 1 payload "{\"event\":\"SHIPPED\",\"id\":8801}" wait 1ms
    gw -> svc websocket ping finbit 1 maskkey 0x11223344 payload "hb" wait 1ms
    gw <- svc websocket pong finbit 1 payload "hb" wait 1ms
    gw -> svc websocket close finbit 1 maskkey 0x37fa213d hexpayload "03e8"
}

compile { ws_session(api_gw, app_svc) }
```

### Cheat-Sheet: `http`, `http2`, `grpc`, `websocket`

| Protocol | Operations / Frame Types | Modifiers | Wire Notes and Defaults |
| :--- | :--- | :--- | :--- |
| **`http`** | `get`, `post`, `put`, `delete`, `head`, `options`, `patch` (or `method "<verb>"`) | `uri "<path>"`, `version "<ver>"`, `hosthdr "<host>"`, `useragent "<ua>"`, `contenttype "<mime>"`, `header "<K>" "<V>"`, `status <100..599>`, `reason "<str>"`, `body "<str>"` | `TCP 80`, RFC 9110 / 9112. Setting `status` makes it a response, omitting it makes a request. `header` may repeat. `Content-Length` is computed from `body`. |
| **`http2`** | `preface`, `settings` (default), `headers`, `data`, `windowupdate`, `ping`, `goaway` | `streamid <u32>`, `payload "<str>"`, `hexpayload "<hex>"` | `TCP 443`, RFC 9113 with the 9-byte frame header. `preface` is the 24-byte `PRI * HTTP/2.0` string. `streamid 0` is connection control, odd numbers are client streams. |
| **`grpc`** | Unary / streaming RPC frame | `service "<pkg.Svc>"`, `method "<Rpc>"`, `grpcstatus <0..16>`, `payload "<str>"` | `TCP 50051`, 5-byte length prefix. `grpcstatus`: `0` OK, `3` INVALID_ARGUMENT, `4` DEADLINE_EXCEEDED, `7` PERMISSION_DENIED, `14` UNAVAILABLE, `16` UNAUTHENTICATED. |
| **`websocket`** | `text` (default), `binary`, `ping`, `pong`, `close` (or `opcode "<text\|binary\|ping\|pong\|close>"`) | `finbit <0\|1>`, `maskkey <u32>`, `payload "<str>"`, `hexpayload "<hex>"` | `TCP 80`, RFC 6455. Sets the `MASK` bit (`0x80`) and XOR-masks the payload with the 4-byte `maskkey`. |

## 2. `tls` 1.3 `SNI` and `ALPN` Filtering, and `quic` UDP 443 Pinholes

### Block a Domain by `SNI`

Next-generation firewalls and egress proxies read the `ClientHello` before anything is encrypted. Test the policy over IPv6 without creating a single X.509 certificate. `ciphersuite 4866` is `TLS_AES_256_GCM_SHA384`. The `alert` defaults to a fatal `handshake_failure`:

```frameassembly
host client_v6   { ip 2001:db8:443::50 }
host cdn_edge_v6 { ip 2001:db8:443::1 }

flow tls13_sni_alpn(c, s) {
    c -> s tcp syn srcport 54443 dstport 443 win 65535 mss 1440 wscale 7 sackperm wait 1ms
    c <- s tcp syn ack win 65535 mss 1440 wscale 7 sackperm wait 1ms
    c -> s tcp ack wait 1ms
    c -> s tls clienthello recordversion 0x0301 handshakeversion 0x0303 sni "edge.cdn.example.com" ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls serverhello recordversion 0x0303 handshakeversion 0x0303 ciphersuite 4866 alpn "h2" wait 1ms
    c -> s tls alert recordversion 0x0303 wait 5ms
}

compile { tls13_sni_alpn(client_v6, cdn_edge_v6) }
```

For a full handshake with certificate and encrypted application data, add these between the `serverhello` and the `alert`:

```frameassembly
host client_v6   { ip 2001:db8:443::50 }
host cdn_edge_v6 { ip 2001:db8:443::1 }

flow tls_full_exchange(c, s) {
    c <- s tls certificate recordversion 0x0303 payload "X509_ECDSA_CERT_CHAIN" wait 1ms
    c <- s tls finished recordversion 0x0303 payload "SERVER_VERIFY" wait 1ms
    c -> s tls finished recordversion 0x0303 payload "CLIENT_VERIFY" wait 1ms
    c -> s tls appdata recordversion 0x0303 payload "ENCRYPTED_H2_GET" wait 1ms
}

compile { tls_full_exchange(client_v6, cdn_edge_v6) }
```

### Is UDP 443 Open for `quic`?

Many firewalls block UDP 443 so that HTTP/3 clients give up and fall back to TCP. This flow plays a QUIC v1 `initial`, a `retry` token challenge, the second `initial`, `0-RTT` data, a `handshake` packet, and a 1-RTT `short` header packet:

```frameassembly
host client_v6   { ip 2001:db8:443::50 }
host cdn_edge_v6 { ip 2001:db8:443::1 }

flow quic_retry_and_0rtt(c, s) {
    c -> s quic initial version 1 dcid 0x8394c8f03e515708 scid 0x1122334455667788 pktnum 1 payload "CRYPTO_CH" wait 1ms
    c <- s quic retry   version 1 dcid 0x1122334455667788 scid 0x9988776655443322 token "retry_tok_v1" wait 1ms
    c -> s quic initial version 1 dcid 0x9988776655443322 scid 0x1122334455667788 token "retry_tok_v1" pktnum 2 payload "CRYPTO_CH_RETRY" wait 1ms
    c -> s quic zerortt version 1 dcid 0x9988776655443322 scid 0x1122334455667788 pktnum 3 payload "H3_0RTT_GET" wait 1ms
    c <- s quic handshake version 1 dcid 0x1122334455667788 scid 0x9988776655443322 pktnum 1 payload "CRYPTO_FIN" wait 1ms
    c <- s quic short dcid 0x1122334455667788 pktnum 2 payload "H3_200_OK_DATA"
}

compile { quic_retry_and_0rtt(client_v6, cdn_edge_v6) }
```

### Cheat-Sheet: `tls`, `quic`

| Protocol | Packet / Record Types | Modifiers | Wire Notes and Defaults |
| :--- | :--- | :--- | :--- |
| **`tls`** | `clienthello` (default), `serverhello`, `certificate`, `finished`, `appdata`, `alert` | `recordversion <u16>`, `handshakeversion <u16>`, `sni "<host>"`, `ciphersuite <u16>`, `alpn "<proto>"`, `payload "<str>"` | `TCP 443`, RFC 8446 / 6066. 5-byte record and 4-byte handshake lengths are computed. `ciphersuite`: `4865` (`0x1301` AES_128_GCM), `4866` (`0x1302` AES_256_GCM), `4867` (`0x1303` CHACHA20). `alert` defaults to fatal `handshake_failure` (`[2, 40]`). |
| **`quic`** | `initial` (default), `zerortt`, `handshake`, `retry`, `short` | `version <u32>`, `dcid <u64>`, `scid <u64>`, `token "<str>"`, `pktnum <u32>`, `payload "<str>"` | `UDP 443`, RFC 9000 / 9114, variable-length integers computed. `version 1` is QUIC v1, `0x6b3343cf` is QUIC v2 (RFC 9369). |

## 3. Cleartext Tripwires, `ssh` Banner Audits, `tftp` ZTP and `whois`

### `telnet` on a Management VLAN

The sensor should alert on the login prompt and the username going out in cleartext. The switch does not have to run `telnetd`. Options are `do`, `will`, `dont`, `wont` with a number (`1` Echo, `3` Suppress Go Ahead):

```frameassembly
host admin_ws    { ip 10.50.1.100 }
host core_switch { ip 10.50.1.1 }

flow telnet_login(ws, sw) {
    ws -> sw telnet do 1 will 3 wait 1ms
    ws <- sw telnet will 1 do 3 data "User Access Verification\r\nUsername: " wait 1ms
    ws -> sw telnet data "netadmin\r\n" wait 2ms
}

compile { telnet_login(admin_ws, core_switch) }
```

### `ftp` Passwords and the Passive-Mode Helper

A cleartext `PASS` is the whole point of this capture. The `229` reply carries the extended passive port that a firewall's FTP helper is supposed to open a pinhole for:

```frameassembly
host admin_ws    { ip 10.50.1.100 }
host core_switch { ip 10.50.1.1 }

flow ftp_cleartext_login(ws, sw) {
    ws <- sw ftp code 220 reply "Switch FTP Ready" wait 1ms
    ws -> sw ftp cmd "USER" arg "admin" wait 1ms
    ws <- sw ftp code 331 reply "Password required" wait 1ms
    ws -> sw ftp cmd "PASS" arg "SwitchPass!2026" wait 1ms
    ws <- sw ftp code 230 reply "User logged in" wait 1ms
    ws -> sw ftp cmd "EPSV" wait 1ms
    ws <- sw ftp code 229 reply "Entering Extended Passive Mode (|||62001|)"
}

compile { ftp_cleartext_login(admin_ws, core_switch) }
```

### Outdated `ssh` Banners

A bastion that still advertises `OpenSSH_7.2p2` should show up in a scanner report. The flow runs the banner exchange, `kexinit` with 16-byte cookies, `newkeys`, and an encrypted channel-data record (`msgcode 94`):

```frameassembly
host admin_ws    { ip 10.50.1.100 }
host core_switch { ip 10.50.1.1 }

flow ssh_banner_audit(ws, sw) {
    ws -> sw ssh banner "SSH-2.0-OpenSSH_7.2p2" wait 1ms
    ws <- sw ssh banner "SSH-2.0-Cisco-2.0" wait 1ms
    ws -> sw ssh kexinit cookie "00112233445566778899aabbccddeeff" wait 1ms
    ws <- sw ssh kexinit cookie "ffeeddccbbaa99887766554433221100" wait 1ms
    ws -> sw ssh newkeys wait 1ms
    ws <- sw ssh newkeys wait 1ms
    ws -> sw ssh msgcode 94 payload "ENCRYPTED_SHOW_RUN" wait 2ms
}

compile { ssh_banner_audit(admin_ws, core_switch) }
```

### `tftp` Zero-Touch Provisioning

A new leaf pulls its startup config over UDP port 69. This lets you check the ZTP path through an ACL, or see how a PXE or config server answers a missing file (`error`, `errcode 1`):

```frameassembly
host new_leaf   { ip 10.50.1.100 }
host ztp_server { ip 10.50.1.1 }

flow ztp_config_pull(leaf, srv) {
    leaf -> srv tftp rrq filename "leaf01-startup.cfg" mode "octet" wait 1ms
    leaf <- srv tftp data block 1 payload "hostname leaf01\ninterface Eth1/1\n" wait 1ms
    leaf -> srv tftp ack block 1 wait 2ms
}

compile { ztp_config_pull(new_leaf, ztp_server) }
```

### `whois` for an Air-Gapped SOC

Domain and ASN enrichment that works with no outbound access, and no RIR rate limit. `domain` accepts a domain, an IPv4 or IPv6 prefix, or an ASN:

```frameassembly
host analyst_ws { ip 10.50.1.100 }
host whois_srv  { ip 10.50.1.1 }

flow asn_lookup(ws, srv) {
    ws -> srv whois query domain "AS65001" wait 1ms
    ws <- srv whois response domain "AS65001" registrar "IANA Private Use ASN"
}

compile { asn_lookup(analyst_ws, whois_srv) }
```

### Cheat-Sheet: `ssh`, `telnet`, `ftp`, `tftp`, `whois`

| Protocol | Sub-Keywords / Modes | Modifiers | Wire Notes and Defaults |
| :--- | :--- | :--- | :--- |
| **`ssh`** | Version banner (default), `kexinit`, `newkeys` | `banner "<str>"`, `msgcode <0..255>`, `cookie "<32hex_or_str>"`, `payload "<str>"` | `TCP 22`, RFC 4253, binary packets padded to 8-byte boundaries. `msgcode`: `20` KEXINIT, `21` NEWKEYS, `50` UserAuth Request, `90` Channel Open, `94` Channel Data. |
| **`telnet`** | `will`, `wont`, `do`, `dont` | `[option] <0..255>`, `data "<str>"`, `payload "<str>"` | `TCP 23`, RFC 854 / 855. Options: `0` Binary, `1` Echo, `3` Suppress Go Ahead, `24` TermType, `31` NAWS. |
| **`ftp`** | Client command or 3-digit reply | `cmd "<verb>"`, `arg "<str>"`, `code <100..599>`, `reply "<str>"` | `TCP 21`, RFC 959 / 2428. `code`: `220` Ready, `331` Password required, `230` Logged in, `227` PASV, `229` EPSV, `530` Login incorrect. |
| **`tftp`** | `rrq` (default), `wrq`, `data`, `ack`, `error` (or `err`) | `filename "<str>"`, `mode "<octet\|netascii>"`, `block <u16>`, `errcode <u16>`, `errmsg "<str>"`, `payload "<str>"` | `UDP 69`, RFC 1350. `errcode`: `1` File not found, `2` Access violation, `3` Disk full, `6` File exists. |
| **`whois`** | `query` (default), `response` | `domain "<str>"`, `registrar "<str>"`, `payload "<str>"` | `TCP 43`, RFC 3912. `domain` accepts domains, IPv4/IPv6 prefixes, and ASNs (`"AS65001"`). |

## 4. `sip` ALG Bugs, `dscp 46` `rtp` Voice, `stun`, `rtsp` Cameras and Rogue `ssdp`

### Find Out What the SIP ALG Rewrote

One-way audio across a firewall almost always means a SIP ALG helpfully rewrote something it should have left alone. A `stun` binding request to learn the public address, then an `invite` whose SDP body announces RTP on port 5004, `200 OK`, and `ack`. Signaling is marked `dscp 24` (CS3):

```frameassembly
host voip_phone { ip 10.80.1.50 }
host sbc_media  { ip 10.80.1.10 }

flow sip_call_setup(phone, sbc) {
    phone -> sbc stun bindingrequest txid 9001 software "Polycom-VVX/6.4" wait 1ms
    phone <- sbc stun bindingresponse txid 9001 xormappedaddr 203.0.113.50 software "Coturn-4.6" wait 2ms
    phone -> sbc dscp 24 sip invite uri "sip:1002@pbx.example.com" from "sip:1001@pbx.example.com" to "sip:1002@pbx.example.com" callid "call-7741@10.80.1.50" cseq 1 contact "sip:1001@10.80.1.50" contenttype "application/sdp" body "v=0\r\nm=audio 5004 RTP/AVP 0\r\n" wait 2ms
    phone <- sbc dscp 24 sip status 200 reason "OK" callid "call-7741@10.80.1.50" cseq 1 wait 2ms
    phone -> sbc dscp 24 sip ack uri "sip:1002@pbx.example.com" callid "call-7741@10.80.1.50" cseq 1
}

compile { sip_call_setup(voip_phone, sbc_media) }
```

`stun` uses a plain IPv4 or IPv6 address in `xormappedaddr` (no `:port`), and the compiler XORs it with the magic cookie `0x2112A442`. Switch SIP to TCP with `transport tcp` after a handshake:

```frameassembly
host voip_phone { ip 10.80.1.50 }
host sbc_media  { ip 10.80.1.10 }

flow sip_over_tcp(phone, sbc) {
    phone -> sbc tcp syn srcport 50600 dstport 5060 win 65535 mss 1460 wait 1ms
    phone <- sbc tcp syn ack win 65535 mss 1460 wait 1ms
    phone -> sbc tcp ack wait 1ms
    phone -> sbc transport tcp sip options uri "sip:pbx.example.com" callid "opt-5521@10.80.1.50" cseq 1 wait 2ms
}

compile { sip_over_tcp(voip_phone, sbc_media) }
```

### Is Voice Really in the EF Queue?

G.711 PCMU (`pt 0`) at 20 ms spacing, marked `dscp 46` in both directions, then the `bye` that ends the call. Count the packets on the far side of the QoS trunk:

```frameassembly
host voip_phone { ip 10.80.1.50 }
host sbc_media  { ip 10.80.1.10 }

flow rtp_voice_and_bye(phone, sbc) {
    phone -> sbc dscp 46 rtp pt 0 seq 1001 timestamp 160 ssrc 0x11223344 marker 1 payload "G711_PCMU_FRAME_1" wait 20ms
    phone <- sbc dscp 46 rtp pt 0 seq 5001 timestamp 160 ssrc 0x99887766 marker 1 payload "G711_PCMU_REPLY_1" wait 20ms
    phone -> sbc dscp 24 sip bye uri "sip:1002@pbx.example.com" callid "call-7741@10.80.1.50" cseq 2 wait 2ms
    phone <- sbc dscp 24 sip status 200 reason "OK" callid "call-7741@10.80.1.50" cseq 2
}

compile { rtp_voice_and_bye(voip_phone, sbc_media) }
```

### NVR Camera Setup over `rtsp`

`describe`, `setup` with the `Transport:` header, `play`, and `teardown` on TCP port 554. The header is `transporthdr`, because `transport` already switches Layer 4 protocols:

```frameassembly
host nvr    { ip 10.80.1.50 }
host camera { ip 10.80.1.10 }

flow rtsp_camera_stream(n, cam) {
    n -> cam rtsp describe uri "rtsp://10.80.1.10:554/cam01/main" cseq 1 wait 1ms
    n <- cam rtsp status 200 cseq 1 wait 1ms
    n -> cam rtsp setup uri "rtsp://10.80.1.10:554/cam01/main/track1" cseq 2 transporthdr "RTP/AVP;unicast;client_port=5004-5005" wait 1ms
    n <- cam rtsp status 200 cseq 2 session "cam-sess-991" wait 1ms
    n -> cam rtsp play uri "rtsp://10.80.1.10:554/cam01/main" cseq 3 session "cam-sess-991" wait 2ms
    n -> cam rtsp teardown uri "rtsp://10.80.1.10:554/cam01/main" cseq 4 session "cam-sess-991"
}

compile { rtsp_camera_stream(nvr, camera) }
```

### Rogue UPnP Sweep with `ssdp`

An `msearch` to `239.255.255.250:1900` and a media server answering with a `notify`. Useful for checking that the IoT VLAN stays separate from the office. `hosthdr` carries the `Host:` header here too:

```frameassembly
host scanner_ws { ip 10.80.1.50 }
host media_srv  { ip 10.80.1.10 }

flow ssdp_sweep(ws, media) {
    ws -> media ssdp msearch hosthdr "239.255.255.250:1900" man "\"ssdp:discover\"" mx 3 st "urn:schemas-upnp-org:device:MediaServer:1" wait 1ms
    ws <- media ssdp notify hosthdr "239.255.255.250:1900" nt "urn:schemas-upnp-org:device:MediaServer:1" nts "ssdp:alive" usn "uuid:media-01::upnp:rootdevice" location "http://10.80.1.10:8200/rootDesc.xml"
}

compile { ssdp_sweep(scanner_ws, media_srv) }
```

### Cheat-Sheet: `sip`, `rtp`, `stun`, `rtsp`, `ssdp`

| Protocol | Methods / Types | Modifiers | Wire Notes and Defaults |
| :--- | :--- | :--- | :--- |
| **`sip`** | `invite` (default), `ack`, `bye`, `cancel`, `register`, `options` (or `method "<verb>"`) | `uri "<sip>"`, `status <100..699>`, `reason "<str>"`, `from "<uri>"`, `to "<uri>"`, `callid "<id>"`, `cseq <u32>`, `via "<str>"`, `contact "<uri>"`, `contenttype "<mime>"`, `body "<sdp>"`, `transport tcp\|udp` | `UDP 5060`, or `TCP 5060` with `transport tcp`. RFC 3261 / 4566. `Content-Length` is computed from `body`. |
| **`rtp`** | Media frame | `pt <0..127>`, `seq <u16>`, `timestamp <u32>`, `ssrc <u32>`, `marker <0\|1>`, `payload "<str>"`, `hexpayload "<hex>"` | `UDP 5004` (override with `srcport` / `dstport`). RFC 3550 / 3551. `pt`: `0` PCMU, `8` PCMA, `9` G.722, `18` G.729, `96..127` dynamic (Opus, H.264). |
| **`stun`** | `bindingrequest` (default), `bindingresponse`, `bindingerror` | `txid <u32>`, `xormappedaddr <ip>`, `software "<str>"` | `UDP 3478`, RFC 8489 / 5389. `xormappedaddr` takes a plain IPv4 or IPv6 address. |
| **`rtsp`** | `options` (default), `describe`, `setup`, `play`, `teardown` (or `method "<verb>"`) | `uri "<url>"`, `status <100..599>`, `cseq <u32>`, `session "<id>"`, `transporthdr "<spec>"` | `TCP 554`, RFC 7826 / 2326. Always use `transporthdr` for the `Transport:` header. |
| **`ssdp`** | `msearch` (default), `notify` | `hosthdr "<ip:port>"`, `man "<str>"`, `mx <u8>`, `st "<target>"`, `nt "<type>"`, `nts "<sub_type>"`, `usn "<uuid>"`, `location "<url>"` | `UDP 1900`, UPnP DA 1.1 / 2.0. `nts`: `"ssdp:alive"`, `"ssdp:byebye"`, `"ssdp:update"`. |

`mqtt`, `coap`, and `amqp` are covered in [09_l7_mail_auth_storage_db.md](09_l7_mail_auth_storage_db.md).

## Inspecting and Replaying

```console
# Pull TLS SNI and ALPN extensions and QUIC connection IDs out in tshark
$ tshark -r tls13_sni_alpn.pcap -T fields -e frame.number -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str -e quic.dcid

# Check WAF, Suricata, or Zeek detections offline
$ suricata -r waf_check.pcap -k none
$ zeek -C -r ssh_banner_audit.pcap

# Replay SIP and DSCP EF RTP across a lab SBC or QoS trunk
$ sudo tcpreplay -i eth0 rtp_voice_and_bye.pcap
```
