# Layer 7 — Web, Cloud, Transport Security, VoIP & Remote Access (`docs/l7_web_and_cloud.md`)

[**Use Cases**](#web-cloud-security-and-voip-use-cases) • [**How It Works**](#what-frameassembly-handles-for-you) • [**Web, HTTP/2, gRPC & WebSocket**](#1-web-apis-and-microservices-http-http2-grpc-websocket) • [**TLS & QUIC**](#2-transport-security-and-http3-tls-quic) • [**SSH, Telnet, FTP, TFTP & WHOIS**](#3-remote-access-file-transfer-and-whois-ssh-telnet-tftp-ftp-whois) • [**VoIP, Media & UPnP**](#4-voip-streaming-media-and-upnp-sip-rtp-rtsp-stun-ssdp) • [**Inspect & Replay**](#inspecting-and-replaying-web-and-voip-captures)

## Why Use FrameAssembly for Web, Security & VoIP?

Testing a Web Application Firewall (WAF), checking whether an egress proxy blocks unauthorized TLS 1.3 `SNI`s or UDP `443` `QUIC`, debugging a broken firewall SIP ALG, or verifying that your SOC wakes up when someone opens Telnet on a management VLAN usually requires way too much throwaway infrastructure -> spin up Docker containers, Nginx reverse proxies, self-signed OpenSSL CAs, `protoc` gRPC stubs, Asterisk PBXs, or `telnetd` on a core switch :)

With **FrameAssembly**, you script both the client request and server response in a few lines of `.fasm` packet code, let the compiler handle TCP `SEQ`/`ACK` math, reply-port swapping, and `Content-Length` headers automatically, and feed the `.pcap` straight into **`tcpreplay`**, **Wireshark** / **`tshark`**, **Suricata**, or **Zeek**:

```frameassembly
host scanner { ip 198.51.100.42 mac 00:0c:29:11:22:33 }
host waf_gw  { ip 203.0.113.10  mac 00:1b:21:aa:bb:cc }

flow waf_and_sni_check(c, gw) {
    // Tracked TCP handshake -> suspicious HTTP POST -> 403 Forbidden WAF block
    c -> gw tcp syn srcport 53080 dstport 80 win 65535 mss 1460 wait 1ms
    c <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    c -> gw tcp ack wait 1ms
    c -> gw http post uri "/api/login" host_hdr "portal.example.com" content_type "application/json" body "{\"user\":\"admin' OR 1=1--\"}" wait 2ms
    c <- gw http status 403 reason "Forbidden" content_type "application/json" body "{\"blocked\":\"sqli_rule_942100\"}"
}

compile { waf_and_sni_check(scanner, waf_gw) }
```

```console
$ frameassembly show waf_check.fasm
$ frameassembly waf_check.fasm -o waf_check.pcap && suricata -r waf_check.pcap -k none
```

| Protocol | Keyword | Default Port | Standard / RFC | Primary Testing Focus |
| :--- | :--- | :--- | :--- | :--- |
| **HTTP/1.1** | `http` | `TCP 80` | RFC 9110 / 9112 | WAF SQLi/XSS rules, reverse-proxy `X-Forwarded-For` headers, REST status codes |
| **HTTP/2** | `http2` | `TCP 443` | RFC 9113 | Binary stream multiplexing, `SETTINGS` / `WINDOW_UPDATE`, graceful `GOAWAY` |
| **gRPC** | `grpc` | `TCP 50051` | gRPC over HTTP/2 | Service-mesh telemetry, Protobuf RPC paths, `grpc-status` error handling |
| **WebSocket** | `websocket`| `TCP 80` | RFC 6455 | XOR-masked client frames, `PING`/`PONG` keepalives, proxy upgrade policies |
| **TLS 1.2 / 1.3**| `tls` | `TCP 443` | RFC 8446 / 6066 | Firewall `SNI` & `ALPN` inspection, cipher-suite audits, fatal `Alert` drops |
| **QUIC / HTTP/3**| `quic` | `UDP 443` | RFC 9000 / 9114 | UDP `443` firewall pinholes, `Retry` token validation, `0-RTT` & `Short` frames |
| **SSH-2** | `ssh` | `TCP 22` | RFC 4253 | Outdated banner detection (`OpenSSH_7.2`), `KEXINIT` cookies, bastion ACLs |
| **Telnet** | `telnet` | `TCP 23` | RFC 854 / 855 | Cleartext management VLAN IDS alerts, `IAC` (`DO`/`WILL`) option negotiation |
| **TFTP** | `tftp` | `UDP 69` | RFC 1350 | Switch Zero-Touch Provisioning (ZTP), PXE boot blocks, `File not found` errors |
| **FTP** | `ftp` | `TCP 21` | RFC 959 / 2428 | Firewall `PASV`/`EPSV` ALG dynamic pinholes, cleartext credential alerts |
| **WHOIS** | `whois` | `TCP 43` | RFC 3912 | Air-gapped SOC domain/ASN enrichment tests without public RIR rate limits |
| **SIP** | `sip` | `UDP/TCP 5060`| RFC 3261 / 4566 | SBC call signaling (`INVITE`/`200`/`BYE`), SIP ALG mangling, SDP bodies |
| **RTP** | `rtp` | `UDP 5004` | RFC 3550 / 3551 | `DSCP EF` (`46`) voice/video priority queues, jitter & sequence-gap checks |
| **RTSP** | `rtsp` | `TCP 554` | RFC 7826 / 2326 | IP camera NVR VLAN ACLs (`DESCRIBE`/`SETUP`/`PLAY`), `Transport:` ports |
| **STUN** | `stun` | `UDP 3478` | RFC 8489 / 5389 | WebRTC ICE NAT traversal, `XOR-MAPPED-ADDRESS` reflexive IP discovery |
| **SSDP / UPnP** | `ssdp` | `UDP 1900` | UPnP DA 1.1 / 2.0 | Rogue UPnP media-server sweeps (`239.255.255.250`), IoT VLAN segmentation |

> **Looking for IoT & Message Broker Protocols (`MQTT`, `COAP`, `AMQP`)?**
> Those three live in [**Layer 7 — Mail, Auth, Storage, Databases & Message Brokers (`l7_mail_auth_storage_db.md`)**](l7_mail_auth_storage_db.md#5-message-brokers-and-iot-telemetry-mqtt-coap-amqp).

## Web, Cloud, Security and VoIP Use Cases

### 1. Audit WAF Rules, Microservice `gRPC` Failures & Masked `WebSocket` Streams Without Backend Stubs
Using `curl` only captures traffic if you already have a live backend returning the exact status code, headers, or `grpc-status: 14 UNAVAILABLE` failure you want to test—and naive packet generators forget RFC 6455's mandatory 32-bit client XOR mask on `WebSocket` frames so proxies drop them immediately. Script the whole microservice tier directly:

```frameassembly
host api_gw  { ip 10.120.1.10 mac 00:1b:21:10:01:0a }
host app_svc { ip 10.120.1.50 mac 00:1b:21:10:01:32 }

flow web_and_microservice_tier(gw, svc) {
    // 1. HTTP/1.1 POST with reverse-proxy headers + 201 Created JSON response
    gw -> svc http post uri "/v1/orders" version "1.1" host_hdr "api.corp.example" user_agent "Envoy/1.31" content_type "application/json" header "X-Request-Id" "req-4092" header "X-Forwarded-For" "198.51.100.7" body "{\"sku\":\"RTR-9000\",\"qty\":2}" wait 1ms
    gw <- svc http version "1.1" status 201 reason "Created" content_type "application/json" header "X-Request-Id" "req-4092" body "{\"order_id\":8801,\"status\":\"confirmed\"}" wait 2ms

    // 2. Binary HTTP/2 connection preface -> SETTINGS -> Stream 1 request -> graceful GOAWAY drain
    gw -> svc http2 preface wait 1ms
    gw -> svc http2 settings stream_id 0 wait 1ms
    gw <- svc http2 settings stream_id 0 wait 1ms
    gw -> svc http2 headers stream_id 1 payload ":method GET :path /v2/inventory" wait 1ms
    gw <- svc http2 data stream_id 1 payload "{\"in_stock\":true}" wait 1ms
    gw <- svc http2 goaway stream_id 0 wait 2ms

    // 3. gRPC unary call and UNAVAILABLE (14) service-mesh failure on TCP 50051
    gw -> svc grpc service "inventory.v1.StockService" method "ReserveItems" payload "PROTOBUF_RESERVE_REQ" wait 1ms
    gw <- svc grpc service "inventory.v1.StockService" method "ReserveItems" grpc_status 14 payload "upstream_reset" wait 2ms

    // 4. RFC 6455 WebSocket XOR-masked client frame, server reply, PING/PONG, and CLOSE
    gw -> svc websocket text fin_bit 1 mask_key 0x37fa213d payload "{\"subscribe\":\"orders\"}" wait 1ms
    gw <- svc websocket opcode "TEXT" fin_bit 1 payload "{\"event\":\"SHIPPED\",\"id\":8801}" wait 1ms
    gw -> svc websocket ping fin_bit 1 mask_key 0x11223344 payload "hb" wait 1ms
    gw <- svc websocket pong fin_bit 1 payload "hb" wait 1ms
    gw -> svc websocket close fin_bit 1 mask_key 0x37fa213d hexpayload "03e8"
}

compile { web_and_microservice_tier(api_gw, app_svc) }
```

### 2. Test Firewall `TLS` 1.3 `SNI`/`ALPN` Filtering & UDP `443` `QUIC` Pinholes Without OpenSSL CAs
Next-gen firewalls and egress proxies inspect cleartext `ClientHello` `SNI` and `ALPN` extensions—and often block or throttle UDP `443` `QUIC` to force HTTP/3 clients back onto TCP. Verify both policies over IPv6 without generating a single X.509 certificate:

```frameassembly
host client_v6   { ip 2001:db8:443::50 }
host cdn_edge_v6 { ip 2001:db8:443::1 }

flow tls13_and_quic_audit(c, s) {
    // 1. Tracked TCP 443 handshake + TLS 1.3 SNI/ALPN negotiation + encrypted AppData + close_notify Alert
    c -> s tcp syn srcport 54443 dstport 443 win 65535 mss 1440 wscale 7 sack_perm wait 1ms
    c <- s tcp syn ack win 65535 mss 1440 wscale 7 sack_perm wait 1ms
    c -> s tcp ack wait 1ms
    c -> s tls client_hello record_version 0x0301 handshake_version 0x0303 sni "edge.cdn.example.com" ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls server_hello record_version 0x0303 handshake_version 0x0303 ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls certificate record_version 0x0303 payload "X509_ECDSA_CERT_CHAIN" wait 1ms
    c <- s tls finished record_version 0x0303 payload "SERVER_VERIFY" wait 1ms
    c -> s tls finished record_version 0x0303 payload "CLIENT_VERIFY" wait 1ms
    c -> s tls app_data record_version 0x0303 payload "ENCRYPTED_H2_GET" wait 1ms
    c -> s tls alert record_version 0x0303 wait 5ms

    // 2. QUIC v1 Initial -> Retry token challenge -> Initial -> 0-RTT -> Handshake -> 1-RTT Short Header
    c -> s quic initial version 1 dcid 0x8394c8f03e515708 scid 0x1122334455667788 pkt_num 1 payload "CRYPTO_CH" wait 1ms
    c <- s quic retry   version 1 dcid 0x1122334455667788 scid 0x9988776655443322 token "retry_tok_v1" wait 1ms
    c -> s quic initial version 1 dcid 0x9988776655443322 scid 0x1122334455667788 token "retry_tok_v1" pkt_num 2 payload "CRYPTO_CH_RETRY" wait 1ms
    c -> s quic zero_rtt version 1 dcid 0x9988776655443322 scid 0x1122334455667788 pkt_num 3 payload "H3_0RTT_GET" wait 1ms
    c <- s quic handshake version 1 dcid 0x1122334455667788 scid 0x9988776655443322 pkt_num 1 payload "CRYPTO_FIN" wait 1ms
    c <- s quic short dcid 0x1122334455667788 pkt_num 2 payload "H3_200_OK_DATA"
}

compile { tls13_and_quic_audit(client_v6, cdn_edge_v6) }
```

### 3. Trigger Legacy `Telnet`/`FTP` IDS Alerts, Bastion `SSH` Audits & `TFTP` ZTP Without `telnetd`
Every SOC claims to alert on cleartext `Telnet` logins, `FTP` passwords, and vulnerable `SSH` banners on management VLANs, yet nobody wants to enable `telnetd` or `vsftpd` on real switches just to test the sensor:

```frameassembly
host admin_ws    { ip 10.50.1.100 }
host core_switch { ip 10.50.1.1 }

flow remote_admin_and_ztp(ws, sw) {
    // 1. SSH-2 banner audit, KEXINIT cookie exchange, NEWKEYS, and encrypted channel payload
    ws -> sw ssh banner "SSH-2.0-OpenSSH_7.2p2" wait 1ms
    ws <- sw ssh banner "SSH-2.0-Cisco-2.0" wait 1ms
    ws -> sw ssh kexinit cookie "00112233445566778899aabbccddeeff" wait 1ms
    ws <- sw ssh kexinit cookie "ffeeddccbbaa99887766554433221100" wait 1ms
    ws -> sw ssh newkeys wait 1ms
    ws <- sw ssh newkeys wait 1ms
    ws -> sw ssh msg_code 94 payload "ENCRYPTED_SHOW_RUN" wait 2ms

    // 2. Cleartext Telnet IAC negotiation (Echo=1, SGA=3) and login prompt on TCP 23
    ws -> sw telnet do 1 will 3 wait 1ms
    ws <- sw telnet will 1 do 3 data "User Access Verification\r\nUsername: " wait 1ms
    ws -> sw telnet data "netadmin\r\n" wait 2ms

    // 3. Switch Zero-Touch Provisioning (ZTP) TFTP config pull on UDP 69
    ws -> sw tftp rrq filename "leaf01-startup.cfg" mode "octet" wait 1ms
    ws <- sw tftp data block 1 payload "hostname leaf01\ninterface Eth1/1\n" wait 1ms
    ws -> sw tftp ack block 1 wait 2ms

    // 4. Cleartext FTP login + Extended Passive Mode (EPSV 229) firewall helper check + WHOIS lookup
    ws <- sw ftp code 220 reply "Switch FTP Ready" wait 1ms
    ws -> sw ftp cmd "USER" arg "admin" wait 1ms
    ws <- sw ftp code 331 reply "Password required" wait 1ms
    ws -> sw ftp cmd "PASS" arg "SwitchPass!2026" wait 1ms
    ws <- sw ftp code 230 reply "User logged in" wait 1ms
    ws -> sw ftp cmd "EPSV" wait 1ms
    ws <- sw ftp code 229 reply "Entering Extended Passive Mode (|||62001|)" wait 2ms
    ws -> sw whois query domain "AS65001" wait 1ms
    ws <- sw whois response domain "AS65001" registrar "IANA Private Use ASN"
}

compile { remote_admin_and_ztp(admin_ws, core_switch) }
```

### 4. Debug Broken `SIP` ALGs, `DSCP EF` `RTP` Voice Queues, `RTSP` Cameras & Rogue `SSDP` UPnP
Troubleshooting one-way VoIP audio across NAT or firewall SIP ALGs usually means digging two desk phones out of a closet or fighting `sipp` XML templates. Build the entire `STUN` + `SIP` + `RTP` call flow, `RTSP` NVR camera setup, and `SSDP` multicast sweep in one flow:

```frameassembly
host voip_phone { ip 10.80.1.50 }
host sbc_media  { ip 10.80.1.10 }

flow voip_camera_and_upnp(phone, sbc) {
    // 1. STUN NAT binding discovery (XORs reflexive IP with magic cookie 0x2112A442)
    phone -> sbc stun binding_request txid 9001 software "Polycom-VVX/6.4" wait 1ms
    phone <- sbc stun binding_response txid 9001 xor_mapped_addr 203.0.113.50 software "Coturn-4.6" wait 2ms

    // 2. DSCP CS3 (24) SIP call setup + DSCP EF (46) G.711 PCMU RTP stream + SIP BYE
    phone -> sbc dscp 24 sip invite uri "sip:1002@pbx.example.com" from "sip:1001@pbx.example.com" to "sip:1002@pbx.example.com" call_id "call-7741@10.80.1.50" cseq 1 contact "sip:1001@10.80.1.50" content_type "application/sdp" body "v=0\r\nm=audio 5004 RTP/AVP 0\r\n" wait 2ms
    phone <- sbc dscp 24 sip status 200 reason "OK" call_id "call-7741@10.80.1.50" cseq 1 wait 2ms
    phone -> sbc dscp 24 sip ack uri "sip:1002@pbx.example.com" call_id "call-7741@10.80.1.50" cseq 1 wait 1ms
    phone -> sbc dscp 46 rtp pt 0 seq 1001 timestamp 160 ssrc 0x11223344 marker 1 payload "G711_PCMU_FRAME_1" wait 20ms
    phone <- sbc dscp 46 rtp pt 0 seq 5001 timestamp 160 ssrc 0x99887766 marker 1 payload "G711_PCMU_REPLY_1" wait 20ms
    phone -> sbc dscp 24 sip bye uri "sip:1002@pbx.example.com" call_id "call-7741@10.80.1.50" cseq 2 wait 2ms
    phone <- sbc dscp 24 sip status 200 reason "OK" call_id "call-7741@10.80.1.50" cseq 2 wait 5ms

    // 3. Security camera RTSP stream setup on TCP 554 (uses transport_hdr for RTP/AVP ports)
    phone -> sbc rtsp describe uri "rtsp://10.80.1.10:554/cam01/main" cseq 1 wait 1ms
    phone <- sbc rtsp status 200 cseq 1 wait 1ms
    phone -> sbc rtsp setup uri "rtsp://10.80.1.10:554/cam01/main/track1" cseq 2 transport_hdr "RTP/AVP;unicast;client_port=5004-5005" wait 1ms
    phone <- sbc rtsp status 200 cseq 2 session "cam-sess-991" wait 1ms
    phone -> sbc rtsp play uri "rtsp://10.80.1.10:554/cam01/main" cseq 3 session "cam-sess-991" wait 2ms
    phone -> sbc rtsp teardown uri "rtsp://10.80.1.10:554/cam01/main" cseq 4 session "cam-sess-991" wait 2ms

    // 4. SSDP UPnP multicast M-SEARCH and NOTIFY alive advertisement on UDP 1900
    phone -> sbc ssdp msearch host_hdr "239.255.255.250:1900" man "\"ssdp:discover\"" mx 3 st "urn:schemas-upnp-org:device:MediaServer:1" wait 1ms
    phone <- sbc ssdp notify  host_hdr "239.255.255.250:1900" nt "urn:schemas-upnp-org:device:MediaServer:1" nts "ssdp:alive" usn "uuid:media-01::upnp:rootdevice" location "http://10.80.1.10:8200/rootDesc.xml"
}

compile { voip_camera_and_upnp(voip_phone, sbc_media) }
```

## What FrameAssembly Handles for You

* **Shared 4-Tuple TCP State & Port Flipping:** Every TCP-based Layer 7 line (`http`, `http2`, `grpc`, `websocket`, `tls`, `ssh`, `telnet`, `ftp`, `whois`, `rtsp`, or `sip` with `transport tcp`) emits a `PSH ACK` segment, flips ports on `<-` replies, and advances TCP `SEQ`/`ACK` counters by the exact generated payload length.
* **Automatic `Content-Length` & Payload Masking:** Attaching `body "<text>"` to `http` or `sip` computes and inserts the exact `Content-Length` header automatically, while `websocket` XOR-masks payloads with `mask_key` per RFC 6455.
* **Zero-Math Binary Headers:** `http2` packs the 9-byte RFC 9113 frame header, `grpc` writes the 5-byte Protobuf length prefix, `tls` encodes 5-byte Record + 4-byte Handshake lengths plus `SNI`/`ALPN` extensions, `quic` encodes RFC 9000 variable-length payload integers, and `ssh` pads binary packets to 8-byte cipher boundaries.
* **Collision-Free Header Keywords:** Because `host` declares endpoints and `transport tcp|udp` switches Layer 4 protocols, `http`/`ssdp` use `host_hdr` for `Host:` and `rtsp` uses `transport_hdr` for `Transport:`.

## Web, Security, Remote Access & VoIP Reference

### 1. Web, APIs and Microservices (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`)

| Protocol | Operations / Frame Types | Modifiers | Wire Notes & Defaults |
| :--- | :--- | :--- | :--- |
| **`http`** | `get`, `post`, `put`, `delete`, `head`, `options`, `patch` (or `method "<verb>"`) | `uri "<path>"`, `version "<ver>"`, `host_hdr "<host>"`, `user_agent "<ua>"`, `content_type "<mime>"`, `header "<K>" "<V>"`, `status <100..599>`, `reason "<str>"`, `body "<str>"` | `TCP 80`; setting `status` emits a response, omitting it emits a request; `header` may be repeated |
| **`http2`** | `preface`, `settings` (default), `headers`, `data`, `window_update`, `ping`, `goaway` | `stream_id <u32>`, `payload "<str>"`, `hexpayload "<hex>"` | `TCP 443`; `preface` emits the 24B `PRI * HTTP/2.0...` string; `stream_id 0` = connection control, odd `1, 3, 5` = client streams |
| **`grpc`** | Unary / streaming RPC frame | `service "<pkg.Svc>"`, `method "<Rpc>"`, `grpc_status <0..16>`, `payload "<str>"` | `TCP 50051`; `grpc_status`: `0` OK, `3` INVALID_ARGUMENT, `4` DEADLINE_EXCEEDED, `7` PERMISSION_DENIED, `14` UNAVAILABLE, `16` UNAUTHENTICATED |
| **`websocket`**| `text` (default), `binary`, `ping`, `pong`, `close` (or `opcode "<name>"`) | `fin_bit <0\|1>`, `mask_key <u32>`, `payload "<str>"`, `hexpayload "<hex>"` | `TCP 80`; sets `MASK` bit (`0x80`) and XOR-masks payload bytes with 4-byte `mask_key` |

### 2. Transport Security and HTTP/3 (`TLS`, `QUIC`)

| Protocol | Packet / Record Types | Modifiers | Wire Notes & Defaults |
| :--- | :--- | :--- | :--- |
| **`tls`** | `client_hello` (default), `server_hello`, `certificate`, `finished`, `app_data`, `alert` | `record_version <u16>`, `handshake_version <u16>`, `sni "<host>"`, `ciphersuite <u16>`, `alpn "<proto>"`, `payload "<str>"` | `TCP 443`; `ciphersuite`: `4865` (`0x1301` AES_128_GCM), `4866` (`0x1302` AES_256_GCM), `4867` (`0x1303` CHACHA20); `alert` defaults to fatal `handshake_failure` (`[2, 40]`) |
| **`quic`** | `initial` (default), `zero_rtt`, `handshake`, `retry`, `short` | `version <u32>`, `dcid <u64>`, `scid <u64>`, `token "<str>"`, `pkt_num <u32>`, `payload "<str>"` | `UDP 443`; `version 1` = RFC 9000 QUIC v1, `0x6b3343cf` = RFC 9369 QUIC v2 |

### 3. Remote Access, File Transfer and WHOIS (`SSH`, `TELNET`, `TFTP`, `FTP`, `WHOIS`)

| Protocol | Sub-Keywords / Modes | Modifiers | Wire Notes & Defaults |
| :--- | :--- | :--- | :--- |
| **`ssh`** | Version banner (default), `kexinit`, `newkeys` | `banner "<str>"`, `msg_code <0..255>`, `cookie "<32hex_or_str>"`, `payload "<str>"` | `TCP 22`; `msg_code`: `20` KEXINIT, `21` NEWKEYS, `50` UserAuth Req, `90` Channel Open, `94` Channel Data |
| **`telnet`** | `will`, `wont`, `do`, `dont` | `[option] <0..255>`, `data "<str>"`, `payload "<str>"` | `TCP 23`; options: `0` Binary, `1` Echo, `3` Suppress Go Ahead, `24` TermType, `31` NAWS |
| **`tftp`** | `rrq` (default), `wrq`, `data`, `ack`, `error` (or `err`) | `filename "<str>"`, `mode "<octet\|netascii>"`, `block <u16>`, `errcode <u16>`, `errmsg "<str>"`, `payload "<str>"` | `UDP 69`; `errcode`: `1` File not found, `2` Access violation, `3` Disk full, `6` File exists |
| **`ftp`** | Client command or 3-digit reply | `cmd "<verb>"`, `arg "<str>"`, `code <100..599>`, `reply "<str>"` | `TCP 21`; `code`: `220` Ready, `331` Pass req, `230` Logged in, `227` PASV, `229` EPSV, `530` Login incorrect |
| **`whois`** | `query` (default), `response` | `domain "<str>"`, `registrar "<str>"`, `payload "<str>"` | `TCP 43`; `domain` accepts domains, IPv4/IPv6 prefixes, or ASNs (`"AS65001"`) |

### 4. VoIP, Streaming Media and UPnP (`SIP`, `RTP`, `RTSP`, `STUN`, `SSDP`)

| Protocol | Methods / Types | Modifiers | Wire Notes & Defaults |
| :--- | :--- | :--- | :--- |
| **`sip`** | `invite` (default), `ack`, `bye`, `cancel`, `register`, `options` (or `method "<verb>"`) | `uri "<sip>"`, `status <100..699>`, `reason "<str>"`, `from "<uri>"`, `to "<uri>"`, `call_id "<id>"`, `cseq <u32>`, `via "<str>"`, `contact "<uri>"`, `content_type "<mime>"`, `body "<sdp>"`, `transport tcp\|udp` | `UDP 5060` default (`TCP 5060` with `transport tcp`) |
| **`rtp`** | Media frame | `pt <0..127>`, `seq <u16>`, `timestamp <u32>`, `ssrc <u32>`, `marker <0\|1>`, `payload "<str>"`, `hexpayload "<hex>"` | `UDP 5004` (override via `srcport`/`dstport`); `pt`: `0` PCMU, `8` PCMA, `9` G.722, `18` G.729, `96..127` dynamic Opus/H.264 |
| **`rtsp`** | `options` (default), `describe`, `setup`, `play`, `teardown` (or `method "<verb>"`) | `uri "<url>"`, `status <100..599>`, `cseq <u32>`, `session "<id>"`, `transport_hdr "<spec>"` | `TCP 554`; always use `transport_hdr` for the RTSP `Transport:` header |
| **`stun`** | `binding_request` (default), `binding_response`, `binding_error` | `txid <u32>`, `xor_mapped_addr <ip>`, `software "<str>"` | `UDP 3478`; pass a plain IPv4 or IPv6 address to `xor_mapped_addr` (no `:port`) |
| **`ssdp`** | `msearch` (default), `notify` | `host_hdr "<ip:port>"`, `man "<str>"`, `mx <u8>`, `st "<target>"`, `nt "<type>"`, `nts "<sub_type>"`, `usn "<uuid>"`, `location "<url>"` | `UDP 1900`; `nts`: `"ssdp:alive"`, `"ssdp:byebye"`, `"ssdp:update"` |

## Inspecting and Replaying Web and VoIP Captures

```console
# Extract HTTP URIs, TLS SNI/ALPN extensions, and QUIC connection IDs in tshark
$ tshark -r tls13_and_quic_audit.pcap -T fields -e frame.number -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str -e quic.dcid

# Verify WAF / Suricata / Zeek detection logs offline
$ suricata -r waf_check.pcap -k none
$ zeek -C -r remote_admin_and_ztp.pcap

# Replay VoIP SIP + DSCP EF RTP streams across a lab SBC or QoS trunk
$ sudo tcpreplay -i eth0 voip_camera_and_upnp.pcap
```

## Related Documentation

* [**Getting Started (`getting_started.md`)**](getting_started.md) — Core `host` / `flow` / `compile` mechanics, stateful TCP, and `frameassembly show`.
* [**Real-World Use Cases (`use_cases.md`)**](use_cases.md) — Copy-paste recipes for WAF/IDS validation, firewall ACLs, and QoS queues.
* [**Layer 4 — Stateful TCP, UDP & Telecom SCTP (`l4_transports.md`)**](l4_transports.md) — Shared 4-tuple TCP `SEQ`/`ACK` tracking, `ZeroWindow` stalls, and RFC 7323 options.
* [**Layer 7 — Core Infrastructure, Time, AAA & Flow Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — Pair `http`, `tls`, and `ssh` flows with `dns`, `radius`, `tacacs`, `syslog`, and `ipfix`.
* [**Layer 7 — Mail, Auth, Storage, Databases & Message Brokers (`l7_mail_auth_storage_db.md`)**](l7_mail_auth_storage_db.md) — `smtp`, `kerberos`, `ldap`, `smb`, `redis`, `postgres`, `mqtt`, `coap`, and `amqp`.
* [**Topologies & Dual-Stack (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — End-to-end IPv4/IPv6 Kubernetes service-mesh (`dns` + `tcp` + `tls` + `grpc` + `redis` + `postgres`) captures.