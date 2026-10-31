# Layer 7 Web, Cloud-Native, Transport Security, VoIP & Remote Access Reference

Whether you need an **HTTP/1.1, HTTP/2, gRPC, or WebSocket API test capture**, a **TLS 1.3 SNI/ALPN & QUIC / HTTP/3 firewall inspection pcap**, an **SSH / Telnet / TFTP / FTP / WHOIS remote administration capture**, or a **SIP / RTP / RTSP / STUN / SSDP VoIP & media stream packet generator**, this guide covers **16 Layer 7 application protocols** across IPv4 and IPv6:
**`HTTP`**, **`HTTP2`**, **`GRPC`**, **`WEBSOCKET`**, **`TLS`**, **`QUIC`**, **`TFTP`**, **`FTP`**, **`SSH`**, **`TELNET`**, **`WHOIS`**, **`SIP`**, **`RTP`**, **`RTSP`**, **`STUN`**, and **`SSDP`**.

> **Looking for IoT & Message Broker protocols (`MQTT`, `COAP`, `AMQP`)?**
> Those three protocols are documented in [**Layer 7 Mail, Directory, Storage, Databases & Message Brokers (`l7_mail_auth_storage_db.md`)**](l7_mail_auth_storage_db.md#5-message-brokers--iot-telemetry-mqtt-coap-amqp).

---

## Quick Protocol & Default Port Matrix

Every protocol below works with **zero mandatory modifiers** (emitting a complete, RFC-compliant default frame on its standard port) or with explicit header overrides.

| Protocol | Keyword | Default Transport & Port | Standard / RFC | Common Network & Security Testing Use Cases |
| :--- | :--- | :--- | :--- | :--- |
| **HTTP/1.1** | `HTTP` | TCP `80` | RFC 9110 / RFC 9112 | WAF rule validation, reverse-proxy routing, REST API health checks |
| **HTTP/2** | `HTTP2` | TCP `443` | RFC 9113 / RFC 7541 | Multiplexed stream inspection, `GOAWAY` graceful drain, `SETTINGS` tuning |
| **gRPC** | `GRPC` | TCP `50051` | gRPC over HTTP/2 | Kubernetes service-mesh telemetry, Protobuf RPC status code testing |
| **WebSocket** | `WEBSOCKET` | TCP `80` | RFC 6455 | Full-duplex masked client frames, `PING`/`PONG` keepalives, proxy upgrades |
| **TLS 1.2 / 1.3** | `TLS` | TCP `443` | RFC 8446 / RFC 6066 | Firewall SNI/ALPN filtering, cipher-suite policy audits, TLS alert handling |
| **QUIC / HTTP/3** | `QUIC` | UDP `443` | RFC 9000 / RFC 9114 | UDP `443` firewall pinholes, Connection ID migration, Retry token validation |
| **SSH-2** | `SSH` | TCP `22` | RFC 4253 / RFC 4252 | Bastion access ACLs, SSH version banner audits, `KEXINIT` algorithm inspection |
| **Telnet** | `TELNET` | TCP `23` | RFC 854 / RFC 855 | Legacy out-of-band console detection, IDS cleartext management alerts |
| **TFTP** | `TFTP` | UDP `69` | RFC 1350 | PXE network boot, switch Zero-Touch Provisioning (ZTP), firmware transfers |
| **FTP** | `FTP` | TCP `21` | RFC 959 / RFC 2428 | Firewall FTP ALG / passive helper testing, cleartext credential detection |
| **WHOIS** | `WHOIS` | TCP `43` | RFC 3912 | SOC domain/IP enrichment lookups, RIR/registrar query simulation |
| **SIP** | `SIP` | UDP / TCP `5060` | RFC 3261 / RFC 4566 | VoIP Session Border Controller (SBC) call setup, SIP ALG inspection |
| **RTP** | `RTP` | UDP `5004` | RFC 3550 / RFC 3551 | DSCP `EF` (`46`) voice/video QoS queue verification, jitter/sequence tests |
| **RTSP** | `RTSP` | TCP `554` | RFC 7826 / RFC 2326 | IP security camera NVR streams, media transport port negotiation |
| **STUN** | `STUN` | UDP `3478` | RFC 8489 / RFC 5389 | WebRTC ICE NAT traversal, `XOR-MAPPED-ADDRESS` reflexive IP discovery |
| **SSDP / UPnP** | `SSDP` | UDP `1900` | UPnP DA 1.1 / 2.0 | Multicast IoT/printer discovery (`239.255.255.250`), rogue UPnP auditing |

> **Shared 4-Tuple TCP State & Port Overrides:**
> All TCP-based Layer 7 statements automatically emit a `PSH ACK` segment on that protocol's default port and share sequence/acknowledgment numbers (`SEQ`/`ACKNUM`) with raw `TCP` statements between the same two hosts and ports. You can override source or destination ports on any statement using `srcport <0..65535>` and `dstport <0..65535>`, or add Layer 2/Layer 3 tags (`vlan <id>`, `qinq <s_vid> inner_vlan <c_vid>`, `mpls <label>`, `dscp <0..63>`, `ttl <0..255>`) anywhere on the line.

---

## 1. Web, API & Microservice Protocols (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`)

### 1.1 HTTP/1.1 (`HTTP` — Default: TCP Port `80`)

Need an **HTTP/1.1 `GET`/`POST` request & `200`/`404`/`503` response pcap** for WAF rule testing, reverse-proxy validation, or REST API health checks? `HTTP` builds CRLF-delimited RFC 9112 HTTP/1.1 request and response messages:
- **Request vs. Response:** If `STATUS` (or `REASON`) is specified, FrameAssembly emits an HTTP response (`HTTP/1.1 <status> <reason>\r\n...`). Otherwise, it emits an HTTP request (`<method> <uri> HTTP/<version>\r\n...`).
- **Automatic `Content-Length`:** Whenever you include `BODY "<text>"`, FrameAssembly automatically computes the exact byte length of the body and appends a matching `Content-Length: <n>\r\n` header before the blank `\r\n\r\n` separator.
- **Why `HOST_HDR` instead of `HOST`?** In FrameAssembly, `HOST` is a top-level keyword used to declare network endpoints (`host web_srv { ip 10.0.0.10 }`). Using `HOST_HDR "<hostname>"` for the HTTP `Host:` header prevents any ambiguity between endpoint declarations and HTTP headers.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Verb** | `GET` \| `POST` \| `PUT` \| `DELETE` \| `HEAD` \| `OPTIONS` \| `PATCH` | `GET` | Standalone keyword setting the HTTP request method |
| **`METHOD`** | `METHOD "<verb>"` | `"GET"` | Explicit HTTP method string (e.g., `"POST"`, `"PROPFIND"`, `"TRACE"`) |
| **`URI`** | `URI "<path>"` | `"/"` | Request target path or query string (e.g., `"/api/v1/orders?limit=10"`) |
| **`VERSION`** | `VERSION "<ver>"` | `"1.1"` | HTTP protocol version string (`"1.1"` or `"1.0"`) |
| **`HOST_HDR`** | `HOST_HDR "<host>"` | `"localhost"` | Sets the HTTP `Host:` header (never write `HOST` inside an `HTTP` statement) |
| **`USER_AGENT`** | `USER_AGENT "<ua>"` | Omitted | Appends `User-Agent: <ua>\r\n` |
| **`CONTENT_TYPE`** | `CONTENT_TYPE "<mime>"` | Omitted | Appends `Content-Type: <mime>\r\n` (e.g., `"application/json"`) |
| **`HEADER`** | `HEADER "<Key>" "<Val>"` | None | Appends a custom `Key: Val\r\n` header; may be repeated multiple times |
| **`STATUS`** | `STATUS <100..599>` | `200` (if response) | Switches frame to an HTTP response with the given status code (`200`, `404`, `503`) |
| **`REASON`** | `REASON "<phrase>"` | Auto-derived | Response reason phrase (`"OK"`, `"Created"`, `"Forbidden"`) |
| **`BODY`** | `BODY "<text>"` | Empty | Appends message body and automatically adds `Content-Length: <len>` |

### 1.2 HTTP/2 (`HTTP2` — Default: TCP Port `443`)

Need an **HTTP/2 connection preface, `SETTINGS`, `HEADERS`, `DATA` & `GOAWAY` stream pcap** for ALPN/proxy inspection? `HTTP2` builds RFC 9113 binary HTTP/2 frames (9-byte header: 24-bit length, 8-bit frame type, 8-bit flags, 1-bit reserved bit, and 31-bit stream ID) and the optional 24-byte client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`). Multiple frame type flags can be combined in a single packet (such as `preface settings`).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`PREFACE`** | `PREFACE` | Off | Prepends the 24-byte RFC 9113 client connection preface string |
| **`SETTINGS`** | `SETTINGS` | Default if none set | Emits Frame Type `0x04` (`SETTINGS`, 6-byte parameter entry) |
| **`HEADERS`** | `HEADERS` | Off | Emits Frame Type `0x01` (`HEADERS` with `END_HEADERS = 0x04`) |
| **`DATA`** | `DATA` | Off | Emits Frame Type `0x00` (`DATA` with `END_STREAM = 0x01`) |
| **`WINDOW_UPDATE`** | `WINDOW_UPDATE` | Off | Emits Frame Type `0x08` (`WINDOW_UPDATE`, 4-byte window increment) |
| **`PING`** | `PING` | Off | Emits Frame Type `0x06` (`PING`, 8-byte opaque payload) |
| **`GOAWAY`** | `GOAWAY` | Off | Emits Frame Type `0x07` (`GOAWAY`, last stream ID + error code) |
| **`STREAM_ID`** | `STREAM_ID <number>` | `0` or `1` | 31-bit HTTP/2 Stream ID (`0` for connection control, odd `1, 3, 5` for client streams) |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Default per type | Custom frame payload bytes |

### 1.3 gRPC (`GRPC` — Default: TCP Port `50051`)

Need a **gRPC over HTTP/2 TCP 50051 unary RPC & `grpc-status` trailer pcap** for Kubernetes service-mesh or Envoy proxy testing? `GRPC` builds HTTP/2 frames carrying `/package.Service/Method` call paths, 5-byte length-prefixed Protocol Buffers envelopes (1-byte compression flag `0x00` + 32-bit big-endian message length), and `grpc-status` trailer codes.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`SERVICE`** | `SERVICE "<pkg.Svc>"` | `"grpc.health.v1.Health"` | Fully qualified Protobuf service name |
| **`METHOD`** | `METHOD "<Rpc>"` | `"Check"` | Target RPC method name (combined on wire as `/<SERVICE>/<METHOD>`) |
| **`GRPC_STATUS`** | `GRPC_STATUS <0..16>` | Omitted (Request) | Emits a gRPC response trailer (`0` `OK`, `1` `CANCELLED`, `3` `INVALID_ARGUMENT`, `4` `DEADLINE_EXCEEDED`, `5` `NOT_FOUND`, `7` `PERMISSION_DENIED`, `14` `UNAVAILABLE`, `16` `UNAUTHENTICATED`) |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Serialized Protobuf message body wrapped in the 5-byte gRPC length prefix |

### 1.4 WebSocket (`WEBSOCKET` — Default: TCP Port `80`)

Need a **WebSocket RFC 6455 masked client frame, `PING`/`PONG` keepalive & `CLOSE` pcap**? `WEBSOCKET` builds binary WebSocket frames with configurable opcodes, `FIN` bit fragmentation control, and automatic 32-bit XOR client masking when `MASK_KEY` is provided.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Opcode** | `TEXT` \| `BINARY` \| `CLOSE` \| `PING` \| `PONG` | `TEXT` | Bare keyword setting the 4-bit WebSocket opcode (`0x1`, `0x2`, `0x8`, `0x9`, `0xA`) |
| **`OPCODE`** | `OPCODE "<name>"` | `"TEXT"` | Explicit opcode name (`"TEXT"`, `"BINARY"`, `"CLOSE"`, `"PING"`, `"PONG"`, `"CONTINUATION"`) |
| **`FIN_BIT`** | `FIN_BIT <0\|1>` | `1` | `1` = final fragment in message; `0` = more fragments follow |
| **`MASK_KEY`** | `MASK_KEY <32-bit_hex>` | Unmasked | Sets the `MASK` bit (`0x80`), writes the 4-byte key, and XOR-masks the payload on the wire |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | `"Hello WebSocket"` | Application text or binary payload (automatically XOR-masked if `MASK_KEY` is set) |

### Compilable Example: Web API Gateway, HTTP/2, gRPC & WebSocket Stream

```frameassembly
host api_gateway { ip 10.120.1.10 mac 00:1b:21:10:01:0a }
host app_service { ip 10.120.1.50 mac 00:1b:21:10:01:32 }

flow web_and_microservice_tier(gw, svc) {
    // 1. HTTP/1.1 POST request with custom headers and JSON body + 201 Created response
    gw -> svc http post uri "/v1/orders" version "1.1" host_hdr "api.corp.example.com" user_agent "Envoy/1.31" content_type "application/json" header "X-Request-Id" "req-4092" header "X-Forwarded-Proto" "https" body "{\"sku\":\"RTR-9000\",\"qty\":2}" wait 1ms
    gw <- svc http version "1.1" status 201 reason "Created" content_type "application/json" header "X-Request-Id" "req-4092" body "{\"order_id\":8801,\"status\":\"confirmed\"}" wait 2ms

    // 2. HTTP/2 connection preface, settings exchange, stream 1 request, and graceful GOAWAY
    gw -> svc http2 preface settings stream_id 0 wait 1ms
    gw <- svc http2 settings window_update stream_id 0 wait 1ms
    gw -> svc http2 headers stream_id 1 payload ":method GET :path /v2/inventory" wait 1ms
    gw <- svc http2 data stream_id 1 payload "{\"in_stock\":true}" wait 1ms
    gw -> svc http2 ping stream_id 0 wait 1ms
    gw <- svc http2 goaway stream_id 0 wait 2ms

    // 3. gRPC unary RPC call and OK response on TCP 50051
    gw -> svc grpc service "inventory.v1.StockService" method "ReserveItems" payload "PROTOBUF_RESERVE_REQ" wait 1ms
    gw <- svc grpc service "inventory.v1.StockService" method "ReserveItems" grpc_status 0 payload "PROTOBUF_RESERVE_OK" wait 2ms

    // 4. WebSocket client-masked TEXT frame, server unmasked reply, PING/PONG, and CLOSE
    gw -> svc websocket text fin_bit 1 mask_key 0x37fa213d payload "{\"subscribe\":\"order_events\"}" wait 1ms
    gw <- svc websocket opcode "TEXT" fin_bit 1 payload "{\"event\":\"ORDER_SHIPPED\",\"id\":8801}" wait 1ms
    gw -> svc websocket ping fin_bit 1 mask_key 0x11223344 payload "hb" wait 1ms
    gw <- svc websocket pong fin_bit 1 payload "hb" wait 1ms
    gw -> svc websocket close fin_bit 1 mask_key 0x37fa213d payload ""
}

compile {
    web_and_microservice_tier(api_gateway, app_service)
}
```

---

## 2. Transport Security & Next-Gen Web (`TLS`, `QUIC`)

### 2.1 Transport Layer Security (`TLS` — Default: TCP Port `443`)

Need a **TLS 1.2 / TLS 1.3 `ClientHello` SNI & ALPN firewall inspection pcap**? `TLS` builds RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3) 5-byte Record Layer headers (`ContentType`, `RecordVersion`, `Length`) and Handshake messages (`ClientHello`, `ServerHello`, `Certificate`, `Finished`) complete with RFC 6066 Server Name Indication (`SNI`) and RFC 7301 Application-Layer Protocol Negotiation (`ALPN`) extensions.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`CLIENT_HELLO`** | `CLIENT_HELLO` | Default if none set | Handshake Type `1` (`ClientHello`) with 32-byte random, cipher suite, SNI, and ALPN |
| **`SERVER_HELLO`** | `SERVER_HELLO` | Off | Handshake Type `2` (`ServerHello`) selecting cipher suite and ALPN |
| **`CERTIFICATE`** | `CERTIFICATE` | Off | Handshake Type `11` (`Certificate`) carrying X.509 certificate payload |
| **`FINISHED`** | `FINISHED` | Off | Handshake Type `20` (`Finished`) carrying handshake verify data |
| **`APP_DATA`** | `APP_DATA` | Off | Record ContentType `23` (`ApplicationData`) carrying encrypted record bytes |
| **`ALERT`** | `ALERT` | Off | Record ContentType `21` (`Alert`, e.g., `close_notify` or `handshake_failure`) |
| **`RECORD_VERSION`** | `RECORD_VERSION <0..65535>` | `0x0303` | Outer 16-bit TLS record version (`0x0301` = TLS 1.0, `0x0303` = TLS 1.2) |
| **`HANDSHAKE_VERSION`**| `HANDSHAKE_VERSION <0..65535>`| `0x0303` | Inner 16-bit handshake client/server version (`0x0303` = TLS 1.2 / TLS 1.3 legacy) |
| **`SNI`** | `SNI "<hostname>"` | Omitted | Encodes TLS Extension `0x0000` (`server_name`) for firewall SNI inspection |
| **`CIPHERSUITE`** | `CIPHERSUITE <0..65535>` | `0x1301` (`4865`) | 16-bit IANA Cipher Suite (`4865`/`0x1301` = `TLS_AES_128_GCM_SHA256`, `4866`/`0x1302` = `TLS_AES_256_GCM_SHA384`, `4867`/`0x1303` = `TLS_CHACHA20_POLY1305_SHA256`) |
| **`ALPN`** | `ALPN "<proto>"` | Omitted | Encodes TLS Extension `0x0010` (`"h2"`, `"http/1.1"`, `"grpc-exp"`) |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Default per type | Custom certificate, verify data, alert, or encrypted application payload |

### 2.2 QUIC & HTTP/3 Transport (`QUIC` — Default: UDP Port `443`)

Need a **QUIC v1 / HTTP/3 UDP 443 `Initial`, `Retry`, `0-RTT`, `Handshake` & `Short` header pcap** for next-gen firewall testing? `QUIC` builds RFC 9000 QUIC Long Header packets (`INITIAL`, `ZERO_RTT`, `HANDSHAKE`, `RETRY`) with RFC 9000 §16 2-byte variable-length integer payload lengths and 1-RTT `SHORT` Header packets over UDP port `443`.
- **Important Syntax Note on `DCID` and `SCID`:** Destination and Source Connection IDs (`DCID` and `SCID`) take **unquoted 64-bit integer or hexadecimal values** (for example `dcid 0x8394c8f03e515708`), never quoted strings.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`INITIAL`** | `INITIAL` | Default if none set | Long Header Type `0x00` (`Initial`, carries Token length + Token + Packet Number) |
| **`ZERO_RTT`** | `ZERO_RTT` | Off | Long Header Type `0x01` (`0-RTT` early data packet) |
| **`HANDSHAKE`** | `HANDSHAKE` | Off | Long Header Type `0x02` (`Handshake` cryptographic exchange) |
| **`RETRY`** | `RETRY` | Off | Long Header Type `0x03` (`Retry` address validation packet) |
| **`SHORT`** | `SHORT` | Off | 1-RTT Short Header (`Header Form = 0`, `Fixed Bit = 1`, `DCID` + `PKT_NUM`) |
| **`VERSION`** | `VERSION <number>` | `1` (`0x00000001`) | 32-bit QUIC version (`1` = RFC 9000 QUIC v1, `0x6b3343cf` = RFC 9369 QUIC v2) |
| **`DCID`** | `DCID <64-bit_id>` | `0x0102030405060708` | 64-bit Destination Connection ID (unquoted integer or `0x...` hex value) |
| **`SCID`** | `SCID <64-bit_id>` | `0x1112131415161718` | 64-bit Source Connection ID (unquoted integer or `0x...` hex value) |
| **`TOKEN`** | `TOKEN "<text>"` | Empty | Address validation token string included in `INITIAL` or `RETRY` packets |
| **`PKT_NUM`** | `PKT_NUM <number>` | `1` | Packet number encoded into `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, or `SHORT` headers |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Default per type | Encrypted QUIC frames / HTTP/3 payload bytes |

### Compilable Example: TLS 1.3 Inspection & QUIC v1 / HTTP/3 Handshake over IPv6

```frameassembly
host client_v6   { ip 2001:db8:443::50 }
host cdn_edge_v6 { ip 2001:db8:443::1 }

flow tls13_and_quic_v1(c, s) {
    // 1. TLS 1.3 handshake with SNI and ALPN "h2", encrypted AppData, and close_notify Alert
    c -> s tls client_hello record_version 0x0301 handshake_version 0x0303 sni "edge.cdn.example.com" ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls server_hello record_version 0x0303 handshake_version 0x0303 ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls certificate record_version 0x0303 payload "X509_ECDSA_CERT_CHAIN" wait 1ms
    c <- s tls finished record_version 0x0303 payload "SERVER_HANDSHAKE_VERIFY" wait 1ms
    c -> s tls finished record_version 0x0303 payload "CLIENT_HANDSHAKE_VERIFY" wait 1ms
    c -> s tls app_data record_version 0x0303 payload "ENCRYPTED_HTTP2_GET_REQUEST" wait 1ms
    c <- s tls app_data record_version 0x0303 payload "ENCRYPTED_HTTP2_200_RESPONSE" wait 1ms
    c -> s tls alert record_version 0x0303 payload "CLOSE_NOTIFY" wait 5ms

    // 2. QUIC v1 Initial -> Retry with token -> Initial -> 0-RTT -> Handshake -> 1-RTT Short Header
    c -> s quic initial version 1 dcid 0x8394c8f03e515708 scid 0x1122334455667788 pkt_num 1 payload "CRYPTO_CLIENT_HELLO" wait 1ms
    c <- s quic retry version 1 dcid 0x1122334455667788 scid 0x9988776655443322 token "quic_retry_tok_v1" wait 1ms
    c -> s quic initial version 1 dcid 0x9988776655443322 scid 0x1122334455667788 token "quic_retry_tok_v1" pkt_num 2 payload "CRYPTO_CLIENT_HELLO_RETRY" wait 1ms
    c -> s quic zero_rtt version 1 dcid 0x9988776655443322 scid 0x1122334455667788 pkt_num 3 payload "HTTP3_0RTT_GET_INDEX" wait 1ms
    c <- s quic handshake version 1 dcid 0x1122334455667788 scid 0x9988776655443322 pkt_num 1 payload "CRYPTO_SERVER_FINISHED" wait 1ms
    c <- s quic short dcid 0x1122334455667788 pkt_num 2 payload "HTTP3_200_OK_HEADERS_AND_DATA"
}

compile {
    tls13_and_quic_v1(client_v6, cdn_edge_v6)
}
```

---

## 3. Remote Access, File Transfer & Domain Lookup (`SSH`, `TELNET`, `TFTP`, `FTP`, `WHOIS`)

### 3.1 Secure Shell (`SSH` — Default: TCP Port `22`)

Need an **SSH-2 TCP 22 version banner, `KEXINIT` algorithm negotiation & `NEWKEYS` pcap** for bastion ACL or IDS testing? `SSH` builds RFC 4253 version banners (`SSH-2.0-...`) and binary SSH packet framing (`packet_length`, `padding_length`, `msg_code`, 16-byte `KEXINIT` cookie + algorithm negotiation lists, `NEWKEYS`, and encrypted channel payloads).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`BANNER`** | `BANNER "<text>"` | `"SSH-2.0-OpenSSH_9.3"` | Emits CRLF-terminated version exchange string (`SSH-2.0-...\r\n`) |
| **`KEXINIT`** | `KEXINIT` | Off | Emits `SSH_MSG_KEXINIT` (`msg_code = 20`) with 16-byte cookie and kex algorithm lists |
| **`NEWKEYS`** | `NEWKEYS` | Off | Emits `SSH_MSG_NEWKEYS` (`msg_code = 21`) signaling transition to encrypted keys |
| **`MSG_CODE`** | `MSG_CODE <0..255>` | `20` (if binary) | Explicit SSH message code (`5` Service Req, `50` UserAuth Req, `52` UserAuth Success, `90` Channel Open, `94` Channel Data) |
| **`COOKIE`** | `COOKIE "<hex_or_text>"` | 16-byte default | Custom 16-byte KEXINIT cookie value |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Additional SSH binary packet body or encrypted channel data |

### 3.2 Telnet (`TELNET` — Default: TCP Port `23`)

Need a **Telnet TCP 23 `IAC` option negotiation & cleartext management alert pcap**? `TELNET` builds RFC 854 Interpret As Command (`IAC = 0xFF`) option negotiation sequences (`WILL = 0xFB`, `WONT = 0xFC`, `DO = 0xFD`, `DONT = 0xFE`) and NVT-ASCII terminal lines.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`WILL`** | `WILL [OPTION] <0..255>` | Omitted | Emits 3-byte `0xFF 0xFB <opt>` (`1` Echo, `3` Suppress Go Ahead, `24` TermType, `31` NAWS) |
| **`WONT`** | `WONT [OPTION] <0..255>` | Omitted | Emits 3-byte `0xFF 0xFC <opt>` refusing to perform option |
| **`DO`** | `DO [OPTION] <0..255>` | Omitted | Emits 3-byte `0xFF 0xFD <opt>` requesting peer to enable option |
| **`DONT`** | `DONT [OPTION] <0..255>` | Omitted | Emits 3-byte `0xFF 0xFE <opt>` requesting peer to disable option |
| **`OPTION`** | `OPTION <0..255>` | Omitted | Standalone option code when no negotiation verb is specified |
| **`DATA`** | `DATA "<text>"` | Omitted | Terminal text line or CLI command string (appended after any IAC bytes) |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Omitted | Additional raw terminal bytes |

### 3.3 Trivial File Transfer Protocol (`TFTP` — Default: UDP Port `69`)

Need a **TFTP UDP 69 PXE network boot or switch Zero-Touch Provisioning (`ZTP`) `RRQ`/`WRQ`/`DATA`/`ACK`/`ERROR` pcap**? `TFTP` builds RFC 1350 UDP file transfer packets used for PXE bootloaders, switch/router ZTP, and VoIP phone configuration downloads.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`RRQ`** | `RRQ` | Default if none set | Opcode `1` (Read Request: `0x0001` + `FILENAME` + `0x00` + `MODE` + `0x00`) |
| **`WRQ`** | `WRQ` | Off | Opcode `2` (Write Request: `0x0002` + `FILENAME` + `0x00` + `MODE` + `0x00`) |
| **`DATA`** | `DATA` | Off | Opcode `3` (Data block: `0x0003` + 16-bit `BLOCK` + `PAYLOAD` bytes) |
| **`ACK`** | `ACK` | Off | Opcode `4` (Acknowledgment: `0x0004` + 16-bit `BLOCK`) |
| **`ERROR`** | `ERROR` (or `ERR`) | Auto if `ERRCODE` set | Opcode `5` (Error: `0x0005` + 16-bit `ERRCODE` + `ERRMSG` + `0x00`) |
| **`FILENAME`** | `FILENAME "<text>"` | `"boot.bin"` | Target filename for `RRQ` and `WRQ` packets |
| **`MODE`** | `MODE "<text>"` | `"octet"` | Transfer mode string (`"octet"` for binary or `"netascii"` for text) |
| **`BLOCK`** | `BLOCK <0..65535>` | `1` | 16-bit block counter for `DATA` and `ACK` (`0` acknowledges a `WRQ`) |
| **`ERRCODE`** | `ERRCODE <0..65535>` | `1` | TFTP error code (`1` File not found, `2` Access violation, `3` Disk full, `4` Illegal op, `6` File exists) |
| **`ERRMSG`** | `ERRMSG "<text>"` | `"File not found"` | Human-readable NUL-terminated error string |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Block data content for `DATA` frames |

### 3.4 File Transfer Protocol (`FTP` — Default: TCP Port `21`)

Need an **FTP TCP 21 control-channel login & `PASV`/`EPSV` firewall ALG helper pcap**? `FTP` builds RFC 959 / RFC 2428 control-channel commands and 3-digit server status replies (`<CODE> <REPLY>\r\n` or `<CMD> <ARG>\r\n`).

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`CMD`** | `CMD "<verb>"` | `"USER"` | FTP client command (`"USER"`, `"PASS"`, `"SYST"`, `"FEAT"`, `"PWD"`, `"TYPE"`, `"PASV"`, `"EPSV"`, `"RETR"`, `"STOR"`, `"QUIT"`) |
| **`ARG`** | `ARG "<text>"` | Omitted | Command argument (e.g., `"anonymous"`, `"I"`, `"/pub/firmware.bin"`) |
| **`CODE`** | `CODE <100..599>` | Omitted (Command) | Emits a 3-digit FTP server response (`220` Ready, `331` Password required, `230` Logged in, `227` Passive Mode, `229` Extended Passive, `150` Opening data, `226` Transfer complete, `530` Login incorrect) |
| **`REPLY`** | `REPLY "<text>"` | `"OK"` | Server response text following `CODE` |

### 3.5 WHOIS Registry Lookup (`WHOIS` — Default: TCP Port `43`)

Need a **WHOIS TCP 43 domain, IP prefix, or ASN registry lookup pcap** for SOC enrichment testing? `WHOIS` builds RFC 3912 domain, IPv4/IPv6 CIDR prefix, and Autonomous System Number (ASN) queries and registry responses.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`QUERY`** | `QUERY` | Default if no `REGISTRAR` | Emits `<DOMAIN>\r\n` client query on TCP port 43 |
| **`RESPONSE`** | `RESPONSE` | Auto if `REGISTRAR` set | Emits formatted multi-line WHOIS registry record (`Domain Name:`, `Registrar:`) |
| **`DOMAIN`** | `DOMAIN "<text>"` | `"example.com"` | Queried domain name, IP prefix, or ASN |
| **`REGISTRAR`** | `REGISTRAR "<text>"` | `"IANA"` | Sponsoring registrar name included in `RESPONSE` records |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | Additional WHOIS response lines (e.g., `Name Server:` or `NetRange:` fields) |

### Compilable Example: Bastion SSH/Telnet Access, Switch ZTP TFTP/FTP & WHOIS Audit

```frameassembly
host admin_ws    { ip 10.50.1.100 }
host core_switch { ip 10.50.1.1 }

flow remote_admin_and_provisioning(ws, sw) {
    // 1. SSH-2 version banner exchange, KEXINIT with cookie, NEWKEYS, and encrypted channel data
    ws -> sw ssh banner "SSH-2.0-OpenSSH_9.6" wait 1ms
    sw -> ws ssh banner "SSH-2.0-Cisco-2.0" wait 1ms
    ws -> sw ssh kexinit cookie "00112233445566778899aabbccddeeff" wait 1ms
    sw -> ws ssh kexinit cookie "ffeeddccbbaa99887766554433221100" wait 1ms
    ws -> sw ssh newkeys wait 1ms
    sw -> ws ssh newkeys wait 1ms
    ws -> sw ssh msg_code 94 payload "ENCRYPTED_SHOW_RUNNING_CONFIG" wait 2ms

    // 2. Legacy Telnet IAC option negotiation (Echo=1, SGA=3) and CLI prompt
    ws -> sw telnet do 1 will 3 wait 1ms
    sw -> ws telnet will 1 do 3 data "User Access Verification\r\nUsername: " wait 1ms
    ws -> sw telnet data "netadmin\r\n" wait 2ms

    // 3. TFTP switch configuration download (RRQ -> DATA Block 1 -> ACK Block 1)
    sw -> ws tftp rrq filename "leaf01-startup.cfg" mode "octet" wait 1ms
    ws -> sw tftp data block 1 payload "hostname leaf01\ninterface Eth1/1\n" wait 1ms
    sw -> ws tftp ack block 1 wait 2ms

    // 4. FTP firmware archive login and passive mode retrieval
    ws <- sw ftp code 220 reply "Switch FTP Server Ready" wait 1ms
    ws -> sw ftp cmd "USER" arg "admin" wait 1ms
    ws <- sw ftp code 331 reply "Password required for admin" wait 1ms
    ws -> sw ftp cmd "PASS" arg "SwitchPass!2026" wait 1ms
    ws <- sw ftp code 230 reply "User admin logged in" wait 1ms
    ws -> sw ftp cmd "EPSV" wait 1ms
    ws <- sw ftp code 229 reply "Entering Extended Passive Mode (|||62001|)" wait 1ms
    ws -> sw ftp cmd "RETR" arg "nos-v10.4.bin" wait 1ms
    ws <- sw ftp code 226 reply "Transfer complete" wait 2ms

    // 5. WHOIS domain registration lookup and response
    ws -> sw whois query domain "corp-network.example.net" wait 1ms
    ws <- sw whois response domain "corp-network.example.net" registrar "Example Enterprise Registrar LLC"
}

compile {
    remote_admin_and_provisioning(admin_ws, core_switch)
}
```

---

## 4. VoIP, Streaming Media, NAT Traversal & UPnP (`SIP`, `RTP`, `RTSP`, `STUN`, `SSDP`)

### 4.1 Session Initiation Protocol (`SIP` — Default: UDP / TCP Port `5060`)

Need a **SIP UDP/TCP 5060 `INVITE` / `100 Trying` / `180 Ringing` / `200 OK` / `ACK` / `BYE` VoIP call setup & SBC ALG pcap**? `SIP` builds RFC 3261 VoIP call control signaling and status responses with automatic `Content-Length` calculation when an SDP `BODY` is attached.
- **UDP vs. TCP Transport:** `SIP` defaults to UDP port `5060`. Add `transport tcp` on the statement to emit SIP over TCP port `5060`.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Method** | `INVITE` \| `ACK` \| `BYE` \| `CANCEL` \| `REGISTER` \| `OPTIONS` | `INVITE` | Standalone keyword setting the SIP request method |
| **`METHOD`** | `METHOD "<verb>"` | `"INVITE"` | Explicit SIP method string (e.g., `"PRACK"`, `"SUBSCRIBE"`, `"NOTIFY"`, `"REFER"`) |
| **`URI`** | `URI "<sip_uri>"` | `"sip:bob@example.com"` | Request-URI in the SIP Request-Line |
| **`STATUS`** | `STATUS <100..699>` | Omitted (Request) | Emits a SIP response (`SIP/2.0 <STATUS> <REASON>`, e.g., `100`, `180`, `200`, `401`, `486`) |
| **`REASON`** | `REASON "<text>"` | Auto-derived | Response reason phrase (`"Trying"`, `"Ringing"`, `"OK"`, `"Busy Here"`) |
| **`FROM`** | `FROM "<uri>"` | `"sip:alice@example.com"`| Sets the `From:` header URI |
| **`TO`** | `TO "<uri>"` | `"sip:bob@example.com"` | Sets the `To:` header URI |
| **`CALL_ID`** | `CALL_ID "<id>"` | `"fasm-call-1"` | Sets the `Call-ID:` dialog identifier header |
| **`CSEQ`** | `CSEQ <number>` | `1` | Sequence number in `CSeq: <n> <METHOD>` |
| **`VIA`** | `VIA "<text>"` | Auto-generated | Custom `Via:` header (e.g., `"SIP/2.0/UDP 10.80.1.50:5060;branch=z9hG4bK776"`) |
| **`CONTACT`** | `CONTACT "<uri>"` | Omitted | Sets the `Contact:` header |
| **`CONTENT_TYPE`** | `CONTENT_TYPE "<mime>"` | `"application/sdp"` (if `BODY`) | Sets the `Content-Type:` header |
| **`BODY`** | `BODY "<sdp>"` | Empty | Attaches an SDP media description body and computes `Content-Length` |
| **`TRANSPORT`** | `TRANSPORT TCP` \| `UDP` | `UDP` | Switches SIP between UDP port `5060` and TCP port `5060` |

### 4.2 Real-Time Transport Protocol (`RTP` — Default: UDP Port `5004`)

Need an **RTP UDP 5004 G.711 PCMU / PCMA / Opus voice stream & DSCP `EF` (`46`) QoS priority queue pcap**? `RTP` builds RFC 3550 12-byte RTP headers (`Version = 2`, `Marker`, 7-bit `Payload Type`, 16-bit `Sequence Number`, 32-bit `Timestamp`, and 32-bit `SSRC`) over UDP port `5004`.
- **Canonical Syntax Note:** Always write `a -> b rtp ...` directly (never `a -> b udp rtp ...`). Override ports with `srcport <0..65535> dstport <0..65535>` if your SDP negotiated a custom UDP media port such as `16384`.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`PT`** | `PT <0..127>` | `0` (`PCMU`) | 7-bit RTP Payload Type (`0` = G.711 PCMU, `8` = G.711 PCMA, `9` = G.722, `18` = G.729, `96..127` = dynamic Opus / H.264 / VP9) |
| **`SEQ`** | `SEQ <0..65535>` | `1` | 16-bit RTP packet sequence counter |
| **`TIMESTAMP`** | `TIMESTAMP <number>` | `160` | 32-bit media sampling timestamp (e.g., `+160` per 20ms frame at 8 kHz) |
| **`SSRC`** | `SSRC <number>` | `0x12345678` | 32-bit Synchronization Source identifier |
| **`MARKER`** | `MARKER <0\|1>` | `0` | 1-bit Marker flag (`1` indicates start of talkspurt or end of video keyframe) |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | 160B silence | Encoded audio/video frame bytes (or `hexpayload "<hex>"`) |

### 4.3 Real-Time Streaming Protocol (`RTSP` — Default: TCP Port `554`)

Need an **RTSP TCP 554 IP security camera & NVR `DESCRIBE` / `SETUP` / `PLAY` / `TEARDOWN` stream control pcap**? `RTSP` builds RFC 2326 / RFC 7826 media streaming control commands and status replies.
- **Why `TRANSPORT_HDR`?** FrameAssembly reserves `TRANSPORT TCP` / `TRANSPORT UDP` to select the Layer 4 protocol. Use `TRANSPORT_HDR "<spec>"` to set the RTSP `Transport: RTP/AVP;unicast;client_port=5004-5005` header.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Method** | `OPTIONS` \| `DESCRIBE` \| `SETUP` \| `PLAY` \| `TEARDOWN` | `OPTIONS` | Standalone keyword setting the RTSP request method |
| **`METHOD`** | `METHOD "<verb>"` | `"OPTIONS"` | Explicit RTSP method string (e.g., `"PAUSE"`, `"ANNOUNCE"`, `"RECORD"`, `"GET_PARAMETER"`) |
| **`URI`** | `URI "<rtsp_url>"` | `"rtsp://localhost/stream"` | Target RTSP stream URL |
| **`STATUS`** | `STATUS <100..599>` | Omitted (Request) | Emits an RTSP response (`RTSP/1.0 <STATUS> OK\r\n`, e.g., `200`, `401`, `454`) |
| **`CSEQ`** | `CSEQ <number>` | `1` | `CSeq:` request/response correlation counter |
| **`SESSION`** | `SESSION "<id>"` | Omitted | Sets the `Session:` header identifier |
| **`TRANSPORT_HDR`** | `TRANSPORT_HDR "<text>"` | Omitted | Sets the RTSP `Transport:` header (e.g., `"RTP/AVP;unicast;client_port=5004-5005"`) |

### 4.4 Session Traversal Utilities for NAT (`STUN` — Default: UDP Port `3478`)

Need a **STUN UDP 3478 WebRTC ICE NAT traversal & `XOR-MAPPED-ADDRESS` reflexive IP discovery pcap**? `STUN` builds RFC 8489 / RFC 5389 20-byte STUN headers (with fixed magic cookie `0x2112A442` and 96-bit transaction ID) and padded TLV attributes (`0x0020` `XOR-MAPPED-ADDRESS` and `0x8022` `SOFTWARE`).
- **Important Syntax Note on `XOR_MAPPED_ADDR`:** Pass an IPv4 or IPv6 address only (e.g., `xor_mapped_addr 203.0.113.50` or `xor_mapped_addr 2001:db8::50`), never an `ip:port` pair.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`BINDING_REQUEST`** | `BINDING_REQUEST` | Default if none set | Message Type `0x0001` (STUN Binding Request) |
| **`BINDING_RESPONSE`**| `BINDING_RESPONSE` | Auto if `XOR_MAPPED_ADDR` | Message Type `0x0101` (STUN Binding Success Response) |
| **`BINDING_ERROR`** | `BINDING_ERROR` | Off | Message Type `0x0111` (STUN Binding Error Response) |
| **`TXID`** | `TXID <number>` | `1` | Populates the lower 32 bits of the 96-bit STUN Transaction ID |
| **`XOR_MAPPED_ADDR`** | `XOR_MAPPED_ADDR <ip>` | Omitted | XORs the reflexive IPv4 or IPv6 address with the magic cookie (`0x2112A442`) per RFC 8489 |
| **`SOFTWARE`** | `SOFTWARE "<text>"` | Omitted | Appends 4-byte-aligned `SOFTWARE` (`0x8022`) TLV attribute |

### 4.5 Simple Service Discovery Protocol (`SSDP` — Default: UDP Port `1900`)

Need an **SSDP / UPnP UDP 1900 `M-SEARCH` & `NOTIFY` multicast IoT discovery pcap**? `SSDP` builds UPnP HTTPU multicast discovery requests (`M-SEARCH * HTTP/1.1`) and presence advertisements (`NOTIFY * HTTP/1.1`) over UDP port `1900`.

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`MSEARCH`** | `MSEARCH` | Default if none set | Emits `M-SEARCH * HTTP/1.1\r\n` active discovery query |
| **`NOTIFY`** | `NOTIFY` | Off | Emits `NOTIFY * HTTP/1.1\r\n` multicast device announcement |
| **`HOST_HDR`** | `HOST_HDR "<ip:port>"` | `"239.255.255.250:1900"` | Sets the HTTPU `HOST:` header |
| **`MAN`** | `MAN "<text>"` | `"\"ssdp:discover\""` | Sets the `MAN:` header for `MSEARCH` packets |
| **`MX`** | `MX <0..255>` | `3` | Maximum wait response delay in seconds (`MX:` header) |
| **`ST`** | `ST "<target>"` | `"ssdp:all"` | Search Target (`"upnp:rootdevice"`, `"urn:schemas-upnp-org:device:MediaServer:1"`) |
| **`NT`** | `NT "<type>"` | `"upnp:rootdevice"` | Notification Type header in `NOTIFY` advertisements |
| **`NTS`** | `NTS "<sub_type>"` | `"ssdp:alive"` | Notification Sub-Type (`"ssdp:alive"`, `"ssdp:byebye"`, `"ssdp:update"`) |
| **`USN`** | `USN "<uuid>"` | Default UUID | Unique Service Name identifier |
| **`LOCATION`** | `LOCATION "<url>"` | Omitted | URL to the XML UPnP device description document |

### Compilable Example: VoIP Call Setup (`STUN` + `SIP` + `RTP`), `RTSP` Camera & `SSDP` Discovery

```frameassembly
host voip_phone { ip 10.80.1.50 }
host sbc_media  { ip 10.80.1.10 }

flow voip_rtsp_and_upnp(phone, sbc) {
    // 1. WebRTC / VoIP STUN NAT binding discovery
    phone -> sbc stun binding_request txid 9001 software "Polycom-VVX/6.4" wait 1ms
    phone <- sbc stun binding_response txid 9001 xor_mapped_addr 203.0.113.50 software "Coturn-4.6" wait 2ms

    // 2. DSCP CS3 (24) SIP call setup + DSCP EF (46) G.711 PCMU RTP voice stream + SIP BYE
    phone -> sbc dscp 24 sip invite uri "sip:1002@pbx.example.com" from "sip:1001@pbx.example.com" to "sip:1002@pbx.example.com" call_id "call-7741@10.80.1.50" cseq 1 via "SIP/2.0/UDP 10.80.1.50:5060" contact "sip:1001@10.80.1.50" content_type "application/sdp" body "v=0\r\nm=audio 5004 RTP/AVP 0\r\n" wait 2ms
    phone <- sbc dscp 24 sip status 200 reason "OK" call_id "call-7741@10.80.1.50" cseq 1 wait 2ms
    phone -> sbc dscp 24 sip ack uri "sip:1002@pbx.example.com" call_id "call-7741@10.80.1.50" cseq 1 wait 1ms
    phone -> sbc dscp 46 rtp pt 0 seq 1001 timestamp 160 ssrc 0x11223344 marker 1 payload "G711_PCMU_FRAME_1" wait 20ms
    phone <- sbc dscp 46 rtp pt 0 seq 5001 timestamp 160 ssrc 0x99887766 marker 1 payload "G711_PCMU_REPLY_1" wait 20ms
    phone -> sbc dscp 24 sip bye uri "sip:1002@pbx.example.com" call_id "call-7741@10.80.1.50" cseq 2 wait 2ms
    phone <- sbc dscp 24 sip status 200 reason "OK" call_id "call-7741@10.80.1.50" cseq 2 wait 5ms

    // 3. RTSP security camera stream negotiation (DESCRIBE -> SETUP -> PLAY -> TEARDOWN)
    phone -> sbc rtsp describe uri "rtsp://10.80.1.10:554/cam01/main" cseq 1 wait 1ms
    phone <- sbc rtsp status 200 cseq 1 wait 1ms
    phone -> sbc rtsp setup uri "rtsp://10.80.1.10:554/cam01/main/track1" cseq 2 transport_hdr "RTP/AVP;unicast;client_port=5004-5005" wait 1ms
    phone <- sbc rtsp status 200 cseq 2 session "cam-sess-991" wait 1ms
    phone -> sbc rtsp play uri "rtsp://10.80.1.10:554/cam01/main" cseq 3 session "cam-sess-991" wait 5ms
    phone -> sbc rtsp teardown uri "rtsp://10.80.1.10:554/cam01/main" cseq 4 session "cam-sess-991" wait 2ms

    // 4. SSDP UPnP M-SEARCH query and NOTIFY alive response
    phone -> sbc ssdp msearch host_hdr "239.255.255.250:1900" man "\"ssdp:discover\"" mx 3 st "urn:schemas-upnp-org:device:MediaServer:1" wait 1ms
    phone <- sbc ssdp notify host_hdr "239.255.255.250:1900" nt "urn:schemas-upnp-org:device:MediaServer:1" nts "ssdp:alive" usn "uuid:media-sbc-01::upnp:rootdevice" location "http://10.80.1.10:8200/rootDesc.xml"
}

compile {
    voip_rtsp_and_upnp(voip_phone, sbc_media)
}
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — `.fasm` file anatomy, automatic defaults vs. explicit overrides, and step-by-step Wireshark workflows.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — End-to-end recipes for WAF/firewall ACL testing, QoS validation, and IDS/IPS verification.
- [**Layer 4 Transport Protocols (`l4_transports.md`)**](l4_transports.md) — Shared 4-tuple `TCP` state tracking, RFC 7323 options, `UDP`, and `SCTP`.
- [**Layer 7 Infrastructure & Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — `DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, and `SFLOW`.
- [**Layer 7 Mail, Directory, Storage, Databases & Message Brokers (`l7_mail_auth_storage_db.md`)**](l7_mail_auth_storage_db.md) — `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, and `AMQP`.
- [**Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Dual-stack IPv4/IPv6 Kubernetes service-mesh (`DNS` + `TCP` + `TLS` + `GRPC` + `REDIS` + `POSTGRES`) captures.
