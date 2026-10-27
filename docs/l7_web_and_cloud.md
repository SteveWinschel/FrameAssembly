# Layer 7 Web, Cloud-Native, Real-Time Media, Remote Access & IoT Messaging Reference

FrameAssembly provides native, RFC-compliant wire builders for **Layer 7 Web, Cloud-Native Microservices, Cryptographic Transport, Real-Time VoIP/Streaming Media, Remote Administration, and IoT Discovery/Messaging** protocols across IPv4 and IPv6.

This canonical reference covers:
- **Web, API & Microservice Protocols**: `HTTP` (RFC 9110 / 9112), `HTTP2` (RFC 9113), `GRPC` (gRPC over HTTP/2), and `WEBSOCKET` (RFC 6455)
- **Cryptographic & Next-Gen Web Transport**: `TLS` (RFC 8446 TLS 1.3 / RFC 5246 TLS 1.2) and `QUIC` (RFC 9000 / RFC 9114 HTTP/3)
- **Real-Time VoIP, NAT Traversal & Media Streaming**: `STUN` (RFC 5389 / 8489), `SIP` (RFC 3261), `RTP` (RFC 3550), and `RTSP` (RFC 2326 / 7826)
- **IoT Telemetry, Message Queues & UPnP Discovery**: `MQTT` (OASIS v3.1.1 / v5.0), `COAP` (RFC 7252), `AMQP` (OASIS 0-9-1), and `SSDP` (UPnP 2.0)
- **Remote Access, File Transfer & Registry Lookup**: `SSH` (RFC 4253), `TELNET` (RFC 854), `TFTP` (RFC 1350), `FTP` (RFC 959), and `WHOIS` (RFC 3912)

---

## 1. Protocol Architecture & RFC Matrix

| Protocol | Keyword | Standard Specification | Default Transport & Port | Corpus Directory | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **HTTP/1.1** | `HTTP` | RFC 9110, RFC 9112 | TCP `80` | [`examples/l7/http/`](../examples/l7/http) | REST APIs, `GET`/`POST`/`PUT`/`DELETE`, custom `HEADER`, `STATUS`, `BODY` |
| **HTTP/2** | `HTTP2` | RFC 9113, RFC 7541 | TCP `443` / `80` | [`examples/l7/http2/`](../examples/l7/http2) | Binary framing (`PREFACE`, `SETTINGS`, `HEADERS`, `WINDOW_UPDATE`, `GOAWAY`) |
| **gRPC** | `GRPC` | CNCF gRPC over HTTP/2 | TCP `50051` | [`examples/l7/grpc/`](../examples/l7/grpc) | Length-prefixed Protobuf RPC (`SERVICE`, `METHOD`, `GRPC_STATUS`) |
| **WebSocket**| `WEBSOCKET`| RFC 6455 | TCP `80` / `443` | [`examples/l7/websocket/`](../examples/l7/websocket) | Full-duplex framing (`OPCODE`, `FIN_BIT`, `MASK_KEY`, `PAYLOAD`) |
| **TLS 1.2/1.3**| `TLS` | RFC 8446, RFC 5246 | TCP `443` | [`examples/l7/tls/`](../examples/l7/tls) | `CLIENT_HELLO`, `SERVER_HELLO`, `CERTIFICATE`, `FINISHED`, `SNI`, `ALPN` |
| **QUIC v1** | `QUIC` | RFC 9000, RFC 9001 | UDP `443` | [`examples/l7/quic/`](../examples/l7/quic) | `INITIAL`, `ZERO_RTT`/`ZERORTT`, `HANDSHAKE`, `RETRY`, `SHORT`, `TOKEN` |
| **STUN** | `STUN` | RFC 5389, RFC 8489 | UDP `3478` | [`examples/l7/stun/`](../examples/l7/stun) | WebRTC ICE NAT traversal (`BINDING_REQUEST`, `XOR_MAPPED_ADDR`, `SOFTWARE`) |
| **SIP** | `SIP` | RFC 3261, RFC 3264 | UDP / TCP `5060` | [`examples/l7/sip/`](../examples/l7/sip) | VoIP call control (`INVITE`, `BYE`, `CANCEL`, `CONTACT`, `CONTENT_TYPE`) |
| **RTP** | `RTP` | RFC 3550, RFC 3551 | UDP `5004` / `16384` | [`examples/l7/rtp/`](../examples/l7/rtp) | Real-time audio/video media (`PT`, `SEQ`, `TIMESTAMP`, `SSRC`, `MARKER`) |
| **RTSP** | `RTSP` | RFC 2326, RFC 7826 | TCP `554` | [`examples/l7/rtsp/`](../examples/l7/rtsp) | Media stream control (`OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, `TEARDOWN`) |
| **MQTT** | `MQTT` | OASIS MQTT v3.1.1 / v5.0| TCP `1883` / `8883` | [`examples/l7/mqtt/`](../examples/l7/mqtt) | IoT pub/sub (`CONNECT`, `CONNACK`, `PUBLISH`, `SUBSCRIBE`, `TOPIC`, `QOS`) |
| **CoAP** | `COAP` | RFC 7252, RFC 7641 | UDP `5683` | [`examples/l7/coap/`](../examples/l7/coap) | Constrained REST (`CON`, `NON`, `ACK`, `RST`, `CODE`, `URI_PATH`, `TOKEN`) |
| **AMQP** | `AMQP` | OASIS AMQP 0-9-1 | TCP `5672` | [`examples/l7/amqp/`](../examples/l7/amqp) | Enterprise message queuing (`BASIC_PUBLISH`, `EXCHANGE`, `ROUTING_KEY`) |
| **SSDP** | `SSDP` | UPnP Device Arch 2.0 | UDP `1900` (`239.255.255.250`)| [`examples/l7/ssdp/`](../examples/l7/ssdp) | Multicast UPnP discovery (`MSEARCH`, `NOTIFY`, `ST`, `NT`, `NTS`, `USN`) |
| **SSHv2** | `SSH` | RFC 4253 | TCP `22` | [`examples/l7/ssh/`](../examples/l7/ssh) | Identification banner & binary framing (`BANNER`, `KEXINIT`, `NEWKEYS`, `COOKIE`) |
| **Telnet** | `TELNET` | RFC 854, RFC 855 | TCP `23` | [`examples/l7/telnet/`](../examples/l7/telnet) | IAC option negotiation (`WILL`, `WONT`, `DO`, `DONT`, `OPTION`, `DATA`) |
| **TFTP** | `TFTP` | RFC 1350 | UDP `69` | [`examples/l7/tftp/`](../examples/l7/tftp) | PXE boot & firmware transfer (`RRQ`, `WRQ`, `FILENAME`, `MODE`, `BLOCK`) |
| **FTP** | `FTP` | RFC 959, RFC 2428 | TCP `21` | [`examples/l7/ftp/`](../examples/l7/ftp) | File transfer control channel (`CMD`, `ARG`, `CODE`, `REPLY`) |
| **WHOIS** | `WHOIS` | RFC 3912 | TCP `43` | [`examples/l7/whois/`](../examples/l7/whois) | Domain & ASN registry lookup (`QUERY`, `RESPONSE`, `DOMAIN`, `REGISTRAR`) |

---

## 2. Web, API & Microservice Protocols (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`)

### 2.1 Canonical Modifiers (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`)

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`HTTP`** | `METHOD "<verb>"` | Quoted string | HTTP request method (`"GET"`, `"POST"`, `"PUT"`, `"DELETE"`, `"PATCH"`, `"HEAD"`, `"OPTIONS"`) |
| **`HTTP`** | `URI "<path>"` / `HOST_HDR "<host>"` | Quoted string | Request target path (e.g. `"/v1/orders"`) and `Host:` header value |
| **`HTTP`** | `USER_AGENT "<ua>"` / `CONTENT_TYPE "<mime>"` | Quoted string | `User-Agent:` and `Content-Type:` header values |
| **`HTTP`** | `HEADER "<Key>" "<Val>"` | Two quoted strings | Appends an arbitrary custom HTTP header pair |
| **`HTTP`** | `STATUS <u32>` / `REASON "<str>"` | `u32`, String | HTTP response status code (`200`, `201`, `404`, `503`) and reason phrase |
| **`HTTP`** | `BODY "<payload>"` | Quoted string | HTTP request or response entity body (auto-populates `Content-Length`) |
| **`HTTP2`** | `PREFACE` / `SETTINGS` / `HEADERS` / `WINDOW_UPDATE` / `PING` / `GOAWAY` | Bare flag (0-arg) | RFC 9113 HTTP/2 connection preface (`PRI * HTTP/2.0...`) or binary frame type |
| **`HTTP2`** | `STREAM_ID <u32>` / `FRAME_TYPE <u32>` / `FLAGS <u32>` | `u32` | 31-bit HTTP/2 Stream Identifier (`0` for control, odd `1, 3, 5` for requests), frame type, and flags |
| **`GRPC`** | `SERVICE "<pkg.Svc>"` / `METHOD "<Rpc>"` | Quoted string | gRPC target service name and RPC method mapped to `:path /<Service>/<Method>` |
| **`GRPC`** | `GRPC_STATUS <u32>` / `COMPRESSED` | `u32` (`0..16`), Flag | `grpc-status` trailer code (`0` = OK, `14` = UNAVAILABLE) and 1-byte compression flag |
| **`WEBSOCKET`**| `OPCODE "<type>"` | Quoted string | RFC 6455 frame opcode (`"TEXT"`=`0x1`, `"BINARY"`=`0x2`, `"CLOSE"`=`0x8`, `"PING"`=`0x9`, `"PONG"`=`0xA`) |
| **`WEBSOCKET`**| `FIN_BIT <0\|1>` / `MASK_KEY <u32>` | `u32`, `u32` | Final fragment bit (`1` default) and 32-bit client-to-server XOR masking key |

#### Wire Encoding Details (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`)
- **`HTTP` (RFC 9110 / RFC 9112)**: Formats CRLF-delimited HTTP/1.1 requests (`<METHOD> <URI> HTTP/1.1\r\nHost: <HOST_HDR>\r\n...`) or responses (`HTTP/1.1 <STATUS> <REASON>\r\n...`), automatically appending `Content-Length: <len>` whenever `BODY` or `PAYLOAD` is present.
- **`HTTP2` (`SETTINGS` & Binary Framing, RFC 9113)**: Emits the 24-byte client connection preface (`"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`) when `PREFACE` is set, followed by 9-byte HTTP/2 frame headers (`[Length(24-bit BE), Type(1B), Flags(1B), StreamID(31-bit BE)]`). `SETTINGS` (`Type = 0x04`, `StreamID = 0`) encodes 6-byte `[Identifier(2B BE), Value(4B BE)]` parameters (such as `SETTINGS_MAX_CONCURRENT_STREAMS = 100`, `SETTINGS_INITIAL_WINDOW_SIZE = 65535`).
- **`GRPC` (`GRPC_STATUS` & Length-Prefixed Framing)**: Encodes the 5-byte gRPC Length-Prefixed-Message header (`[Compressed-Flag(1B), Message-Length(4B BE)]`) followed by the Protobuf payload, `:path /<SERVICE>/<METHOD>` metadata, and `grpc-status: <GRPC_STATUS>` trailer semantics on TCP port `50051`.
- **`WEBSOCKET` (RFC 6455)**: Encodes `[FIN_BIT << 7 | opcode, mask_bit << 7 | len_code, extended_len..., MASK_KEY(4B optional), masked_payload]`. When `MASK_KEY <u32>` is specified, sets the mask bit (`0x80`) and XOR-masks every payload byte with `mask_key_bytes[i % 4]`.

> **Important Syntax Rule**: In `HTTP`, always specify the request verb using `METHOD "<VERB>"` (e.g. `HTTP METHOD "GET" URI "/health"` or `HTTP METHOD "POST" URI "/v1/items"`). In `WEBSOCKET`, always specify `OPCODE "<TYPE>"` (e.g. `WEBSOCKET OPCODE "TEXT" FIN_BIT 1`).

### 2.2 Verified `HTTP`, `HTTP2`, `GRPC`, and `WEBSOCKET` Example

```frameassembly
// PROMPT: Cloud-native API gateway and service mesh flow covering HTTP/1.1 REST, HTTP/2 multiplexing, gRPC Protobuf RPC, and WebSocket streaming.
// TOKENS: HOST, IP, MAC, FLOW, HTTP, METHOD, URI, HOST_HDR, USER_AGENT, CONTENT_TYPE, HEADER, STATUS, REASON, BODY, HTTP2, PREFACE, SETTINGS, HEADERS, WINDOW_UPDATE, PING, GOAWAY, STREAM_ID, GRPC, SERVICE, GRPC_STATUS, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare API Ingress Gateway node.
host ingress_gw {
    ip 10.120.1.10
    mac 00:50:56:78:01:10
}

// INSTRUCTION: Declare Microservice Backend Pod node.
host mesh_pod {
    ip 10.120.1.50
    mac 00:50:56:78:01:50
}

// INSTRUCTION: Define HTTP/1.1 REST POST/201, HTTP/2 stream multiplexing, gRPC unary call, and WebSocket bidirectional frames.
flow web_and_microservice_mesh(gw, pod) {
    gw -> pod http method "POST" uri "/v1/checkout" host_hdr "api.shop.example.com" user_agent "Envoy/1.31" content_type "application/json" header "X-Request-Id" "req-9901" body "{\"cart_id\":42}" wait 1ms
    gw <- pod http status 201 reason "Created" content_type "application/json" header "X-Request-Id" "req-9901" body "{\"order_id\":8801,\"status\":\"confirmed\"}" wait 1ms
    gw -> pod http2 preface settings stream_id 0 wait 1ms
    gw <- pod http2 settings window_update stream_id 0 wait 1ms
    gw -> pod http2 headers stream_id 1 payload ":method GET :path /v2/catalog" wait 1ms
    gw <- pod http2 headers stream_id 1 payload ":status 200 content-type application/json" wait 1ms
    gw -> pod http2 ping stream_id 0 wait 1ms
    gw <- pod http2 goaway stream_id 0 wait 1ms
    gw -> pod grpc service "payment.v1.LedgerService" method "AuthorizeCharge" payload "PROTOBUF_CHARGE_REQ_100_USD" wait 1ms
    gw <- pod grpc service "payment.v1.LedgerService" method "AuthorizeCharge" grpc_status 0 payload "PROTOBUF_CHARGE_RES_AUTH_OK" wait 1ms
    gw -> pod websocket opcode "TEXT" fin_bit 1 mask_key 0x37fa213d payload "{\"sub\":\"ticker.btcusd\"}" wait 1ms
    gw <- pod websocket opcode "TEXT" fin_bit 1 payload "{\"ticker\":\"btcusd\",\"price\":94520.50}" wait 1ms
    gw -> pod websocket opcode "CLOSE" fin_bit 1 mask_key 0x37fa213d wait 1ms
}

// INSTRUCTION: Compile the cloud-native web and microservice mesh capture.
compile {
    web_and_microservice_mesh(ingress_gw, mesh_pod)
}
```

---

## 3. Cryptographic & Next-Gen Web Transport (`TLS` & `QUIC`)

### 3.1 Canonical `TLS` (RFC 8446) and `QUIC` (RFC 9000) Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`TLS`** | `CLIENT_HELLO` / `SERVER_HELLO` / `CERTIFICATE` / `FINISHED` / `APP_DATA` / `ALERT` | Bare flag (0-arg) | TLS Record / Handshake message type on TCP port `443` |
| **`TLS`** | `RECORD_VERSION <u32>` / `HANDSHAKE_VERSION <u32>` | `u32` | TLS version code (`0x0301` = 1.0, `0x0303` = 1.2, `0x0304` = 1.3) |
| **`TLS`** | `SNI "<hostname>"` | Quoted string | RFC 6066 Server Name Indication extension (`0x0000`) |
| **`TLS`** | `CIPHERSUITE <u32>` | `u32` | IANA Cipher Suite ID (`4865` = `0x1301` AES_128_GCM_SHA256, `4866` = `0x1302` AES_256_GCM_SHA384, `4867` = `0x1303` CHACHA20_POLY1305) |
| **`TLS`** | `ALPN "<proto>"` | Quoted string | RFC 7301 Application-Layer Protocol Negotiation extension (`0x0010`: `"h2"`, `"http/1.1"`, `"h3"`) |
| **`QUIC`** | `INITIAL` / `ZERO_RTT` (`ZERORTT`) / `HANDSHAKE` / `RETRY` / `SHORT` | Bare flag (0-arg) | RFC 9000 Long Header packet types (`0x00..0x03`) or 1-RTT `SHORT` header (`0x40`) on UDP `443` |
| **`QUIC`** | `VERSION <u32>` | `u32` | 32-bit QUIC Version field in Long Header packets (`0x00000001` = QUIC v1 default) |
| **`QUIC`** | `DCID <u64>` / `SCID <u64>` | `u64` integer | 64-bit Destination Connection ID and Source Connection ID |
| **`QUIC`** | `PKT_NUM <u32>` / `TOKEN "<str>"` | `u32`, String | QUIC Packet Number and `INITIAL` / `RETRY` address validation token |

#### Wire Encoding Invariants (`TLS`, `QUIC`)
- **`TLS` Record & Handshake Layer (`src/builders/l7/tls.rs`)**:
  - **5-Byte TLS Record Header**: `[ContentType(1B), RECORD_VERSION(2B BE, default 0x0303), RecordLength(2B BE)]`, where `ContentType` is `22` (`0x16` Handshake) for `CLIENT_HELLO` (`1`), `SERVER_HELLO` (`2`), `CERTIFICATE` (`11`), and `FINISHED` (`20`); `23` (`0x17`) for `APP_DATA`; and `21` (`0x15`) for `ALERT`.
  - **Handshake Body & Extensions**: For `CLIENT_HELLO` and `SERVER_HELLO`, encodes `[HandshakeType(1B), Length(24-bit BE), HANDSHAKE_VERSION(2B BE), Random(32B), SessionID, CipherSuites(CIPHERSUITE), CompressionMethods, ExtensionsLength(2B BE)]` followed by RFC 6066 `SNI` (`0x0000` Server Name Indication list), RFC 7301 **`ALPN` (`0x0010` Application-Layer Protocol Negotiation)**, and `supported_versions` (`0x002b`).
- **`QUIC` RFC 9000 §16 2-Byte Varint Long Header Length & Short Header (`src/builders/l7/quic.rs`)**:
  - **Long Header (`INITIAL` `0x00`, `ZERO_RTT`/`ZERORTT` `0x01`, `HANDSHAKE` `0x02`, `RETRY` `0x03`)**: Byte `0` is `0xC0 | (pkt_type << 4) | 0x03`, followed by 4-byte big-endian `VERSION` (`0x00000001`), 1-byte `DCID Len (8)` + 8-byte `DCID`, and 1-byte `SCID Len (8)` + 8-byte `SCID`.
  - **`INITIAL` Token & RFC 9000 §16 2-Byte Varint Length**: For `INITIAL` packets, encodes the `TOKEN` length and `TOKEN` bytes before the Length field. For `INITIAL`, `ZERO_RTT`/`ZERORTT`, and `HANDSHAKE`, the `Length` field is encoded as an **RFC 9000 §16 2-byte variable-length integer with the `0x4000` prefix** (`((0x4000 | inner_len) as u16).to_be_bytes()`, where `inner_len = 4 (PKT_NUM) + payload.len()`), followed by the 4-byte `PKT_NUM` and payload. (`RETRY` packets carry the retry token + 16-byte Retry Integrity Tag directly without a Length or Packet Number field.)
  - **Short Header (`SHORT` `0x40`)**: 1-RTT packets omit Version, SCID, Token, and Length, encoding `[0x40 (Fixed Bit = 1), DCID(8B), PKT_NUM(4B BE), payload]`.

> **Important Syntax Rule**: In `QUIC`, `DCID` and `SCID` take 64-bit integer literals (`DCID 0x8394c8f03e515708 SCID 0x1122334455667788`), never quoted strings.

### 3.2 Verified `TLS` 1.3 and `QUIC` v1 (HTTP/3) Example

```frameassembly
// PROMPT: Dual-stack TLS 1.3 mTLS handshake (SNI, ALPN h2, AES-256-GCM) and QUIC v1 (RFC 9000) 0-RTT / 1-RTT HTTP/3 connection migration.
// TOKENS: HOST, IP, MAC, FLOW, TLS, CLIENT_HELLO, SERVER_HELLO, CERTIFICATE, FINISHED, APP_DATA, ALERT, RECORD_VERSION, HANDSHAKE_VERSION, SNI, CIPHERSUITE, ALPN, QUIC, INITIAL, RETRY, HANDSHAKE, ZERO_RTT, SHORT, DCID, SCID, PKT_NUM, TOKEN, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare Edge Client IPv6 host.
host client_v6 {
    ip 2001:db8:443::50
    mac 00:50:56:44:03:50
}

// INSTRUCTION: Declare Anycast CDN Edge Server IPv6 host.
host cdn_edge_v6 {
    ip 2001:db8:443::1
    mac 00:1c:73:44:03:01
}

// INSTRUCTION: Define a complete TLS 1.3 handshake, encrypted application data exchange, and close_notify alert.
flow tls13_full_session(c, s) {
    c -> s tls client_hello record_version 0x0301 handshake_version 0x0303 sni "edge.cdn.example.com" ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls server_hello record_version 0x0303 handshake_version 0x0303 ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls certificate record_version 0x0303 payload "X509_ECDSA_P256_CERT_CHAIN" wait 1ms
    c <- s tls finished record_version 0x0303 payload "HMAC_SHA384_VERIFY_DATA" wait 1ms
    c -> s tls finished record_version 0x0303 payload "CLIENT_HMAC_VERIFY_DATA" wait 1ms
    c -> s tls app_data record_version 0x0303 payload "AEAD_AES_256_GCM_H2_GET_INDEX" wait 1ms
    c <- s tls app_data record_version 0x0303 payload "AEAD_AES_256_GCM_H2_200_OK" wait 1ms
    c -> s tls alert record_version 0x0303 payload "CLOSE_NOTIFY_0x0100" wait 1ms
}

// INSTRUCTION: Define a QUIC v1 handshake with Retry token validation, 0-RTT early data, and 1-RTT SHORT header frames.
flow quic_http3_lifecycle(c, s) {
    c -> s quic initial dcid 0x8394c8f03e515708 scid 0x1122334455667788 pkt_num 1 payload "QUIC_CRYPTO_CLIENT_HELLO_H3" wait 1ms
    c <- s quic retry dcid 0x1122334455667788 scid 0x9988776655443322 payload "retry_addr_validation_tok" wait 1ms
    c -> s quic initial dcid 0x9988776655443322 scid 0x1122334455667788 pkt_num 2 payload "QUIC_CRYPTO_CLIENT_HELLO_RETRY" wait 1ms
    c -> s quic zero_rtt dcid 0x9988776655443322 scid 0x1122334455667788 pkt_num 3 payload "HTTP3_EARLY_DATA_GET_API" wait 1ms
    c <- s quic handshake dcid 0x1122334455667788 scid 0x9988776655443322 pkt_num 1 payload "QUIC_CRYPTO_SERVER_HELLO_FINISHED" wait 1ms
    c -> s quic short dcid 0x9988776655443322 pkt_num 4 payload "HTTP3_1RTT_HEADERS_STREAM_0" wait 1ms
    c <- s quic short dcid 0x1122334455667788 pkt_num 2 payload "HTTP3_1RTT_DATA_200_OK" wait 1ms
}

// INSTRUCTION: Compile both the TLS 1.3 and QUIC v1 HTTP/3 flows over IPv6.
compile {
    tls13_full_session(client_v6, cdn_edge_v6)
    quic_http3_lifecycle(client_v6, cdn_edge_v6)
}
```

---

## 4. Real-Time VoIP, NAT Traversal & Media Streaming (`STUN`, `SIP`, `RTP`, `RTSP`)

### 4.1 Canonical Modifiers (`STUN`, `SIP`, `RTP`, `RTSP`)

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`STUN`** | `BINDING_REQUEST` / `BINDING_RESPONSE` / `BINDING_ERROR` | Bare flag (0-arg) | RFC 5389 STUN message class (`0x0001`, `0x0101`, `0x0111`) on UDP port `3478` |
| **`STUN`** | `XOR_MAPPED_ADDR <ip>` | IPv4 or IPv6 | Reflexive public address in `XOR-MAPPED-ADDRESS` (`0x0020`, takes only `<ip>`) |
| **`STUN`** | `SOFTWARE "<str>"` / `TXID <u64>` | String, `u64` | `SOFTWARE` attribute (`0x8022`, 4B-padded) and Transaction ID seed |
| **`SIP`** | `INVITE` / `BYE` / `CANCEL` or `METHOD "<verb>"` | Flag or String | RFC 3261 request method (`INVITE`, `BYE`, `CANCEL`, `METHOD "ACK"`, `METHOD "REGISTER"`) |
| **`SIP`** | `URI "<sip_uri>"` / `FROM "<uri>"` / `TO "<uri>"` | Quoted string | Request-URI, `From:` header, and `To:` header |
| **`SIP`** | `CALL_ID "<id>"` / `CSEQ <u32>` | String, `u32` | Unique `Call-ID` dialog identifier and `CSeq` sequence number |
| **`SIP`** | `VIA "<str>"` / `CONTACT "<str>"` / `CONTENT_TYPE "<str>"` | Quoted string | `Via:`, `Contact:`, and `Content-Type:` (e.g. `"application/sdp"`) headers |
| **`SIP`** | `STATUS <u32>` / `REASON "<str>"` / `BODY "<sdp>"` | `u32`, String | SIP response status (`100`, `180`, `200`) and SDP body |
| **`RTP`** | `PT <0..127>` / `SEQ <u32>` / `TIMESTAMP <u32>` | `u32` | Payload Type (`0` = PCMU, `96` = Opus/H.264), 16-bit sequence, 32-bit media clock |
| **`RTP`** | `SSRC <u32>` / `MARKER <0\|1>` | `u32` | Synchronization Source ID and Marker bit (`1` = talkspurt / video keyframe end) |
| **`RTSP`** | `OPTIONS` or `METHOD "<verb>"` | Flag or String | RTSP method (`OPTIONS`, `METHOD "DESCRIBE"`, `METHOD "SETUP"`, `METHOD "PLAY"`, `METHOD "TEARDOWN"`) |
| **`RTSP`** | `URI "<rtsp_url>"` / `CSEQ <u32>` | String, `u32` | Target `rtsp://` stream URI and `CSeq` counter |
| **`RTSP`** | `TRANSPORT_HDR "<str>"` / `SESSION "<id>"` / `STATUS <u32>`| String, `u32` | `Transport:` port negotiation header, `Session:` ID, and response status (`200`) |

#### Wire Encoding Invariants (`STUN`, `SIP`, `RTP`, `RTSP`)
- **`STUN` (`BINDING_REQUEST`, `SOFTWARE` `0x8022`, Dual-Stack `XOR-MAPPED-ADDRESS` `0x0020`)**:
  - Serializes the 20-byte RFC 5389 / 8489 header (`[msg_type(2B BE), msg_len(2B BE), magic_cookie = 0x2112A442(4B BE), transaction_id(12B)]`).
  - **Dual-Stack `XOR-MAPPED-ADDRESS` (`0x0020`)**: For **IPv4** (`family = 0x01`, 8-byte attribute value), encodes `X-Port = port ^ 0x2112` and `X-Address = ipv4_u32 ^ 0x2112A442`. For **IPv6** (`family = 0x02`, 20-byte attribute value), XORs the 128-bit IPv6 address against the 16-byte concatenation of Magic Cookie `0x2112A442` and the 96-bit Transaction ID.
  - **`SOFTWARE` (`0x8022`)**: Encodes `[0x80, 0x22, len(2B BE), utf8_bytes..., zero_padding_to_4B]`.
- **`SIP` (`CONTACT`, `CONTENT_TYPE`)**: Formats RFC 3261 requests/responses with `Via:`, `From:`, `To:`, `Call-ID:`, `CSeq:`, `Contact:` (`CONTACT`), `Content-Type:` (`CONTENT_TYPE`), and `Content-Length:` matching `BODY`.
- **`RTP` (RFC 3550)** & **`RTSP` (RFC 2326 / 7826)**: `RTP` encodes a 12-byte big-endian header (`[0x80, (MARKER << 7) | (PT & 0x7F), SEQ(2B), TIMESTAMP(4B), SSRC(4B)]`) + payload; `RTSP` formats CRLF-delimited `RTSP/1.0` requests and responses with `CSeq:`, `Transport:`, and `Session:` headers.

> **Important Syntax Rule**:
> - In `STUN`, `XOR_MAPPED_ADDR <ip>` takes **only** an IPv4 or IPv6 address (never follow it with a port number).
> - In `RTP`, write `RTP PT 0 SEQ 100 TIMESTAMP 160 SSRC 0x12345678` directly as the statement's protocol (never write `UDP ... RTP ...`, which causes a duplicate protocol semantic error).

### 4.2 Verified `STUN`, `SIP`, `RTP`, and `RTSP` Example

```frameassembly
// PROMPT: End-to-end VoIP & media streaming session featuring STUN NAT binding, SIP call setup, RTP G.711 audio stream, and RTSP camera control.
// TOKENS: HOST, IP, MAC, FLOW, DSCP, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, SOFTWARE, SIP, INVITE, BYE, METHOD, URI, FROM, TO, CALL_ID, CSEQ, VIA, CONTACT, CONTENT_TYPE, STATUS, REASON, BODY, RTP, PT, SEQ, TIMESTAMP, SSRC, MARKER, RTSP, OPTIONS, TRANSPORT_HDR, SESSION, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare the VoIP / Media Client endpoint.
host media_client {
    ip 10.80.1.50
    mac 00:50:56:80:01:50
}

// INSTRUCTION: Declare the Session Border Controller / Media Server endpoint.
host sbc_media_srv {
    ip 10.80.1.10
    mac 00:1c:73:80:01:10
}

// INSTRUCTION: Define STUN ICE discovery, SIP INVITE/200/ACK/BYE call lifecycle, QoS EF RTP audio frames, and RTSP stream control.
flow voip_and_rtsp_media_session(c, s) {
    c -> s stun binding_request software "FrameAssembly-WebRTC/1.0" wait 1ms
    c <- s stun binding_response xor_mapped_addr 203.0.113.50 software "Coturn-4.6" wait 1ms
    c -> s dscp 24 sip invite uri "sip:bob@example.com" from "sip:alice@example.com" to "sip:bob@example.com" call_id "call-9901@10.80.1.50" cseq 1 via "SIP/2.0/UDP 10.80.1.50:5060" contact "sip:alice@10.80.1.50" content_type "application/sdp" body "v=0\r\nm=audio 16384 RTP/AVP 0\r\n" wait 2ms
    c <- s dscp 24 sip status 180 reason "Ringing" call_id "call-9901@10.80.1.50" cseq 1 wait 5ms
    c <- s dscp 24 sip status 200 reason "OK" call_id "call-9901@10.80.1.50" cseq 1 content_type "application/sdp" body "v=0\r\nm=audio 16384 RTP/AVP 0\r\n" wait 2ms
    c -> s dscp 24 sip method "ACK" uri "sip:bob@example.com" call_id "call-9901@10.80.1.50" cseq 1 wait 1ms
    c -> s dscp 46 rtp pt 0 seq 1001 timestamp 160 ssrc 0x11223344 marker 1 payload "G711_ULAW_20MS_TALKSPURT_1" wait 20ms
    c <- s dscp 46 rtp pt 0 seq 5001 timestamp 160 ssrc 0x55667788 marker 1 payload "G711_ULAW_20MS_RETURN_1" wait 20ms
    c -> s dscp 24 sip bye uri "sip:bob@example.com" call_id "call-9901@10.80.1.50" cseq 2 wait 1ms
    c <- s dscp 24 sip status 200 reason "OK" call_id "call-9901@10.80.1.50" cseq 2 wait 1ms
    c -> s rtsp options uri "rtsp://10.80.1.10:554/cam01" cseq 1 wait 1ms
    c <- s rtsp status 200 cseq 1 wait 1ms
    c -> s rtsp method "DESCRIBE" uri "rtsp://10.80.1.10:554/cam01" cseq 2 wait 1ms
    c -> s rtsp method "SETUP" uri "rtsp://10.80.1.10:554/cam01/track1" cseq 3 transport_hdr "RTP/AVP;unicast;client_port=5004-5005" wait 1ms
    c <- s rtsp status 200 cseq 3 session "sess-778899" wait 1ms
    c -> s rtsp method "PLAY" uri "rtsp://10.80.1.10:554/cam01" cseq 4 session "sess-778899" wait 1ms
    c -> s rtsp method "TEARDOWN" uri "rtsp://10.80.1.10:554/cam01" cseq 5 session "sess-778899" wait 1ms
}

// INSTRUCTION: Compile the STUN, SIP, RTP, and RTSP real-time media capture.
compile {
    voip_and_rtsp_media_session(media_client, sbc_media_srv)
}
```

---

## 5. IoT Telemetry, Message Queues & UPnP Discovery (`MQTT`, `COAP`, `AMQP`, `SSDP`)

### 5.1 Canonical Modifiers (`MQTT`, `COAP`, `AMQP`, `SSDP`)

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`MQTT`** | `CONNECT` / `CONNACK` / `PUBLISH` / `PUBACK` / `SUBSCRIBE` / `SUBACK` / `PINGREQ` / `PINGRESP` | Bare flag (0-arg) | OASIS MQTT control packet types on TCP port `1883` |
| **`MQTT`** | `CLIENT_ID "<id>"` / `TOPIC "<topic>"` | Quoted string | Client Identifier (use `CLIENT_ID`, never `CLIENTID`) and topic filter |
| **`MQTT`** | `QOS <0..2>` / `RETAIN` / `PKT_ID <u32>` (`PKTID <u32>`) | `u32`, Flag | Quality of Service level (`0`, `1`, `2`), Retain flag, and 16-bit Packet ID |
| **`MQTT`** | `RETURN_CODE <u32>` / `KEEPALIVE <u32>` | `u32` | `CONNACK` return code (`0` = Accepted) and Connect Keep-Alive timer (seconds) |
| **`COAP`** | `CON` / `NON` / `ACK` / `RST` | Bare flag (0-arg) | RFC 7252 Confirmable, Non-confirmable, Acknowledgment, or Reset message |
| **`COAP`** | `CODE "<c.dd>"` / `MSGID <u32>` / `TOKEN <u32>` | String, `u32` | Method/Response code (`"0.01"` GET, `"0.02"` POST, `"2.05"` Content), Message ID, Token |
| **`COAP`** | `URI_PATH "<path>"` / `CONTENT_FORMAT <u32>` | String, `u32` | Option 11 Uri-Path and Option 12 Content-Format (`50` = `application/json`) |
| **`AMQP`** | `PROTOCOL_HEADER` / `CONNECTION_START` / `CHANNEL_OPEN` / `BASIC_PUBLISH` / `BASIC_DELIVER` / `HEARTBEAT` | Bare flag (0-arg) | OASIS AMQP 0-9-1 frame lifecycle (`'AMQP\x00\x00\x09\x01'` or Method/Body/Heartbeat frames) on TCP `5672` |
| **`AMQP`** | `CHANNEL <u32>` / `EXCHANGE "<str>"` / `ROUTING_KEY "<str>"` | `u32`, String | AMQP virtual channel ID, exchange name, and routing key |
| **`SSDP`** | `MSEARCH` / `NOTIFY` | Bare flag (0-arg) | UPnP `M-SEARCH * HTTP/1.1` discovery or `NOTIFY * HTTP/1.1` advertisement on UDP `1900` |
| **`SSDP`** | `HOST_HDR "<ip:port>"` / `MAN "<str>"` / `MX <u32>` | String, `u32` | Multicast `HOST:` header (`239.255.255.250:1900`), `MAN:` (`"\"ssdp:discover\""`), and `MX:` wait seconds |
| **`SSDP`** | `ST "<target>"` / `NT "<type>"` / `NTS "<sub_type>"` | Quoted string | Search Target (`ST:`), Notification Type (`NT:`), and Notification Sub-Type (`"ssdp:alive"` / `"ssdp:byebye"`) |
| **`SSDP`** | `USN "<uuid>"` / `LOCATION "<url>"` | Quoted string | Unique Service Name (`USN:`) UUID and XML device description URL (`LOCATION:`) |

### 5.2 Verified `MQTT`, `COAP`, `AMQP`, and `SSDP` Example

```frameassembly
// PROMPT: IoT edge gateway and message broker pipeline combining MQTT v3.1.1 QoS 1 pub/sub, CoAP confirmable sensor telemetry, AMQP 0-9-1 task queuing, and UPnP SSDP discovery.
// TOKENS: HOST, IP, MAC, FLOW, MQTT, CONNECT, CONNACK, SUBSCRIBE, SUBACK, PUBLISH, PUBACK, PINGREQ, PINGRESP, CLIENT_ID, RETURN_CODE, TOPIC, QOS, RETAIN, PKT_ID, COAP, CON, ACK, CODE, MSGID, TOKEN, URI_PATH, CONTENT_FORMAT, AMQP, PROTOCOL_HEADER, CONNECTION_START, CHANNEL_OPEN, BASIC_PUBLISH, BASIC_DELIVER, HEARTBEAT, CHANNEL, EXCHANGE, ROUTING_KEY, SSDP, MSEARCH, NOTIFY, HOST_HDR, MAN, MX, ST, NT, NTS, USN, LOCATION, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare the IoT Edge Gateway node.
host iot_gateway {
    ip 192.168.140.10
    mac 00:50:56:8c:00:10
}

// INSTRUCTION: Declare the Central Message Broker & IoT Hub node.
host message_broker {
    ip 192.168.140.1
    mac 00:1c:73:8c:00:01
}

// INSTRUCTION: Define MQTT session, CoAP sensor push, AMQP exchange publish/deliver, and SSDP discovery.
flow iot_and_messaging_pipeline(edge, broker) {
    edge -> broker mqtt connect client_id "iot-gw-floor2" wait 1ms
    edge <- broker mqtt connack return_code 0 wait 1ms
    edge -> broker mqtt subscribe pkt_id 10 topic "factory/floor2/cmd/#" qos 1 wait 1ms
    edge <- broker mqtt suback pkt_id 10 return_code 1 wait 1ms
    edge -> broker mqtt publish pkt_id 11 topic "factory/floor2/temp" qos 1 retain payload "{\"temp_c\":23.8}" wait 1ms
    edge <- broker mqtt puback pkt_id 11 wait 1ms
    edge -> broker mqtt pingreq wait 1ms
    edge <- broker mqtt pingresp wait 1ms
    edge -> broker coap con code "0.02" msgid 401 token 0x99aabb uri_path "sensors/pressure" content_format 50 payload "{\"kpa\":101.3}" wait 1ms
    edge <- broker coap ack code "2.04" msgid 401 token 0x99aabb wait 1ms
    edge -> broker amqp protocol_header wait 1ms
    edge <- broker amqp connection_start channel 0 wait 1ms
    edge -> broker amqp channel_open channel 1 wait 1ms
    edge -> broker amqp basic_publish channel 1 exchange "telemetry.topic" routing_key "floor2.alerts" payload "{\"alert\":\"NORMAL\"}" wait 1ms
    edge <- broker amqp basic_deliver channel 1 exchange "telemetry.topic" routing_key "floor2.alerts" payload "{\"ack\":true}" wait 1ms
    edge -> broker amqp heartbeat channel 0 wait 1ms
    edge -> broker ssdp msearch host_hdr "239.255.255.250:1900" man "\"ssdp:discover\"" mx 3 st "urn:schemas-upnp-org:device:IoTGateway:1" wait 1ms
    edge <- broker ssdp notify host_hdr "239.255.255.250:1900" nt "urn:schemas-upnp-org:device:IoTGateway:1" nts "ssdp:alive" usn "uuid:8899aabb-ccdd-1122::urn:schemas-upnp-org:device:IoTGateway:1" location "http://192.168.140.1:8080/desc.xml" wait 1ms
}

// INSTRUCTION: Compile the IoT and messaging pipeline capture.
compile {
    iot_and_messaging_pipeline(iot_gateway, message_broker)
}
```

---

## 6. Remote Access, File Transfer & Registry Lookup (`SSH`, `TELNET`, `TFTP`, `FTP`, `WHOIS`)

| Protocol | Modifier Syntax | Argument Type | Wire Format & Sub-Keyword Details |
| :--- | :--- | :--- | :--- |
| **`SSH`** | `BANNER "<str>"` | Quoted string | **Identification Banner (RFC 4253 §4.2)**: Emits `<BANNER>\r\n` (e.g. `"SSH-2.0-OpenSSH_9.8p1\r\n"`) on TCP port `22`. |
| **`SSH`** | `KEXINIT` / `NEWKEYS` / `MSG_CODE <u32>` (`MSGCODE <u32>`) / `COOKIE "<str>"` | Flag, `u32`, String | **Binary Packet Framing (RFC 4253 §6)**: Emits `[packet_length(4B BE), padding_length(1B), msg_code(1B), payload..., random_padding]` padded to an 8-byte block boundary (`>= 4` bytes padding). `KEXINIT` (`20`) embeds the 16-byte `COOKIE` and algorithm name-lists; `NEWKEYS` (`21`) transitions keys. |
| **`TELNET`** | `WILL <u32>` / `WONT <u32>` / `DO <u32>` / `DONT <u32>` / `OPTION <u32>` / `DATA "<str>"` | `u32` (`0..255`), String | **IAC Negotiation (RFC 854)**: Emits 3-byte `0xff <cmd> <opt>` triplets (`WILL`=`0xfb`, `WONT`=`0xfc`, `DO`=`0xfd`, `DONT`=`0xfe`, or `OPTION`=`0xff 0xfb <opt>`) followed by terminal `DATA` / `PAYLOAD` on TCP port `23`. |
| **`TFTP`** | `RRQ` / `WRQ` / `FILENAME "<str>"` / `MODE "<str>"` / `BLOCK <u32>` / `ERRCODE <u32>` / `ERRMSG "<str>"` | Flag, String, `u32` | **RFC 1350**: 2-byte big-endian Opcode (`1`=`RRQ`, `2`=`WRQ` with NUL-terminated `FILENAME` and `MODE`; `3`=`DATA` / `4`=`ACK` with 2B BE `BLOCK`; `5`=`ERROR` with `ERRCODE` and `ERRMSG`) on UDP port `69`. |
| **`FTP`** | `CMD "<str>"` / `ARG "<str>"` / `CODE <u32>` / `REPLY "<str>"` | String, `u32` | **RFC 959**: Client `<CMD> <ARG>\r\n` or server `<CODE> <REPLY>\r\n` control frames on TCP port `21`. |
| **`WHOIS`** | `QUERY` / `RESPONSE` / `DOMAIN "<str>"` / `REGISTRAR "<str>"` | Flag, String | **RFC 3912**: Emits `<DOMAIN>\r\n` for `QUERY` or a multi-line registry record containing `Domain Name: <DOMAIN>` and `Registrar: <REGISTRAR>` for `RESPONSE` on TCP port `43`. |

> See [**Layer 7 Core Infrastructure & Remote Administration (`docs/l7_infra_and_telemetry.md` §6)**](./l7_infra_and_telemetry.md) for a complete compilable `SSH`, `TELNET`, `TFTP`, `FTP`, and `WHOIS` scenario.

