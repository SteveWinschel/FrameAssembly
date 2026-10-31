# Layer 7 Web, Cloud, TLS/QUIC, VoIP Media & IoT Messaging Reference

This guide covers **14 web, microservice, encrypted transport, real-time VoIP/streaming, and IoT messaging protocols** across IPv4 and IPv6. *(For `SSH`, `TELNET`, `TFTP`, `FTP`, and `WHOIS`, see [`l7_infra_and_telemetry.md`](l7_infra_and_telemetry.md).)*

---

## 1. Web, API & Microservice Protocols (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`)

| Protocol | Default Port | Modifiers & Wire Behavior |
| :--- | :--- | :--- |
| **`HTTP`** | TCP `80` | `GET` / `POST` / `PUT` / `DELETE` / `HEAD` / `OPTIONS` / `PATCH` (or `METHOD "<verb>"`), `URI "<path>"`, `HOST_HDR "<host>"` *(never write `HOST` inside `HTTP`)*, `USER_AGENT "<ua>"`, `CONTENT_TYPE "<mime>"`, `HEADER "<Key>" "<Val>"`, `STATUS <u16>`, `REASON "<str>"`, `BODY "<str>"` (auto-adds `Content-Length`) |
| **`HTTP2`** | TCP `443` | `PREFACE` (24B `"PRI * HTTP/2.0..."`), `SETTINGS`, `HEADERS`, `DATA`, `WINDOW_UPDATE`, `PING`, `GOAWAY`, `STREAM_ID <u32>` (`0` control, odd `1, 3, 5` requests) |
| **`GRPC`** | TCP `50051` | 5-byte length-prefixed framing: `SERVICE "<pkg.Svc>"`, `METHOD "<Rpc>"`, `GRPC_STATUS <0..16>` (`0`=OK, `14`=UNAVAILABLE), `PAYLOAD "<str>"` |
| **`WEBSOCKET`**| TCP `80` | `OPCODE "<TEXT\|BINARY\|CLOSE\|PING\|PONG>"` (or bare `TEXT`, `BINARY`, `CLOSE`, `PING`, `PONG`), `FIN_BIT <0\|1>`, `MASK_KEY <u32>` (auto-XORs payload bytes), `PAYLOAD "<str>"` |

```frameassembly
host ingress_gw { ip 10.120.1.10 }
host mesh_pod   { ip 10.120.1.50 }

flow web_and_service_mesh(gw, pod) {
    gw -> pod http method "POST" uri "/v1/checkout" host_hdr "api.shop.example.com" user_agent "Envoy/1.31" content_type "application/json" header "X-Request-Id" "req-99" body "{\"cart_id\":42}" wait 1ms
    gw <- pod http status 201 reason "Created" content_type "application/json" body "{\"order_id\":8801}" wait 2ms

    gw -> pod http2 preface settings stream_id 0 wait 1ms
    gw <- pod http2 settings window_update stream_id 0 wait 1ms
    gw -> pod http2 headers stream_id 1 payload ":method GET :path /v2/catalog" wait 1ms
    gw <- pod http2 goaway stream_id 0 wait 2ms

    gw -> pod grpc service "payment.v1.Ledger" method "Authorize" payload "PROTOBUF_REQ" wait 1ms
    gw <- pod grpc service "payment.v1.Ledger" method "Authorize" grpc_status 0 payload "PROTOBUF_OK" wait 2ms

    gw -> pod websocket opcode "TEXT" fin_bit 1 mask_key 0x37fa213d payload "{\"sub\":\" alerts\"}" wait 1ms
    gw <- pod websocket opcode "TEXT" fin_bit 1 payload "{\"status\":\"subscribed\"}"
}

compile {
    web_and_service_mesh(ingress_gw, mesh_pod)
}
```

---

## 2. Cryptographic & Next-Gen Web Transport (`TLS` & `QUIC`)

| Protocol | Default Port | Modifiers & Syntax Notes |
| :--- | :--- | :--- |
| **`TLS`** | TCP `443` | `CLIENT_HELLO`, `SERVER_HELLO`, `CERTIFICATE`, `FINISHED`, `APP_DATA`, `ALERT`, `RECORD_VERSION <u16>` (`0x0301`=1.0, `0x0303`=1.2), `HANDSHAKE_VERSION <u16>`, `SNI "<hostname>"`, `CIPHERSUITE <u16>` (`4865`=AES_128_GCM, `4866`=AES_256_GCM, `4867`=CHACHA20), `ALPN "<h2\|http/1.1>"` |
| **`QUIC`** | UDP `443` | `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, `RETRY`, `SHORT`, `VERSION <u32>` (`1` default), `DCID <u64>`, `SCID <u64>` *(64-bit integer/hex literals, never quoted strings)*, `PKT_NUM <u32>`, `TOKEN "<str>"` |

```frameassembly
host client_v6   { ip 2001:db8:443::50 }
host cdn_edge_v6 { ip 2001:db8:443::1 }

flow tls13_and_quic_v1(c, s) {
    // TLS 1.3 handshake with SNI + ALPN h2, encrypted AppData, and close_notify Alert
    c -> s tls client_hello record_version 0x0301 handshake_version 0x0303 sni "edge.cdn.example.com" ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls server_hello record_version 0x0303 handshake_version 0x0303 ciphersuite 4866 alpn "h2" wait 1ms
    c <- s tls certificate record_version 0x0303 payload "X509_CERT_CHAIN" wait 1ms
    c <- s tls finished record_version 0x0303 payload "SERVER_VERIFY_DATA" wait 1ms
    c -> s tls finished record_version 0x0303 payload "CLIENT_VERIFY_DATA" wait 1ms
    c -> s tls app_data record_version 0x0303 payload "ENCRYPTED_H2_GET" wait 1ms
    c -> s tls alert record_version 0x0303 payload "CLOSE_NOTIFY" wait 5ms

    // QUIC v1 Initial -> Retry -> 0-RTT -> Handshake -> 1-RTT Short Header
    c -> s quic initial dcid 0x8394c8f03e515708 scid 0x1122334455667788 pkt_num 1 payload "QUIC_CLIENT_HELLO" wait 1ms
    c <- s quic retry dcid 0x1122334455667788 scid 0x9988776655443322 payload "retry_token_v1" wait 1ms
    c -> s quic zero_rtt dcid 0x9988776655443322 scid 0x1122334455667788 pkt_num 2 payload "HTTP3_EARLY_GET" wait 1ms
    c <- s quic handshake dcid 0x1122334455667788 scid 0x9988776655443322 pkt_num 1 payload "QUIC_SERVER_FINISHED" wait 1ms
    c <- s quic short dcid 0x1122334455667788 pkt_num 2 payload "HTTP3_200_OK"
}

compile {
    tls13_and_quic_v1(client_v6, cdn_edge_v6)
}
```

---

## 3. Real-Time VoIP, NAT Traversal & Media (`STUN`, `SIP`, `RTP`, `RTSP`)

| Protocol | Default Port | Modifiers & Syntax Rules |
| :--- | :--- | :--- |
| **`STUN`** | UDP `3478` | `BINDING_REQUEST`, `BINDING_RESPONSE`, `BINDING_ERROR`, `XOR_MAPPED_ADDR <ip>` *(takes IPv4/IPv6 address only, never a port)*, `SOFTWARE "<str>"`, `TXID <u32>` |
| **`SIP`** | UDP / TCP `5060` | `INVITE`, `BYE`, `CANCEL`, `METHOD "<ACK\|REGISTER\|OPTIONS>"`, `URI "<sip_uri>"`, `FROM "<uri>"`, `TO "<uri>"`, `CALL_ID "<id>"`, `CSEQ <u32>`, `VIA "<str>"`, `CONTACT "<str>"`, `CONTENT_TYPE "<str>"`, `STATUS <u16>`, `REASON "<str>"`, `BODY "<sdp>"`, `TRANSPORT TCP` |
| **`RTP`** | UDP `5004` | `PT <0..127>` (`0`=PCMU, `96`=Opus/H.264), `SEQ <u16>`, `TIMESTAMP <u32>`, `SSRC <u32>`, `MARKER <0\|1>` *(write `RTP ...` directly, never `UDP ... RTP ...`)* |
| **`RTSP`** | TCP `554` | `OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, `TEARDOWN` (or `METHOD "<verb>"`), `URI "<rtsp_url>"`, `CSEQ <u32>`, `TRANSPORT_HDR "<str>"`, `SESSION "<id>"`, `STATUS <u16>` |

```frameassembly
host media_client { ip 10.80.1.50 }
host sbc_server   { ip 10.80.1.10 }

flow voip_and_rtsp_session(c, s) {
    c -> s stun binding_request software "WebRTC-Client/1.0" wait 1ms
    c <- s stun binding_response xor_mapped_addr 203.0.113.50 software "Coturn-4.6" wait 2ms

    c -> s dscp 24 sip invite uri "sip:bob@example.com" from "sip:alice@example.com" to "sip:bob@example.com" call_id "call-99@10.80.1.50" cseq 1 via "SIP/2.0/UDP 10.80.1.50:5060" contact "sip:alice@10.80.1.50" content_type "application/sdp" body "v=0\r\nm=audio 16384 RTP/AVP 0\r\n" wait 2ms
    c <- s dscp 24 sip status 200 reason "OK" call_id "call-99@10.80.1.50" cseq 1 wait 2ms
    c -> s dscp 24 sip method "ACK" uri "sip:bob@example.com" call_id "call-99@10.80.1.50" cseq 1 wait 1ms
    c -> s dscp 46 rtp pt 0 seq 1001 timestamp 160 ssrc 0x11223344 marker 1 payload "G711_20MS_FRAME" wait 20ms
    c -> s dscp 24 sip bye uri "sip:bob@example.com" call_id "call-99@10.80.1.50" cseq 2 wait 2ms

    c -> s rtsp method "SETUP" uri "rtsp://10.80.1.10:554/cam01/track1" cseq 1 transport_hdr "RTP/AVP;unicast;client_port=5004-5005" wait 1ms
    c <- s rtsp status 200 cseq 1 session "sess-7788" wait 1ms
    c -> s rtsp method "PLAY" uri "rtsp://10.80.1.10:554/cam01" cseq 2 session "sess-7788"
}

compile {
    voip_and_rtsp_session(media_client, sbc_server)
}
```

---

## 4. IoT Messaging, Queues & UPnP Discovery (`MQTT`, `COAP`, `AMQP`, `SSDP`)

| Protocol | Default Port | Modifiers |
| :--- | :--- | :--- |
| **`MQTT`** | TCP `1883` | `CONNECT`, `CONNACK`, `PUBLISH`, `PUBACK`, `SUBSCRIBE`, `SUBACK`, `PINGREQ`, `PINGRESP`, `DISCONNECT`, `CLIENT_ID "<id>"`, `TOPIC "<topic>"`, `QOS <0..2>`, `RETAIN`, `PKT_ID <u16>`, `RETURN_CODE <u8>` |
| **`COAP`** | UDP `5683` | `CON`, `NON`, `ACK`, `RST`, `CODE "<0.01\|0.02\|2.04\|2.05>"`, `MSGID <u16>`, `TOKEN <u32>`, `URI_PATH "<path>"`, `CONTENT_FORMAT <u16>` (`50`=`application/json`) |
| **`AMQP`** | TCP `5672` | `PROTOCOL_HEADER`, `CONNECTION_START`, `CHANNEL_OPEN`, `BASIC_PUBLISH`, `BASIC_DELIVER`, `HEARTBEAT`, `CHANNEL <u16>`, `EXCHANGE "<str>"`, `ROUTING_KEY "<str>"` |
| **`SSDP`** | UDP `1900` | `MSEARCH`, `NOTIFY`, `HOST_HDR "239.255.255.250:1900"`, `MAN "\"ssdp:discover\""`, `MX <u8>`, `ST "<target>"`, `NT "<type>"`, `NTS "<ssdp:alive\|ssdp:byebye>"`, `USN "<uuid>"`, `LOCATION "<url>"` |

```frameassembly
host iot_gw { ip 192.168.140.10 }
host broker { ip 192.168.140.1 }

flow iot_messaging_pipeline(edge, brk) {
    edge -> brk mqtt connect client_id "gw-floor2" wait 1ms
    edge <- brk mqtt connack return_code 0 wait 1ms
    edge -> brk mqtt publish pkt_id 10 topic "plant/floor2/temp" qos 1 retain payload "{\"temp_c\":23.8}" wait 1ms
    edge <- brk mqtt puback pkt_id 10 wait 2ms

    edge -> brk coap con code "0.02" msgid 401 token 0x99aabb uri_path "sensors/pressure" content_format 50 payload "{\"kpa\":101.3}" wait 1ms
    edge <- brk coap ack code "2.04" msgid 401 token 0x99aabb wait 2ms

    edge -> brk amqp protocol_header wait 1ms
    edge -> brk amqp basic_publish channel 1 exchange "telemetry" routing_key "alerts" payload "{\"ok\":true}" wait 2ms

    edge -> brk ssdp msearch host_hdr "239.255.255.250:1900" man "\"ssdp:discover\"" mx 3 st "upnp:rootdevice"
}

compile {
    iot_messaging_pipeline(iot_gw, broker)
}
```