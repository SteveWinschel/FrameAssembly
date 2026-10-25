# Layer 7 Core Infrastructure, AAA, Flow Telemetry & Remote Administration Reference

FrameAssembly provides native, RFC-compliant wire builders for **16 Layer 7 Core Infrastructure, Time Synchronization, AAA Security, Flow Observability, File Transfer, and Remote CLI Administration** protocols across IPv4 and IPv6.

This canonical reference covers:
- **Naming & Address Assignment**: `DNS` (RFC 1035 / RFC 3596), `MDNS` (RFC 6762), and `DHCP` (RFC 2131 DHCPv4 / RFC 8415 DHCPv6)
- **Precision Time Synchronization**: `NTP` (RFC 5905) and `PTP` (IEEE 1588v2 Precision Time Protocol)
- **AAA & Network Access Security**: `RADIUS` (RFC 2865 / RFC 2866 / RFC 5176) and `TACACS` (RFC 8907 TACACS+)
- **Logging & Flow Telemetry**: `SYSLOG` (RFC 5424), `NETFLOW` (Cisco v5/v9), `IPFIX` (RFC 7011 v10), and `SFLOW` (sFlow v5)
- **File Transfer, Remote CLI & Registry Lookup**: `TFTP` (RFC 1350), `FTP` (RFC 959), `SSH` (RFC 4253), `TELNET` (RFC 854), and `WHOIS` (RFC 3912)

---

## 1. Protocol Architecture & RFC Matrix

| Protocol | Keyword | Standard RFC / IEEE | Default Transport & Port | Corpus Directory | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DNS** | `DNS` | RFC 1035, RFC 3596 | UDP / TCP `53` | [`examples/l7/dns/`](../examples/l7/dns) | Recursive/authoritative `A`, `AAAA`, `MX`, `SRV`, `TXT`, `PTR` resolution |
| **mDNS** | `MDNS` | RFC 6762, RFC 6763 | UDP `5353` (`224.0.0.251` / `ff02::fb`) | [`examples/l7/mdns/`](../examples/l7/mdns) | Zero-configuration link-local DNS-SD service discovery |
| **DHCP / v6** | `DHCP` | RFC 2131, RFC 8415 | UDP `67`/`68` (v4), `546`/`547` (v6) | [`examples/l7/dhcp/`](../examples/l7/dhcp) | DORA (`DISCOVER`/`OFFER`/`REQUEST`/`ACK`) & SARR (`SOLICIT`/`ADVERTISE`/`REPLY`) |
| **NTPv4** | `NTP` | RFC 5905 | UDP `123` | [`examples/l7/ntp/`](../examples/l7/ntp) | Stratum clock hierarchy synchronization (`STRATUM`, `REFID`, `TX_TIMESTAMP`) |
| **PTPv2** | `PTP` | IEEE 1588-2008 (v2) | UDP `319` (Event), `320` (General) | [`examples/l7/ptp/`](../examples/l7/ptp) | Hardware nanosecond clock sync (`SYNC`, `FOLLOW_UP`, `DELAY_REQ`, `ANNOUNCE`) |
| **RADIUS** | `RADIUS` | RFC 2865, RFC 2866 | UDP `1812` (Auth), `1813` (Acct) | [`examples/l7/radius/`](../examples/l7/radius) | 802.1X / VPN AAA (`ACCESS_REQUEST`, `ACCESS_ACCEPT`, `ACCOUNTING_REQUEST`) |
| **TACACS+** | `TACACS` | RFC 8907 | TCP `49` | [`examples/l7/tacacs/`](../examples/l7/tacacs) | Device administration AAA (`AUTHEN`, `AUTHOR`, `ACCT`, `SESSION_ID`) |
| **Syslog** | `SYSLOG` | RFC 5424 | UDP / TCP `514` | [`examples/l7/syslog/`](../examples/l7/syslog) | Structured SIEM event logging (`FACILITY`, `SEVERITY`, `PRI`, `APP`, `MSG`) |
| **NetFlow** | `NETFLOW`| Cisco NetFlow v5/v9 | UDP `2055` | [`examples/l7/netflow/`](../examples/l7/netflow) | Router flow accounting (`SRCIP`, `DSTIP`, `PROTO`, `PACKETS`, `OCTETS`) |
| **IPFIX** | `IPFIX` | RFC 7011 (NetFlow v10)| UDP / TCP `4739` | [`examples/l7/ipfix/`](../examples/l7/ipfix) | IETF template flow export (`DOMAIN_ID`, `SRCIP`, `DSTIP`, `PACKETS`, `OCTETS`) |
| **sFlow** | `SFLOW` | sFlow v5 | UDP `6343` | [`examples/l7/sflow/`](../examples/l7/sflow) | Switch ASIC packet sampling (`AGENT_IP`, `SUB_AGENT_ID`, `UPTIME`, `SAMPLES`) |
| **TFTP** | `TFTP` | RFC 1350 | UDP `69` | [`examples/l7/tftp/`](../examples/l7/tftp) | PXE boot & firmware transfer (`RRQ`, `WRQ`, `FILENAME`, `MODE`, `BLOCK`) |
| **FTP** | `FTP` | RFC 959, RFC 2428 | TCP `21` | [`examples/l7/ftp/`](../examples/l7/ftp) | File transfer control channel (`CMD`, `ARG`, `CODE`, `REPLY`) |
| **SSHv2** | `SSH` | RFC 4253 | TCP `22` | [`examples/l7/ssh/`](../examples/l7/ssh) | Encrypted remote shell (`BANNER`, `KEXINIT`, `NEWKEYS`, `MSG_CODE`, `COOKIE`) |
| **Telnet** | `TELNET` | RFC 854, RFC 855 | TCP `23` | [`examples/l7/telnet/`](../examples/l7/telnet) | IAC option negotiation (`WILL`, `WONT`, `DO`, `DONT`, `OPTION`, `DATA`) |
| **WHOIS** | `WHOIS` | RFC 3912 | TCP `43` | [`examples/l7/whois/`](../examples/l7/whois) | Domain & ASN registry lookup (`QUERY`, `RESPONSE`, `DOMAIN`, `REGISTRAR`) |

---

## 2. Naming & Dynamic Address Assignment (`DNS`, `MDNS`, `DHCP`)

### 2.1 Canonical `DNS`, `MDNS`, and `DHCP` Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`DNS` / `MDNS`** | `QUERY` / `RESPONSE` | Bare flag (0-arg) | Sets DNS QR bit (`0` = Query, `1` = Response) |
| **`DNS` / `MDNS`** | `TXID <u32>` | `u32` (`0..65535`) | 16-bit DNS Transaction ID (`0` default for mDNS) |
| **`DNS` / `MDNS`** | `QNAME "<domain>"` | Quoted string | Target domain or service name (e.g. `"api.corp.example.com"`) |
| **`DNS` / `MDNS`** | `QTYPE "<type>"` | String or ident | Record type (`"A"`, `"AAAA"`, `"CNAME"`, `"MX"`, `"TXT"`, `"SRV"`, `"PTR"`, `"SOA"`) |
| **`DNS` / `MDNS`** | `RDATA "<value>"` | Quoted string | Resource Record answer data in `RESPONSE` packets |
| **`DNS` / `MDNS`** | `RCODE <u32>` / `ANS_TTL <u32>` | `u32`, `u32` | Response Code (`0` = NOERROR, `3` = NXDOMAIN) and Answer TTL in seconds |
| **`DHCP` (v4)** | `DISCOVER` / `OFFER` / `REQUEST` / `ACK` / `NAK` / `RELEASE` | Bare flag (0-arg) | DHCPv4 Option 53 Message Type on dynamic UDP ports `68`/`67` |
| **`DHCP` (v6)** | `SOLICIT` / `ADVERTISE` / `REQUEST` / `REPLY` | Bare flag (0-arg) | RFC 8415 DHCPv6 Message Type on dynamic UDP ports `546`/`547` |
| **`DHCP`** | `XID <u32>` / `TXID <u32>` | `u32` | 32-bit DHCPv4 Transaction ID or 24-bit DHCPv6 Transaction ID |
| **`DHCP`** | `CIADDR <ip>` / `YIADDR <ip>` / `SIADDR <ip>` / `GIADDR <ip>` | IP literal | Client IP, Your (Assigned) IP, Next Server IP, and Relay Agent IP |
| **`DHCP`** | `CHADDR <mac>` / `HOSTNAME "<str>"` / `DOMAIN "<str>"` | 48-bit MAC, String | Client MAC (v4 `chaddr` / v6 Option 1 DUID-LL), Option 12 Hostname, Option 15 Domain |
| **`DHCP`** | `SERVER_ID <ip>` / `SUBNET_MASK <ip>` / `ROUTER <ip>` / `DNS_SERVER <ip>` | IP literal | DHCP Options 54 (Server ID), 1 (Subnet Mask), 3 (Router), and 6/23 (DNS Server) |
| **`DHCP`** | `LEASE_TIME <u32>` | `u32` | DHCP Option 51 (v4) / IA_NA IAADDR (v6) IP Address Lease Time in seconds |

#### Wire Encoding & Dynamic Return-Tuple Invariants (`DNS`, `MDNS`, `DHCP`)
- **`DNS` (`QUERY` / `RESPONSE`, RFC 1035 / RFC 3596)**: Encodes a 12-byte big-endian header (`TXID`, 16-bit `Flags` with `QR=0` for `QUERY` or `QR=1` for `RESPONSE` plus `RCODE`, `QDCOUNT=1`, `ANCOUNT=0/1`, `NSCOUNT=0`, `ARCOUNT=0`), DNS length-prefixed label encoding of `QNAME`, 2-byte `QTYPE` (`A=1`, `NS=2`, `CNAME=5`, `SOA=6`, `PTR=12`, `MX=15`, `TXT=16`, `AAAA=28`, `SRV=33`, `AXFR=252`, `ANY=255`), and `QCLASS=1` (`IN`). When `RESPONSE` is set, appends an Answer Resource Record (`0xC00C` name compression pointer, `TYPE`, `CLASS=1`, 4-byte `ANS_TTL`, `RDLENGTH`, and parsed IP/domain/text `RDATA`). When `TRANSPORT TCP` is specified, prefixes the DNS message with a 2-byte big-endian byte length per RFC 1035 §4.2.2.
- **`MDNS` (RFC 6762 Multicast IP, MAC & Port `5353`)**: `build_mdns_payload` returns `(payload, target_ip, 5353)` which `src/backend/l7_dispatch.rs` preserves verbatim:
  - Automatically binds UDP source and destination port **`5353`** (with default `TXID 0` per RFC 6762).
  - Automatically sets the destination IP to the link-local mDNS multicast group **`224.0.0.251`** (IPv4) or **`ff02::fb`** (IPv6).
  - Automatically derives the destination Ethernet multicast MAC per RFC 1112 (**`01:00:5e:00:00:fb`** for IPv4) or RFC 2464 (**`33:33:00:00:00:fb`** for IPv6) when no explicit L2 `DST_MAC` override is present.
- **`DHCP` Dynamic UDP Ports & `CHADDR` in DHCPv6 DUID-LL**: `build_dhcp_payload` returns `(pkt, sport, dport)` preserved by `l7_dispatch.rs`:
  - **DHCPv4 (RFC 2131)**: Dynamically assigns UDP ports **`(68, 67)`** for client-to-server frames (`DISCOVER`, `REQUEST`, `RELEASE`) and **`(67, 68)`** for server-to-client frames (`OFFER`, `ACK`, `NAK`). Serializes a 240-byte BOOTP header (`op`, `htype=1`, `hlen=6`, `xid`, `ciaddr`, `yiaddr`, `siaddr`, `giaddr`, 16-byte `chaddr` populated from `CHADDR <mac>`) followed by Magic Cookie `0x63825363` and TLV options (`53`, `1`, `3`, `6`, `51`, `54`, `12`, `15`, `255`).
  - **DHCPv6 (RFC 8415)**: Dynamically assigns UDP ports **`(546, 547)`** for client-to-server frames (`SOLICIT`, `REQUEST`) and **`(547, 546)`** for server-to-client frames (`ADVERTISE`, `REPLY`). Serializes a 4-byte header (`[msg_type(1B), txid(3B)]`) followed by Option `1` (`OPTION_CLIENTID`, `0x0001`), which encodes `CHADDR <mac>` inside a 10-byte **DUID-LL** (DUID Type `3` = `0x0003`, Hardware Type `1` = `0x0001` Ethernet, plus the 6-byte MAC address), alongside Option `2` (`OPTION_SERVERID`), Option `3` (`OPTION_IA_NA` + `OPTION_IAADDR`), Option `23` (`OPTION_DNS_SERVERS`), and Option `39` (`OPTION_CLIENT_FQDN`).

> **Important Syntax Rule**: In `DNS` and `MDNS`, `QUERY` and `RESPONSE` are 0-argument flags. Always specify the domain name with `QNAME "<domain>"` (never `DNS QUERY "<domain>"`), and specify `QTYPE` as a string or identifier (`QTYPE "A"`, `QTYPE "AAAA"`, `QTYPE "PTR"`).

### 2.2 Verified `DNS`, `MDNS`, and `DHCP` (v4 DORA + v6 SARR) Example

```frameassembly
// PROMPT: Enterprise DHCPv4 DORA lease allocation, DHCPv6 SARR assignment, DNS A/AAAA resolution, and mDNS zero-conf discovery.
// TOKENS: HOST, IP, MAC, FLOW, DHCP, DISCOVER, OFFER, REQUEST, ACK, RELEASE, SOLICIT, ADVERTISE, REPLY, CIADDR, YIADDR, SIADDR, CHADDR, HOSTNAME, SUBNET_MASK, ROUTER, DNS_SERVER, LEASE_TIME, DNS, MDNS, QUERY, RESPONSE, TXID, QNAME, QTYPE, RDATA, RCODE, ANS_TTL, TRANSPORT, TCP, WAIT, COMPILE

// INSTRUCTION: Declare IPv4 client workstation and infrastructure server (DHCP + DNS).
HOST client_v4 {
    IP 192.168.20.100
    MAC 00:50:56:20:00:64
}

// INSTRUCTION: Declare the IPv4 DHCP/DNS infrastructure appliance.
HOST infra_srv_v4 {
    IP 192.168.20.1
    MAC 00:50:56:20:00:01
}

// INSTRUCTION: Declare IPv6 client and DHCPv6/DNSv6 server.
HOST client_v6 {
    IP 2001:db8:20::100
    MAC 00:50:56:62:00:64
}

// INSTRUCTION: Declare the IPv6 DHCPv6/DNSv6 server.
HOST infra_srv_v6 {
    IP 2001:db8:20::1
    MAC 00:50:56:62:00:01
}

// INSTRUCTION: Define DHCPv4 DORA lease lifecycle, DNS UDP/TCP queries, and mDNS service discovery.
FLOW dhcpv4_dns_mdns_flow(c, s) {
    c -> s DHCP DISCOVER CHADDR 00:50:56:20:00:64 HOSTNAME "eng-ws-01" WAIT 2ms
    c <- s DHCP OFFER YIADDR 192.168.20.100 SIADDR 192.168.20.1 CHADDR 00:50:56:20:00:64 SUBNET_MASK 255.255.255.0 ROUTER 192.168.20.1 DNS_SERVER 192.168.20.1 LEASE_TIME 86400 WAIT 2ms
    c -> s DHCP REQUEST CIADDR 192.168.20.100 YIADDR 192.168.20.100 SIADDR 192.168.20.1 CHADDR 00:50:56:20:00:64 HOSTNAME "eng-ws-01" WAIT 2ms
    c <- s DHCP ACK YIADDR 192.168.20.100 SIADDR 192.168.20.1 CHADDR 00:50:56:20:00:64 SUBNET_MASK 255.255.255.0 ROUTER 192.168.20.1 DNS_SERVER 192.168.20.1 LEASE_TIME 86400 WAIT 2ms
    c -> s DNS QUERY TXID 1010 QNAME "git.corp.example.com" QTYPE "A" WAIT 1ms
    c <- s DNS RESPONSE TXID 1010 QNAME "git.corp.example.com" QTYPE "A" RDATA "192.168.20.55" RCODE 0 ANS_TTL 300 WAIT 1ms
    c -> s TRANSPORT TCP DNS QUERY TXID 1011 QNAME "corp.example.com" QTYPE "AXFR" WAIT 2ms
    c -> s MDNS QUERY QNAME "_ipp._tcp.local" QTYPE "PTR" WAIT 2ms
    c <- s MDNS RESPONSE QNAME "_ipp._tcp.local" QTYPE "PTR" RDATA "LaserJet-Floor3._ipp._tcp.local" ANS_TTL 120 WAIT 2ms
    c -> s DHCP RELEASE CIADDR 192.168.20.100 CHADDR 00:50:56:20:00:64 WAIT 1ms
}

// INSTRUCTION: Define DHCPv6 Solicit-Advertise-Request-Reply (SARR) and AAAA DNS resolution over IPv6.
FLOW dhcpv6_sarr_and_aaaa(c6, s6) {
    c6 -> s6 DHCP SOLICIT HOSTNAME "eng-ws-01-v6" WAIT 2ms
    c6 <- s6 DHCP ADVERTISE YIADDR 2001:db8:20::100 DNS_SERVER 2001:db8:20::1 LEASE_TIME 86400 WAIT 2ms
    c6 -> s6 DHCP REQUEST HOSTNAME "eng-ws-01-v6" WAIT 2ms
    c6 <- s6 DHCP REPLY YIADDR 2001:db8:20::100 DNS_SERVER 2001:db8:20::1 LEASE_TIME 86400 WAIT 2ms
    c6 -> s6 DNS QUERY TXID 2020 QNAME "git.corp.example.com" QTYPE "AAAA" WAIT 1ms
    c6 <- s6 DNS RESPONSE TXID 2020 QNAME "git.corp.example.com" QTYPE "AAAA" RDATA "2001:db8:20::55" RCODE 0 ANS_TTL 300 WAIT 1ms
}

// INSTRUCTION: Compile both the IPv4 and IPv6 naming and address assignment flows.
COMPILE {
    dhcpv4_dns_mdns_flow(client_v4, infra_srv_v4)
    dhcpv6_sarr_and_aaaa(client_v6, infra_srv_v6)
}
```

---

## 3. Precision Time Synchronization (`NTP` & `PTP`)

### 3.1 Canonical `NTP` (RFC 5905) and `PTP` (IEEE 1588v2) Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`NTP`** | `LI <0..3>` / `VN <1..4>` / `MODE <1..7>` | `u32` | Leap Indicator (`0`), Version (`4`), Mode (`3`=Client, `4`=Server, `5`=Broadcast) |
| **`NTP`** | `STRATUM <0..16>` | `u32` | Clock stratum (`1` = Primary GPS/Atomic, `2..15` = Secondary, `16` = Unsynced) |
| **`NTP`** | `POLL <u32>` / `PRECISION <i32>` | `u32`, `i32` | Poll interval exponent (e.g. `6` = $64$s) and signed clock precision (e.g. `236`) |
| **`NTP`** | `REFID "<str>"` / `TX_TIMESTAMP <u64>` | String, `u64` | 4-char Reference ID (`"GPS"`, `"PPS"`, `"ATOM"`) and 64-bit NTP transmit timestamp |
| **`PTP`** | `ANNOUNCE` / `SYNC` / `FOLLOW_UP` / `DELAY_REQ` / `DELAY_RESP` | Bare flag (0-arg) | IEEE 1588v2 message type on dynamic UDP port `319` (event) / `320` (general) |
| **`PTP`** | `MSG_TYPE "<str>"` / `VERSION <u32>` | String, `u32` | Explicit message type override and PTP protocol version (`2` default) |
| **`PTP`** | `DOMAIN <u32>` / `SEQ_ID <u32>` / `FLAGS <u32>` | `u32` | PTP domain (`0` default, `24` telecom, `127` SMPTE), sequence ID, and 16-bit flags |
| **`PTP`** | `CLOCK_ID "<str>"` / `SOURCE_PORT_ID <u32>` / `CORRECTION <u64>` | String, `u32`, `u64` | 64-bit EUI-64 Clock Identity, source port number, and 64-bit scaled ns `correctionField` |

#### Wire Encoding & Dynamic Return-Tuple Invariants (`NTP`, `PTP`)
- **`NTP` (RFC 5905)**: Encodes a fixed 48-byte header on UDP port `123` with byte `0` packing `((LI & 0x3) << 6) | ((VN & 0x7) << 3) | (MODE & 0x7)`, `STRATUM`, `POLL`, `PRECISION`, 32-bit Root Delay/Dispersion, 4-byte ASCII `REFID`, and 64-bit big-endian `TX_TIMESTAMP` at bytes `40..48` (plus optional trailing extension/auth `PAYLOAD`).
- **`PTP` Dynamic UDP Port (`319` Event vs. `320` General) & Payload-Inclusive `messageLength`**: `build_ptp_payload` returns `(result, dport)` preserved by `l7_dispatch.rs`:
  - **Dynamic UDP Destination Port**: Routes time-critical **Event** messages (`SYNC` `0x0`, `DELAY_REQ` `0x1`, `PDELAY_REQ` `0x2`, `PDELAY_RESP` `0x3`) to **UDP port `319`**, and **General** messages (`FOLLOW_UP` `0x8`, `DELAY_RESP` `0x9`, `PDELAY_RESP_FOLLOW_UP` `0xA`, `ANNOUNCE` `0xB`, `SIGNALING` `0xC`, `MANAGEMENT` `0xD`) to **UDP port `320`**.
  - **Payload-Inclusive `messageLength`**: The 16-bit big-endian `messageLength` field at bytes `2..4` of the 34-byte IEEE 1588v2 header is computed over the complete PTP PDU (`34-byte header + message-specific body + trailing PAYLOAD bytes` — `44` bytes base for `SYNC`/`DELAY_REQ`/`FOLLOW_UP` with 10B `originTimestamp`, `54` bytes base for `DELAY_RESP` with 10B `receiveTimestamp` + 10B `requestingPortIdentity`, and `64` bytes base for `ANNOUNCE`, plus `payload_bytes.len()`).

### 3.2 Verified `NTP` and `PTP` Example

```frameassembly
// PROMPT: Stratum-1 GPS NTPv4 synchronization and IEEE 1588v2 PTP two-step hardware timestamping exchange.
// TOKENS: HOST, IP, MAC, FLOW, DSCP, NTP, LI, VN, MODE, STRATUM, POLL, PRECISION, REFID, TX_TIMESTAMP, PTP, ANNOUNCE, SYNC, FOLLOW_UP, DELAY_REQ, DELAY_RESP, DOMAIN, SEQ_ID, CLOCK_ID, WAIT, COMPILE

// INSTRUCTION: Declare the Grandmaster Clock / Stratum-1 Time Server.
HOST grandmaster_clock {
    IP 10.158.0.1
    MAC 00:1c:73:00:01:01
}

// INSTRUCTION: Declare the trading engine follower node synchronizing both NTP and PTP.
HOST follower_node {
    IP 10.158.0.50
    MAC 00:1c:73:00:01:50
}

// INSTRUCTION: Define NTPv4 Mode 3/4 exchange and IEEE 1588v2 PTP two-step Sync, Follow_Up, Delay_Req, and Delay_Resp cycle.
FLOW precision_time_sync(gm, sub) {
    sub -> gm DSCP 46 NTP LI 0 VN 4 MODE 3 STRATUM 2 POLL 6 PRECISION 236 REFID "INIT" TX_TIMESTAMP 0xe9b0000100000000 WAIT 1ms
    sub <- gm DSCP 46 NTP LI 0 VN 4 MODE 4 STRATUM 1 POLL 6 PRECISION 232 REFID "GPS" TX_TIMESTAMP 0xe9b0000100001000 WAIT 1ms
    gm -> sub DSCP 46 PTP ANNOUNCE DOMAIN 0 SEQ_ID 500 CLOCK_ID "00:1c:73:ff:fe:00:01:01" WAIT 500us
    gm -> sub DSCP 46 PTP SYNC DOMAIN 0 SEQ_ID 501 CLOCK_ID "00:1c:73:ff:fe:00:01:01" WAIT 100us
    gm -> sub DSCP 46 PTP FOLLOW_UP DOMAIN 0 SEQ_ID 501 CLOCK_ID "00:1c:73:ff:fe:00:01:01" WAIT 200us
    sub -> gm DSCP 46 PTP DELAY_REQ DOMAIN 0 SEQ_ID 501 CLOCK_ID "00:1c:73:ff:fe:00:01:50" WAIT 200us
    gm -> sub DSCP 46 PTP DELAY_RESP DOMAIN 0 SEQ_ID 501 CLOCK_ID "00:1c:73:ff:fe:00:01:01" WAIT 200us
}

// INSTRUCTION: Compile the NTPv4 and IEEE 1588v2 PTP synchronization capture.
COMPILE {
    precision_time_sync(grandmaster_clock, follower_node)
}
```

---

## 4. AAA & Network Access Security (`RADIUS` & `TACACS`)

### 4.1 Canonical `RADIUS` and `TACACS` Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`RADIUS`** | `ACCESS_REQUEST` / `ACCESS_ACCEPT` / `ACCESS_REJECT` / `ACCESS_CHALLENGE` / `ACCOUNTING_REQUEST` / `ACCOUNTING_RESPONSE` | Bare flag (0-arg) | Standard RFC 2865 / 2866 RADIUS packet codes (`1`, `2`, `3`, `11`, `4`, `5`) |
| **`RADIUS`** | `CODE "<str>"` / `ID <u32>` | String, `u32` | Custom RADIUS code (or RFC 5176 CoA / Disconnect) and 1-byte RADIUS Identifier |
| **`RADIUS`** | `USER "<username>"` / `REPLY_MSG "<str>"` | Quoted string | Attribute 1 `User-Name` and Attribute 18 `Reply-Message` |
| **`RADIUS`** | `NAS_IP <ip>` / `FRAMED_IP <ip>` | IPv4 or IPv6 | Attribute 4/95 `NAS-IP(v6)-Address` and Attribute 8/168 `Framed-IP(v6)-Address` |
| **`RADIUS`** | `SERVICE_TYPE <u32>` / `NAS_PORT <u32>` | `u32` | Attribute 6 `Service-Type` (`2` = Framed, `6` = Admin) and Attribute 5 `NAS-Port` |
| **`RADIUS`** | `ACCT_STATUS <u32>` / `ACCT_SESSION_ID "<str>"` | `u32`, String | Attribute 40 `Acct-Status-Type` (`1`=Start, `2`=Stop) and Attribute 44 `Acct-Session-Id` |
| **`TACACS`** | `AUTHEN` / `AUTHOR` / `ACCT` or `TYPE <AUTHEN\|AUTHOR\|ACCT>` | Keyword | RFC 8907 TACACS+ packet type (`1` = Authentication, `2` = Authorization, `3` = Accounting) |
| **`TACACS`** | `VERSION <u32>` / `SEQ <u32>` / `FLAGS <u32>` | `u32` | TACACS+ header version (`0xc0`/`0xc1`), sequence number, and encryption flags |
| **`TACACS`** | `SESSION_ID <u64>` | `u64` | 32-bit TACACS+ session identifier |
| **`TACACS`** | `USER "<username>"` / `DATA "<str>"` | Quoted string | TACACS+ principal username and command/attribute payload |

#### Wire Encoding & Dynamic Return-Tuple Invariants (`RADIUS`, `TACACS`)
- **`RADIUS` Dynamic UDP Port (`1812` Auth vs. `1813` Accounting) & Dual-Stack IP Attributes**: `build_radius_payload` returns `(pkt, dport)` preserved by `l7_dispatch.rs`:
  - **Dynamic UDP Destination Port**: Routes Authentication/Authorization messages (`ACCESS_REQUEST` `1`, `ACCESS_ACCEPT` `2`, `ACCESS_REJECT` `3`, `ACCESS_CHALLENGE` `11`) to **UDP port `1812`** (RFC 2865), and Accounting messages (`ACCOUNTING_REQUEST` `4`, `ACCOUNTING_RESPONSE` `5`) to **UDP port `1813`** (RFC 2866).
  - **20-Byte Header & Dual-Stack `NAS_IP` / `FRAMED_IP` Encoding**: Serializes `[Code(1B), ID(1B), Length(2B BE), Authenticator(16B)]` plus TLV attributes. When `NAS_IP` or `FRAMED_IP` is an **IPv4** address, emits RFC 2865 Attribute `4` (`NAS-IP-Address`, 6 bytes `[4, 6, a, b, c, d]`) and Attribute `8` (`Framed-IP-Address`, 6 bytes `[8, 6, a, b, c, d]`). When `NAS_IP` or `FRAMED_IP` is an **IPv6** address, automatically emits RFC 3162 Attribute `95` (`NAS-IPv6-Address`, 18 bytes `[95, 18, <16B IPv6>]`) and Attribute `168` (`Framed-IPv6-Address`, 18 bytes `[168, 18, <16B IPv6>]`).
- **`TACACS` (RFC 8907 TACACS+)**: Encodes a 12-byte big-endian header on TCP port `49` (`[version(1B), type(1B: 1=AUTHEN, 2=AUTHOR, 3=ACCT), seq_no(1B), flags(1B), session_id(4B BE), length(4B BE)]`) followed by the structured body containing `USER` and `DATA` / `PAYLOAD`.

### 4.2 Verified `RADIUS` and `TACACS` Example

```frameassembly
// PROMPT: Enterprise AAA verification covering RADIUS 802.1X authentication/accounting and TACACS+ CLI command authorization.
// TOKENS: HOST, IP, MAC, FLOW, RADIUS, ACCESS_REQUEST, ACCESS_CHALLENGE, ACCESS_ACCEPT, ACCOUNTING_REQUEST, ACCOUNTING_RESPONSE, USER, NAS_IP, SERVICE_TYPE, FRAMED_IP, TACACS, AUTHEN, AUTHOR, ACCT, SESSION_ID, DATA, WAIT, COMPILE

// INSTRUCTION: Declare the Network Access Server (NAS) switch.
HOST nas_switch {
    IP 10.60.1.10
    MAC 00:1c:73:60:01:10
}

// INSTRUCTION: Declare the centralized AAA Policy Server (RADIUS + TACACS+).
HOST aaa_policy_srv {
    IP 10.60.1.200
    MAC 00:50:56:60:01:c8
}

// INSTRUCTION: Define RADIUS EAP challenge-response authentication, accounting start, and TACACS+ CLI command audit.
FLOW radius_and_tacacs_aaa(nas, aaa) {
    nas -> aaa RADIUS ACCESS_REQUEST USER "alice@corp.example.com" NAS_IP 10.60.1.10 SERVICE_TYPE 2 WAIT 2ms
    nas <- aaa RADIUS ACCESS_CHALLENGE USER "alice@corp.example.com" NAS_IP 10.60.1.10 WAIT 2ms
    nas -> aaa RADIUS ACCESS_REQUEST USER "alice@corp.example.com" NAS_IP 10.60.1.10 SERVICE_TYPE 2 WAIT 2ms
    nas <- aaa RADIUS ACCESS_ACCEPT USER "alice@corp.example.com" NAS_IP 10.60.1.10 SERVICE_TYPE 2 FRAMED_IP 10.60.20.55 WAIT 2ms
    nas -> aaa RADIUS ACCOUNTING_REQUEST USER "alice@corp.example.com" NAS_IP 10.60.1.10 FRAMED_IP 10.60.20.55 WAIT 2ms
    nas <- aaa RADIUS ACCOUNTING_RESPONSE USER "alice@corp.example.com" NAS_IP 10.60.1.10 WAIT 2ms
    nas -> aaa TACACS AUTHEN SESSION_ID 900101 USER "netops_admin" PAYLOAD "Interactive-SSH-Login" WAIT 2ms
    nas <- aaa TACACS AUTHEN SESSION_ID 900101 USER "netops_admin" PAYLOAD "AUTHEN_STATUS_PASS" WAIT 2ms
    nas -> aaa TACACS AUTHOR SESSION_ID 900102 USER "netops_admin" PAYLOAD "cmd=configure;cmd-arg=terminal" WAIT 2ms
    nas <- aaa TACACS AUTHOR SESSION_ID 900102 USER "netops_admin" PAYLOAD "AUTHOR_STATUS_PASS_ADD" WAIT 2ms
    nas -> aaa TACACS ACCT SESSION_ID 900103 USER "netops_admin" PAYLOAD "task_id=42;service=shell;cmd=write memory" WAIT 2ms
}

// INSTRUCTION: Compile the RADIUS and TACACS+ AAA capture.
COMPILE {
    radius_and_tacacs_aaa(nas_switch, aaa_policy_srv)
}
```

---

## 5. Logging & Flow Telemetry (`SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`)

### 5.1 Canonical Telemetry Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`SYSLOG`** | `FACILITY <0..23>` / `SEVERITY <0..7>` / `PRI <0..191>` | `u32` | RFC 5424 Facility (`4` = auth, `16` = local0), Severity (`0` = emerg .. `6` = info), or raw `PRI` |
| **`SYSLOG`** | `VERSION <u32>` / `TIMESTAMP "<str>"` | `u32`, String | RFC 5424 version (`1` default) and ISO 8601 timestamp |
| **`SYSLOG`** | `HOSTNAME "<str>"` / `APP "<str>"` / `PROCID "<str>"` / `MSGID "<str>"` | Quoted string | Originating FQDN, application name, process ID, and message ID |
| **`SYSLOG`** | `MSG "<str>"` | Quoted string | RFC 5424 structured log text |
| **`NETFLOW`**| `VERSION <u32>` / `COUNT <u32>` / `SEQ <u32>` / `UPTIME <u32>` | `u32` | NetFlow header version (`5` default), record count, sequence number, and sysUptime |
| **`NETFLOW`**| `SRCIP <ip>` / `DSTIP <ip>` / `SRCPORT <u32>` / `DSTPORT <u32>` / `PROTO <u32>` | IP, `u32` | Flow 5-tuple source/destination IP, L4 ports, and IP protocol number |
| **`NETFLOW`**| `PACKETS <u32>` / `OCTETS <u32>` / `TCP_FLAGS <u32>` / `TOS <u32>` | `u32` | Cumulative packet and byte counters, cumulative TCP flags, and IPv4 ToS byte |
| **`IPFIX`** | `DOMAIN_ID <u32>` / `SEQ <u32>` / `SET_ID <u32>` / `EXPORT_TIME <u32>` | `u32` | RFC 7011 Observation Domain ID, sequence number, Set ID (`256` default), and export epoch |
| **`IPFIX`** | `SRCIP <ip>` / `DSTIP <ip>` / `SRCPORT <u32>` / `DSTPORT <u32>` / `PROTO <u32>` / `PACKETS <u32>` / `OCTETS <u32>` | IP, `u32` | Dual-stack IPv4/IPv6 flow record fields and counters |
| **`SFLOW`** | `VERSION <u32>` / `AGENT_IP <ip>` / `SUB_AGENT_ID <u32>` / `SEQ <u32>` / `UPTIME <u32>` / `SAMPLES <u32>` | IP, `u32` | sFlow v5 datagram header fields (`VERSION 5`, IPv4/IPv6 `AGENT_IP`, uptime ms, sample count) |
| **`SFLOW`** | `SAMPLING_RATE <u32>` / `SAMPLE_POOL <u32>` / `DROPS <u32>` / `INPUT_IF <u32>` / `OUTPUT_IF <u32>` | `u32` | sFlow v5 32-byte Flow Sample header parameters and interface indices |

#### Wire Encoding & Length Invariants (`SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`)
- **`SYSLOG` (RFC 5424)**: Serializes `<PRI>1 <TIMESTAMP> <HOSTNAME> <APP> <PROCID> <MSGID> - <MSG>` over UDP/TCP port `514`, computing `PRI = (FACILITY * 8) + SEVERITY` when `PRI` is not explicitly overridden.
- **`NETFLOW` (Cisco NetFlow v5)**: Serializes a 24-byte NetFlow v5 header (`version = 5`, `count = 1`, `sys_uptime`, `unix_secs`, `unix_nsecs`, `flow_sequence`, `engine_type`, `engine_id`, `sampling_interval`) followed by a 48-byte big-endian flow record (`SRCIP`, `DSTIP`, `nexthop`, `input`, `output`, `PACKETS`, `OCTETS`, `first`, `last`, `SRCPORT`, `DSTPORT`, `tcp_flags`, `PROTO`, `tos`, `src_as`, `dst_as`, `src_mask`, `dst_mask`) on UDP port `2055`.
- **`IPFIX` Payload-Inclusive `set_len` & `total_len` (RFC 7011)**:
  - Encodes a 16-byte IPFIX Message Header (`version = 0x000a`, `total_len`, `export_time`, `seq_num`, `domain_id`) followed by a 4-byte Set Header (`set_id = 256` default, `set_len`), dual-stack IPv4 (4B IPs) or IPv6 (16B IPs) flow record fields (`SRCIP`, `DSTIP`, `PACKETS`, `OCTETS`, `SRCPORT`, `DSTPORT`, `PROTO`), and any trailing `PAYLOAD` bytes on port `4739`.
  - Both `set_len` (`4 + record.len() + payload_bytes.len()`) and `total_len` (`16 + set_len`) **include `payload_bytes.len()`** so Wireshark's IPFIX dissector never reports truncated or trailing garbage bytes.
- **`SFLOW` Full 32-Byte (8 `u32` Fields) Flow Sample Header (sFlow v5)**:
  - Following the sFlow v5 Datagram Header (`version = 5`, `address_type = 1` for IPv4 or `2` for IPv6, `AGENT_IP`, `SUB_AGENT_ID`, `SEQ`, `UPTIME`, `num_samples`) and the 8-byte Sample Data TLV header (`sample_type = 1` Flow Sample, `sample_len`), encodes the complete **32-byte (8 big-endian `u32` fields) sFlow v5 Flow Sample header**:
    1. `sequence_number` (`u32`)
    2. `source_id` (`u32`, `0x00000001` default)
    3. `sampling_rate` (`u32`, `SAMPLING_RATE`, default `512`)
    4. `sample_pool` (`u32`, `SAMPLE_POOL`)
    5. `drops` (`u32`, `DROPS`)
    6. `input_if` (`u32`, `INPUT_IF`)
    7. `output_if` (`u32`, `OUTPUT_IF`)
    8. `num_flow_records` (`u32`, `1`)
  - Followed by the Raw Packet Header flow record (`flow_format = 1`, `flow_data_len`, `protocol = 1` Ethernet, `frame_length`, `stripped = 4`, `header_length`, and 4-byte XDR-padded sampled frame bytes) on UDP port `6343`.

### 5.2 Verified `SYSLOG`, `NETFLOW`, `IPFIX`, and `SFLOW` Example

```frameassembly
// PROMPT: NOC observability pipeline exporting RFC 5424 Syslog alerts, NetFlow v9 records, IPFIX v10 templates, and sFlow v5 ASIC packet samples.
// TOKENS: HOST, IP, MAC, FLOW, SYSLOG, FACILITY, SEVERITY, PRI, HOSTNAME, APP, PROCID, MSG, NETFLOW, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, IPFIX, DOMAIN_ID, SFLOW, AGENT_IP, SUB_AGENT_ID, UPTIME, SAMPLES, WAIT, COMPILE

// INSTRUCTION: Declare Core Border Router exporting logs and flow telemetry.
HOST border_exporter {
    IP 10.250.10.1
    MAC 00:1c:73:fa:10:01
}

// INSTRUCTION: Declare the SIEM & Flow Telemetry Ingestion Cluster.
HOST telemetry_ingest {
    IP 10.250.10.100
    MAC 00:50:56:fa:10:64
}

// INSTRUCTION: Export RFC 5424 Syslog event, NetFlow record, IPFIX observation domain record, and sFlow datagram.
FLOW noc_telemetry_export(rtr, collector) {
    rtr -> collector SYSLOG FACILITY 16 SEVERITY 4 PRI 132 HOSTNAME "border-rtr-01" APP "bgpd" PROCID "1842" MSG "BGP-5-ADJCHANGE: neighbor 198.51.100.1 Up" WAIT 1ms
    rtr -> collector NETFLOW SRCIP 198.51.100.25 DSTIP 203.0.113.80 PROTO 6 PACKETS 15400 OCTETS 21560000 WAIT 1ms
    rtr -> collector IPFIX DOMAIN_ID 4001 SRCIP 198.51.100.25 DSTIP 203.0.113.80 PROTO 6 PACKETS 15400 OCTETS 21560000 WAIT 1ms
    rtr -> collector SFLOW AGENT_IP 10.250.10.1 SUB_AGENT_ID 1 UPTIME 86400000 SAMPLES 8 WAIT 1ms
}

// INSTRUCTION: Compile the NOC telemetry export capture.
COMPILE {
    noc_telemetry_export(border_exporter, telemetry_ingest)
}
```

---

## 6. File Transfer, Remote CLI & Registry Lookup (`TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`)

### 6.1 Canonical Modifiers (`TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`)

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`TFTP`** | `RRQ` / `WRQ` / `OPCODE <u32>` | Flag, `u32` | Read Request (`1`), Write Request (`2`), Data (`3`), ACK (`4`), or Error (`5`) on UDP `69` |
| **`TFTP`** | `FILENAME "<str>"` / `MODE "<str>"` | Quoted string | Target file path and transfer mode (`"octet"` or `"netascii"`) |
| **`TFTP`** | `BLOCK <u32>` / `ERRCODE <u32>` / `ERRMSG "<str>"` | `u32`, String | Data/ACK block number (`1..65535`) or TFTP Error code and string |
| **`FTP`** | `CMD "<str>"` / `ARG "<str>"` | Quoted string | FTP client command (`"USER"`, `"PASS"`, `"EPSV"`, `"RETR"`, `"QUIT"`) and argument |
| **`FTP`** | `CODE <u32>` / `REPLY "<str>"` | `u32`, String | 3-digit FTP server response code (`220`, `230`, `229`, `150`, `226`) and text |
| **`SSH`** | `BANNER "<str>"` | Quoted string | RFC 4253 §4.2 identification string (e.g. `"SSH-2.0-OpenSSH_9.8"`, emitted as `<BANNER>\r\n`) |
| **`SSH`** | `KEXINIT` / `NEWKEYS` / `MSG_CODE <u32>` / `MSGCODE <u32>` | Flag, `u32` | RFC 4253 §6 binary packet framing (`20`=`KEXINIT`, `21`=`NEWKEYS`, `30`/`31`=ECDH KEX) |
| **`SSH`** | `COOKIE "<hex_or_str>"` | Quoted string | 16-byte random cookie inside `SSH_MSG_KEXINIT` (`20`) binary packets |
| **`TELNET`** | `WILL <u32>` / `WONT <u32>` / `DO <u32>` / `DONT <u32>` / `OPTION <u32>` | `u32` (`0..255`) | RFC 854 3-byte `0xff <cmd> <opt>` IAC negotiation (`1`=Echo, `3`=SGA, `24`=TTYPE, `31`=NAWS) |
| **`TELNET`** | `CMD <u32>` / `DATA "<str>"` | `u32`, String | Explicit Telnet command byte (`251..254`) and interactive terminal data stream |
| **`WHOIS`** | `QUERY` / `RESPONSE` | Bare flag (0-arg) | Selects client query (`<DOMAIN>\r\n`) or registry server response on TCP port `43` |
| **`WHOIS`** | `DOMAIN "<str>"` / `REGISTRAR "<str>"` | Quoted string | Queried domain/prefix/ASN and authoritative RIR/registrar name included in response banner |

> **Important Syntax Rule**: In `TELNET`, `WILL`, `WONT`, `DO`, `DONT`, and `OPTION` each take an integer option code `<u32>` directly (e.g. `TELNET DO 1 WILL 3`). Never write `WILL OPTION 3`. In `WHOIS`, `QUERY` is a 0-argument flag; always write `WHOIS QUERY DOMAIN "example.com" REGISTRAR "whois.arin.net"`.

### 6.2 Verified `TFTP`, `FTP`, `SSH`, `TELNET`, and `WHOIS` Example

```frameassembly
// PROMPT: Network administration session combining SSHv2 key exchange, Telnet IAC option negotiation, TFTP firmware boot, FTP archive retrieval, and WHOIS ASN lookup.
// TOKENS: HOST, IP, MAC, FLOW, SSH, BANNER, KEXINIT, NEWKEYS, MSG_CODE, TELNET, DO, WILL, DONT, WONT, TFTP, RRQ, FILENAME, MODE, BLOCK, FTP, CMD, ARG, CODE, REPLY, WHOIS, QUERY, RESPONSE, DOMAIN, REGISTRAR, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare the Admin Bastion Workstation.
HOST admin_bastion {
    IP 10.70.1.50
    MAC 00:50:56:70:01:50
}

// INSTRUCTION: Declare the Managed Infrastructure Server hosting SSH, Telnet, TFTP, FTP, and WHOIS services.
HOST managed_srv {
    IP 10.70.1.10
    MAC 00:1c:73:70:01:10
}

// INSTRUCTION: Define SSHv2 handshake, Telnet IAC negotiation, TFTP octet transfer, FTP login/retrieve, and WHOIS query/response.
FLOW remote_admin_and_file_transfer(adm, srv) {
    adm -> srv SSH BANNER "SSH-2.0-OpenSSH_9.8p1" WAIT 1ms
    adm <- srv SSH BANNER "SSH-2.0-Cisco-2.0" WAIT 1ms
    adm -> srv SSH KEXINIT PAYLOAD "KEX_CURVE25519_SHA256" WAIT 1ms
    adm <- srv SSH KEXINIT PAYLOAD "KEX_CURVE25519_SHA256" WAIT 1ms
    adm -> srv SSH MSG_CODE 30 PAYLOAD "CURVE25519_SHA256_EPHEMERAL_PUBKEY" WAIT 1ms
    adm <- srv SSH NEWKEYS WAIT 1ms
    adm <- srv TELNET DO 24 WILL 1 OPTION 3 PAYLOAD "User Access Verification\r\nUsername: " WAIT 1ms
    adm -> srv TELNET WILL 24 DO 3 DONT 31 WONT 32 PAYLOAD "admin\r\n" WAIT 1ms
    adm -> srv TFTP RRQ FILENAME "sonic-broadcom-202511.bin" MODE "octet" WAIT 1ms
    adm <- srv TFTP BLOCK 1 PAYLOAD "FIRMWARE_IMAGE_BLOCK_0001_512B" WAIT 1ms
    adm <- srv FTP CODE 220 REPLY "vsFTPd 3.0.5 Ready" WAIT 1ms
    adm -> srv FTP CMD "USER" ARG "backup_ops" WAIT 1ms
    adm <- srv FTP CODE 230 REPLY "Login successful" WAIT 1ms
    adm -> srv FTP CMD "RETR" ARG "running-config.cfg" WAIT 1ms
    adm <- srv FTP CODE 226 REPLY "Transfer complete" WAIT 1ms
    adm -> srv WHOIS QUERY DOMAIN "AS65001" REGISTRAR "whois.arin.net" WAIT 1ms
    adm <- srv WHOIS RESPONSE DOMAIN "AS65001" REGISTRAR "whois.arin.net" PAYLOAD "ASNumber: 65001\r\nASName: ENTERPRISE-CORE-ASN\r\n" WAIT 1ms
}

// INSTRUCTION: Compile the remote administration and file transfer suite.
COMPILE {
    remote_admin_and_file_transfer(admin_bastion, managed_srv)
}
```
