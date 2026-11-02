# Layer 7 Core Infrastructure, Precision Time, AAA & Flow Telemetry Reference

Standing up `bind`, `kea-dhcp4`/`kea-dhcp6`, FreeRADIUS/Cisco ISE, a Stratum-1 NTP/PTP grandmaster, and waiting for a hardware router to export NetFlow/IPFIX/sFlow templates just to verify a firewall rule, SIEM parser, or DNS sinkhole takes hours of lab plumbing. FrameAssembly solves that with a few lines of `.fasm` code and two CLI commands:

```bash
# 1. Compile the .fasm code into a deterministic .pcap capture
frameassembly infra.fasm -o infra.pcap

# 2. Replay the traffic onto the network interface (or open infra.pcap in Wireshark / Suricata)
sudo tcpreplay -i eth0 infra.pcap
```

This guide covers all **11 core network infrastructure, precision clock synchronization, AAA access security, centralized logging, and flow telemetry protocols** across IPv4 and IPv6:
* **Naming & Address Assignment (3 Protocols):** `DNS`, `MDNS`, `DHCP`
* **Precision Time Synchronization (2 Protocols):** `NTP`, `PTP`
* **AAA Access & Device Administration (2 Protocols):** `RADIUS`, `TACACS`
* **Centralized Logging & Flow Telemetry (4 Protocols):** `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`

> **Where to Find `SSH`, `TELNET`, `TFTP`, `FTP`, and `WHOIS`:**
> Remote CLI, file transfer, and registry protocols (`TFTP`, `FTP`, `SSH`, `TELNET`, and `WHOIS`) are covered in **[Layer 7 Web, Cloud, VoIP & Remote Access Reference (`l7_web_and_cloud.md`)](l7_web_and_cloud.md)**. For SNMP polling and traps (`SNMP1`, `SNMP2`, `SNMP3`), see **[Layer 7 SNMP Reference (`l7_snmp.md`)](l7_snmp.md)**.

---

## Quick Protocol & Smart Port Matrix

Every protocol works with **zero mandatory sub-keywords** (emitting RFC-compliant default headers and ports) and supports explicit field overrides in any order. Several infrastructure protocols also adjust their UDP ports or multicast destination addresses automatically based on message type or IP version:

| Protocol | `.fasm` Keyword | RFC / Standard | Default Transport & Smart Port Routing |
| :--- | :--- | :--- | :--- |
| **Domain Name System** | `DNS` | RFC 1035, RFC 3596 | **UDP `53`** (default) or **TCP `53`** (with `TRANSPORT TCP`, auto-prepending the 2-byte RFC 1035 length header) |
| **Multicast DNS** | `MDNS` | RFC 6762, RFC 6763 | **UDP `5353`**; automatically targets multicast `224.0.0.251` (`01:00:5e:00:00:fb`) on IPv4 or `ff02::fb` (`33:33:00:00:00:fb`) on IPv6 |
| **DHCPv4 / DHCPv6** | `DHCP` | RFC 2131, RFC 8415 | **DHCPv4:** UDP `68 -> 67` (client) / `67 -> 68` (server); **DHCPv6:** UDP `546 -> 547` (client) / `547 -> 546` (server) |
| **Network Time Protocol** | `NTP` | RFC 5905 (NTPv4) | **UDP `123`** |
| **Precision Time Protocol** | `PTP` | IEEE 1588v2 | **UDP `319` (Event port):** `SYNC`, `DELAY_REQ`; **UDP `320` (General port):** `FOLLOW_UP`, `DELAY_RESP`, `ANNOUNCE` |
| **RADIUS AAA** | `RADIUS` | RFC 2865, RFC 2866 | **UDP `1812` (Authentication):** `ACCESS_REQUEST`, `ACCESS_ACCEPT`, `ACCESS_REJECT`, `ACCESS_CHALLENGE`; **UDP `1813` (Accounting):** `ACCOUNTING_REQUEST`, `ACCOUNTING_RESPONSE` |
| **TACACS+ AAA** | `TACACS` | RFC 8907 | **TCP `49`** (`PSH ACK` frame sharing 4-tuple TCP sequence state) |
| **Syslog** | `SYSLOG` | RFC 5424, RFC 6587 | **UDP `514`** (default) or **TCP `514`** (with `TRANSPORT TCP`) |
| **Cisco NetFlow v5** | `NETFLOW` | Cisco NetFlow v5 | **UDP `2055`** |
| **IPFIX (NetFlow v10)** | `IPFIX` | RFC 7011, RFC 7012 | **UDP `4739`** (or **TCP `4739`** with `TRANSPORT TCP`) |
| **sFlow v5** | `SFLOW` | sFlow v5 | **UDP `6343`** |

---

## 1. Naming & Address Assignment (`DNS`, `MDNS`, `DHCP`)

Validating DDI appliances (Infoblox, BlueCat, Kea, `dnsmasq`, `named`), testing DNS RPZ sinkholes, or troubleshooting dual-stack campus client onboarding (`DHCP` DORA / SARR + `DNS` + `MDNS`) doesn't require spinning up DHCP scopes or poisoning a lab resolver. A few lines of `.fasm` code synthesize the entire sequence with valid ports and multicast MACs.

### 1.1 `DNS` (Domain Name System — RFC 1035 / RFC 3596)

Testing DNS sinkholes (`NXDOMAIN` / `REFUSED`), split-horizon records (`A`, `AAAA`, `PTR`, `SRV`, `TXT`), or unauthorized zone transfer (`AXFR`) alerts in Suricata and Zeek usually means editing zone files in `bind` or `dnsmasq` and firing `dig` commands across VLANs. Instead, write the query and response directly in `.fasm` code. On the wire, `DNS` builds a 12-byte RFC 1035 header, encodes `QNAME` into length-prefixed DNS labels (`[3]www[7]example[3]com[0]`), and—when `RESPONSE` or `RDATA` is present—appends an Answer Resource Record using RFC 1035 `0xC00C` name compression. Adding `TRANSPORT TCP` automatically prepends the mandatory 2-byte big-endian message length prefix (RFC 1035 §4.2.2) for zone transfers (`AXFR`) or large responses.

| Modifier | Syntax | Default Value | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Direction Flags** | `QUERY` \| `RESPONSE` | `QUERY` (`0x0100`) | **Standalone flags** (do not put the domain name immediately after `QUERY`). `QUERY` sets `Flags = 0x0100` (Standard Query, RD=1); `RESPONSE` sets `Flags = 0x8180` (Response, RD=1, RA=1) and `ANCOUNT = 1`. |
| **`TXID`** | `TXID <0..65535>` | `0x1234` (`4660`) | 16-bit DNS Transaction ID matching a response to its query. |
| **`QNAME`** | `QNAME "<domain>"` | `"example.com"` | Question domain name automatically encoded into length-prefixed labels. |
| **`QTYPE`** | `QTYPE "<type>"` | `"A"` (`1`) | Accepts `"A"` (`1`), `"NS"` (`2`), `"CNAME"` (`5`), `"SOA"` (`6`), `"PTR"` (`12`), `"MX"` (`15`), `"TXT"` (`16`), `"AAAA"` (`28`), `"SRV"` (`33`), `"AXFR"` (`252`), `"ANY"` (`255`), or any numeric `<0..65535>`. |
| **`RDATA`** | `RDATA "<val>"` | `"93.184.216.34"` | Answer record data: IPv4 address for `"A"`, IPv6 address for `"AAAA"`, compressed domain name for `"CNAME"`/`"NS"`/`"PTR"`, or text bytes for `"TXT"`. |
| **`RCODE`** | `RCODE <0..15>` | `0` (`NOERROR`) | Lower 4 bits of DNS Flags: `0` = `NOERROR`, `1` = `FORMERR`, `2` = `SERVFAIL`, `3` = `NXDOMAIN`, `4` = `NOTIMP`, `5` = `REFUSED`. |
| **`ANS_TTL`** | `ANS_TTL <seconds>` | `300` | Answer Resource Record cache Time-To-Live in seconds. |
| **`TRANSPORT TCP`** | `TRANSPORT TCP` | UDP (`53`) | Switches transport to TCP port `53` and prepends the 2-byte RFC 1035 message length field. |

> **Syntax Tip:** `QUERY` and `RESPONSE` take **no value directly after the keyword**. Always specify the queried domain with `QNAME "<domain>"` (for example: `c -> s dns query txid 100 qname "intranet.corp.local" qtype "A"`).

### 1.2 `MDNS` (Multicast DNS / Bonjour / Avahi — RFC 6762 & RFC 6763)

Reproducing Apple Bonjour or Avahi `mDNS` printer and IoT service discovery across campus VLANs normally requires physical IoT hardware or a multicast reflector daemon. In `.fasm` code, `MDNS` shares the exact same modifiers as `DNS` (`QUERY`, `RESPONSE`, `TXID`, `QNAME`, `QTYPE`, `RDATA`, `RCODE`, `ANS_TTL`), while automatically applying RFC 6762 link-local multicast addressing over **UDP port `5353`**:
* **Over IPv4:** Automatically sets the destination IP to **`224.0.0.251`** and derives the RFC 1112 multicast destination MAC **`01:00:5e:00:00:fb`** (unless explicitly overridden).
* **Over IPv6:** Automatically sets the destination IP to **`ff02::fb`** and derives the RFC 2464 multicast destination MAC **`33:33:00:00:00:fb`** (unless explicitly overridden).

### 1.3 `DHCP` (DHCPv4 BOOTP & DHCPv6 — RFC 2131 / RFC 2132 / RFC 8415)

Verifying switch DHCP snooping, Dynamic ARP Inspection (DAI), or relay agent ACLs shouldn't require plugging a rogue DHCP server into a switch port. The `DHCP` keyword is fully dual-stack: between IPv4 hosts, it builds a 236-byte BOOTP header + RFC 1497 magic cookie (`0x63825363`) + TLV DHCPv4 options over **UDP ports `68` / `67`** for a complete DORA (`Discover` / `Offer` / `Request` / `ACK`) handshake; between IPv6 hosts, it builds an RFC 8415 DHCPv6 SARR (`Solicit` / `Advertise` / `Request` / `Reply`) exchange + Client DUID-LL option (Option `1`) over **UDP ports `546` / `547`**.

| Modifier | Syntax | Default Value | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **DHCPv4 Flags** | `DISCOVER` \| `OFFER` \| `REQUEST` \| `ACK` \| `RELEASE` | `DISCOVER` (Option 53 = `1`) | Sets DHCPv4 Option `53` (`1`=Discover, `2`=Offer, `3`=Request, `5`=ACK, `7`=Release). Client messages (`DISCOVER`, `REQUEST`, `RELEASE`) use `op=1` and UDP `68 -> 67`; server messages (`OFFER`, `ACK`) use `op=2` and UDP `67 -> 68`. |
| **DHCPv6 Flags** | `SOLICIT` \| `ADVERTISE` \| `REQUEST` \| `REPLY` \| `RELEASE` | `SOLICIT` (`msg-type 1`) | Sets DHCPv6 message type (`1`=Solicit, `2`=Advertise, `3`=Request, `7`=Reply, `8`=Release). Client messages use UDP `546 -> 547`; server messages (`ADVERTISE`, `REPLY`) use UDP `547 -> 546`. |
| **`XID` / `TXID`** | `XID <number>` | `0x12345678` (v4), `0x123456` (v6) | 32-bit BOOTP Transaction ID (DHCPv4) or 24-bit Transaction ID (DHCPv6). (`TXID <number>` is also accepted.) |
| **`CHADDR`** | `CHADDR <mac>` | Sender's Ethernet MAC | Populates the 16-byte BOOTP `chaddr` field (v4) or Option `1` DUID-LL hardware address (v6). Automatically inherits the sender's `HOST` MAC if omitted. |
| **`CIADDR`** | `CIADDR <ipv4>` | `0.0.0.0` | Client IP address (`ciaddr`) for bound/renewing DHCPv4 clients. |
| **`YIADDR`** | `YIADDR <ip>` | `0.0.0.0` | "Your" (assigned client) IP address (`yiaddr`). |
| **`SIADDR`** | `SIADDR <ipv4>` | `0.0.0.0` | Next server / PXE boot server IP address (`siaddr`). |
| **`SUBNET_MASK`** | `SUBNET_MASK <ipv4>` | Omitted | Appends DHCPv4 Option `1` (Subnet Mask). |
| **`ROUTER`** | `ROUTER <ipv4>` | Omitted | Appends DHCPv4 Option `3` (Default Gateway Router). |
| **`DNS_SERVER`** | `DNS_SERVER <ip>` | Omitted | Appends DHCPv4 Option `6` (Domain Name Server). |
| **`HOSTNAME`** | `HOSTNAME "<text>"` | Omitted | Appends DHCPv4 Option `12` (Client Hostname string). |
| **`LEASE_TIME`** | `LEASE_TIME <seconds>` | Omitted | Appends DHCPv4 Option `51` (IP Address Lease Time in seconds, e.g., `86400` = 24 hours). |

### 1.4 Compilable Example: Dual-Stack `DHCP` Onboarding (DORA & SARR), `DNS` Lookups (`NOERROR` / `NXDOMAIN` / TCP `AXFR`) & `MDNS` Service Discovery

```frameassembly
host client_v4 { ip 192.168.20.100 mac 00:50:56:20:00:64 }
host infra_v4  { ip 192.168.20.1   mac 00:50:56:20:00:01 }
host client_v6 { ip 2001:db8:20::100 mac 00:50:56:62:00:64 }
host infra_v6  { ip 2001:db8:20::1   mac 00:50:56:62:00:01 }

flow campus_onboarding_v4(c4, s4) {
    // 1. Full DHCPv4 DORA lease negotiation (UDP 68 <-> 67)
    c4 -> s4 dhcp discover xid 0x10203040 chaddr 00:50:56:20:00:64 hostname "eng-ws-01" wait 2ms
    c4 <- s4 dhcp offer xid 0x10203040 yiaddr 192.168.20.100 siaddr 192.168.20.1 chaddr 00:50:56:20:00:64 subnet_mask 255.255.255.0 router 192.168.20.1 dns_server 192.168.20.1 lease_time 86400 wait 2ms
    c4 -> s4 dhcp request xid 0x10203040 ciaddr 192.168.20.100 yiaddr 192.168.20.100 chaddr 00:50:56:20:00:64 hostname "eng-ws-01" wait 2ms
    c4 <- s4 dhcp ack xid 0x10203040 yiaddr 192.168.20.100 siaddr 192.168.20.1 chaddr 00:50:56:20:00:64 subnet_mask 255.255.255.0 router 192.168.20.1 dns_server 192.168.20.1 lease_time 86400 wait 5ms

    // 2. Standard DNS A record lookup (RCODE 0 = NOERROR) and blocked domain (RCODE 3 = NXDOMAIN)
    c4 -> s4 dns query txid 1010 qname "git.corp.example.com" qtype "A" wait 1ms
    c4 <- s4 dns response txid 1010 qname "git.corp.example.com" qtype "A" rdata "192.168.20.55" rcode 0 ans_ttl 300 wait 2ms
    c4 -> s4 dns query txid 1011 qname "malware-c2.bad.example" qtype "A" wait 1ms
    c4 <- s4 dns response txid 1011 qname "malware-c2.bad.example" qtype "A" rcode 3 wait 2ms

    // 3. DNS Zone Transfer (AXFR) over TCP port 53 (2-byte RFC 1035 length prefix auto-prepended)
    c4 -> s4 transport tcp dns query txid 1012 qname "corp.example.com" qtype "AXFR" wait 2ms

    // 4. Multicast DNS (mDNS) printer discovery on UDP 5353 (auto-targets 224.0.0.251 / 01:00:5e:00:00:fb)
    c4 -> s4 mdns query txid 0 qname "_ipp._tcp.local" qtype "PTR" wait 2ms
    c4 <- s4 mdns response txid 0 qname "_ipp._tcp.local" qtype "PTR" rdata "floor3-printer._ipp._tcp.local" ans_ttl 120
}

flow campus_onboarding_v6(c6, s6) {
    // 1. Full DHCPv6 SARR (Solicit / Advertise / Request / Reply) over UDP 546 <-> 547
    c6 -> s6 dhcp solicit xid 0xabcdef chaddr 00:50:56:62:00:64 hostname "eng-ws-01-v6" wait 2ms
    c6 <- s6 dhcp advertise xid 0xabcdef yiaddr 2001:db8:20::100 dns_server 2001:db8:20::1 lease_time 86400 wait 2ms
    c6 -> s6 dhcp request xid 0xabcdef hostname "eng-ws-01-v6" wait 2ms
    c6 <- s6 dhcp reply xid 0xabcdef yiaddr 2001:db8:20::100 dns_server 2001:db8:20::1 lease_time 86400 wait 5ms

    // 2. IPv6 DNS AAAA lookup + IPv6 mDNS service announcement (auto-targets ff02::fb / 33:33:00:00:00:fb)
    c6 -> s6 dns query txid 2020 qname "git.corp.example.com" qtype "AAAA" wait 1ms
    c6 <- s6 dns response txid 2020 qname "git.corp.example.com" qtype "AAAA" rdata "2001:db8:20::55" rcode 0 ans_ttl 300 wait 2ms
    c6 -> s6 mdns query txid 0 qname "_ssh._tcp.local" qtype "PTR"
}

compile {
    campus_onboarding_v4(client_v4, infra_v4)
    campus_onboarding_v6(client_v6, infra_v6)
}
```

---

## 2. Precision Time Synchronization (`NTP` & `PTP`)

Accurate clock synchronization is critical for correlating syslog/SIEM timelines (`NTP`) and for sub-microsecond financial trading, 5G fronthaul, broadcast media (SMPTE ST 2110), and power-grid synchrophasors (`PTP` IEEE 1588v2).

### 2.1 `NTP` (Network Time Protocol v4 — RFC 5905)

Testing firewall rules for UDP port `123`, simulating Stratum-1 GPS/PPS clock drift, or verifying how clients handle a Stratum-0 Kiss-o'-Death (`RATE` / `DENY`) packet is much easier when you don't have to reconfigure `chronyd` or `ntpd`. In `.fasm` code, `NTP` emits a 48-byte RFC 5905 packet over **UDP port `123`**, packing the Leap Indicator (`LI`), Version (`VN`), and Association Mode (`MODE`) into byte `0`, followed by Stratum, Poll, Precision, Reference ID, and 64-bit fixed-point timestamps.

| Modifier | Syntax | Default Value | Wire Behavior & Common Values |
| :--- | :--- | :--- | :--- |
| **`LI`** | `LI <0..3>` | `0` | 2-bit Leap Indicator: `0` = no warning, `1` = last minute has 61s, `2` = last minute has 59s, `3` = clock unsynchronized (alarm). |
| **`VN`** | `VN <1..4>` | `4` | 3-bit NTP Version Number (`4` = NTPv4, `3` = NTPv3). |
| **`MODE`** | `MODE <0..7>` | `3` (Client) | 3-bit Association Mode: `1` = Symmetric Active, `2` = Symmetric Passive, `3` = **Client**, `4` = **Server**, `5` = **Broadcast**, `6` = NTP Control. |
| **`STRATUM`** | `STRATUM <0..16>` | `0` | Clock stratum level: `0` = Kiss-o'-Death / unspecified, `1` = Primary reference (GPS/Atomic/PPS), `2..15` = Secondary servers, `16` = Unsynchronized. |
| **`POLL`** | `POLL <0..255>` | `4` ($2^4 = 16\text{ s}$) | Poll interval in $\log_2$ seconds (`4` = 16s, `6` = 64s, `10` = 1024s). |
| **`PRECISION`** | `PRECISION <-128..127>` | `-6` ($2^{-6}\text{ s}$) | Signed clock precision in $\log_2$ seconds (e.g., `-20` $\approx 1\,\mu\text{s}$). |
| **`REFID`** | `REFID "<4char>"` | `\x00\x00\x00\x00` | 4-character ASCII reference clock kiss-code (`"GPS"`, `"PPS"`, `"ATOM"`, `"LOCL"`, `"INIT"`, `"RATE"`). |
| **`TX_TIMESTAMP`** | `TX_TIMESTAMP <64-bit_hex>` | `0xE500000000000000` | 64-bit NTP fixed-point Transmit Timestamp (upper 32 bits = seconds since 1900-01-01, lower 32 bits = fractional seconds). |

### 2.2 `PTP` (Precision Time Protocol — IEEE 1588v2)

Hardware IEEE 1588v2 Grandmaster clocks cost thousands of dollars, making it painful to test PTP boundary clock ACLs, QoS `DSCP EF` queues, or SMPTE ST 2110 / financial-trading timing dissectors in a lab. `PTP` builds a 44-byte IEEE 1588v2 frame (34-byte `commonPTP` header with `versionPTP = 2` + 10-byte `originTimestamp`) directly from code and **automatically selects the required UDP port** based on whether the message is time-critical (hardware-timestamped) or general:
* **UDP Port `319` (PTP Event Port):** Automatically selected for **`SYNC`** (`0x00`) and **`DELAY_REQ`** (`0x01`).
* **UDP Port `320` (PTP General Port):** Automatically selected for **`FOLLOW_UP`** (`0x08`), **`DELAY_RESP`** (`0x09`), and **`ANNOUNCE`** (`0x0B`).

| Modifier | Syntax | Default Value | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Message Flags** | `SYNC` \| `DELAY_REQ` \| `FOLLOW_UP` \| `DELAY_RESP` \| `ANNOUNCE` | `SYNC` (UDP `319`) | Sets the 4-bit `messageType`, IEEE 1588 `controlField`, and UDP destination port (`319` or `320`). |
| **`MSG_TYPE`** | `MSG_TYPE "<type>"` | `"SYNC"` | Explicit string alternative to the bare message flags (e.g., `msg_type "ANNOUNCE"`). |
| **`VERSION`** | `VERSION <0..255>` | `2` | IEEE 1588 PTP version (`2` for PTPv2). |
| **`DOMAIN`** | `DOMAIN <0..255>` | `0` | PTP `domainNumber` (`0` = default IEEE 1588 domain, `24` / `44` = telecom profiles, `127` = SMPTE ST 2059). |
| **`SEQ_ID`** | `SEQ_ID <0..65535>` | `1` | 16-bit `sequenceId` linking `SYNC` $\leftrightarrow$ `FOLLOW_UP` and `DELAY_REQ` $\leftrightarrow$ `DELAY_RESP`. |
| **`CLOCK_ID`** | `CLOCK_ID "<text>"` | Auto EUI-64 from MAC | 8-byte Grandmaster/Port `ClockIdentity`. If omitted, FrameAssembly automatically derives a valid IEEE EUI-64 identity (`mac[0..3] : ff : fe : mac[3..6]`) from the sender's MAC address. |

### 2.3 Compilable Example: `NTP` Stratum-1 Poll & Two-Step `PTP` Grandmaster Synchronization

```frameassembly
host grandmaster { ip 10.158.0.1  mac 00:1c:73:00:01:01 }
host boundary_sw { ip 10.158.0.50 mac 00:1c:73:00:01:50 }

flow precision_timing_verification(gm, sw) {
    // 1. NTPv4 Client (mode 3) -> Stratum-1 GPS Server (mode 4) exchange on UDP 123
    sw -> gm dscp 46 ntp li 0 vn 4 mode 3 stratum 2 poll 6 precision -18 refid "INIT" tx_timestamp 0xe9b0000100000000 wait 1ms
    sw <- gm dscp 46 ntp li 0 vn 4 mode 4 stratum 1 poll 6 precision -24 refid "GPS" tx_timestamp 0xe9b0000100001000 wait 5ms

    // 2. IEEE 1588v2 PTP two-step synchronization cycle:
    //    - ANNOUNCE, FOLLOW_UP, and DELAY_RESP automatically route to UDP 320 (General)
    //    - SYNC and DELAY_REQ automatically route to UDP 319 (Event)
    gm -> sw dscp 46 ptp announce domain 0 seq_id 500 clock_id "GM-CLK01" wait 500us
    gm -> sw dscp 46 ptp sync domain 0 seq_id 501 clock_id "GM-CLK01" wait 100us
    gm -> sw dscp 46 ptp follow_up domain 0 seq_id 501 clock_id "GM-CLK01" wait 200us
    sw -> gm dscp 46 ptp delay_req domain 0 seq_id 501 clock_id "SW-CLK50" wait 200us
    gm -> sw dscp 46 ptp delay_resp domain 0 seq_id 501 clock_id "GM-CLK01"
}

compile {
    precision_timing_verification(grandmaster, boundary_sw)
}
```

---

## 3. AAA Access & Device Administration Security (`RADIUS` & `TACACS`)

Network Access Control (802.1X / MAB / VPN authentication via FreeRADIUS, Cisco ISE, or Aruba ClearPass) and router/switch CLI command authorization (`TACACS+`) rely on `RADIUS` and `TACACS`.

### 3.1 `RADIUS` (Authentication & Accounting — RFC 2865 / RFC 2866 / RFC 3162 / RFC 6911)

Testing 802.1X NAC policies, VPN authentication flows, or RADIUS accounting collectors usually forces you to spin up FreeRADIUS, Cisco ISE, or Aruba ClearPass and wrangle supplicant certificates. With FrameAssembly, you script the entire `Access-Request` / `Access-Challenge` / `Access-Accept` and `Accounting-Request` exchange in `.fasm` code. `RADIUS` builds a 20-byte fixed header (Code, Identifier, Length, 16-byte Authenticator) followed by TLV Attribute-Value Pairs (AVPs). FrameAssembly **automatically switches between UDP port `1812` and UDP port `1813`** and **automatically selects IPv4 vs. IPv6 RADIUS attribute codes**:
* **UDP Port `1812` (Authentication):** `ACCESS_REQUEST` (Code `1`), `ACCESS_ACCEPT` (Code `2`), `ACCESS_REJECT` (Code `3`), `ACCESS_CHALLENGE` (Code `11`).
* **UDP Port `1813` (Accounting):** `ACCOUNTING_REQUEST` (Code `4`), `ACCOUNTING_RESPONSE` (Code `5`).
* **Smart Dual-Stack AVPs:** Passing an IPv4 address to `NAS_IP` or `FRAMED_IP` emits RFC 2865 Attributes `4` (`NAS-IP-Address`) and `8` (`Framed-IP-Address`). Passing an IPv6 address automatically emits RFC 3162 Attribute `95` (`NAS-IPv6-Address`) and RFC 6911 Attribute `168` (`Framed-IPv6-Address`).

| Modifier | Syntax | Default Value | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Packet Code Flags** | `ACCESS_REQUEST` \| `ACCESS_ACCEPT` \| `ACCESS_REJECT` \| `ACCESS_CHALLENGE` \| `ACCOUNTING_REQUEST` \| `ACCOUNTING_RESPONSE` | `ACCESS_REQUEST` (Code `1`, UDP `1812`) | Selects the RADIUS Code byte and routes to UDP `1812` (Auth) or `1813` (Accounting). |
| **`CODE`** | `CODE "<name>"` | `"ACCESS_REQUEST"` | Explicit string alternative to the bare packet code flags. |
| **`ID`** | `ID <0..255>` | `1` | 8-bit RADIUS packet Identifier matching requests and responses. |
| **`USER`** | `USER "<username>"` | `"user"` | Encodes Attribute `1` (`User-Name`). |
| **`NAS_IP`** | `NAS_IP <ip>` | Omitted | Encodes Attribute `4` (`NAS-IP-Address` for IPv4) or Attribute `95` (`NAS-IPv6-Address` for IPv6). |
| **`SERVICE_TYPE`** | `SERVICE_TYPE <number>` | Omitted | Encodes Attribute `6` (`Service-Type`: `1` = Login, `2` = Framed/802.1X, `6` = Administrative, `8` = Authenticate-Only). |
| **`FRAMED_IP`** | `FRAMED_IP <ip>` | Omitted | Encodes Attribute `8` (`Framed-IP-Address` for IPv4) or Attribute `168` (`Framed-IPv6-Address` for IPv6). |

### 3.2 `TACACS` (TACACS+ Device Administration — RFC 8907)

Auditing router and switch CLI command authorization (`cmd=configure`, `cmd=reload`) or SIEM TACACS+ parsers without logging into production jump boxes is a one-liner in `.fasm` code. `TACACS` runs over **TCP port `49`** and emits a 12-byte RFC 8907 header (`version = 0xC0`, `type`, `seq_no`, `flags`, `session_id`, `length`) followed by a formatted Authentication (`START`), Authorization (`REQUEST`), or Accounting (`REQUEST`) body.

| Modifier | Syntax | Default Value | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Session Type** | `AUTHEN` \| `AUTHOR` \| `ACCT` \| `TYPE <AUTHEN\|AUTHOR\|ACCT>` | `AUTHEN` (`1`) | Sets TACACS+ packet type: `AUTHEN` (`1` = Authentication), `AUTHOR` (`2` = Command Authorization), `ACCT` (`3` = Accounting). |
| **`SEQ`** | `SEQ <0..255>` | `1` | 8-bit TACACS+ `seq_no` (increments by 1 for each packet in a session: client sends odd `1, 3...`, server replies even `2, 4...`). |
| **`FLAGS`** | `FLAGS <0..255>` | `0x01` (Unencrypted) | 8-bit TACACS+ flags bitmask (`0x01` = `TAC_PLUS_UNENCRYPTED_FLAG` so Wireshark can dissect the cleartext body; `0x04` = `SINGLE_CONNECT`). |
| **`SESSION_ID`** | `SESSION_ID <number>` | `0x12345678` | 32-bit TACACS+ session identifier shared across all packets in the session. |
| **`USER`** | `USER "<username>"` | `"admin"` | Administrative username encoded into the TACACS+ body. |
| **`DATA` / `PAYLOAD`**| `DATA "<text>"` \| `PAYLOAD "<text>"` | `""` | Command arguments or status data inside the TACACS+ body (e.g., `data "cmd=configure"` or `payload "cmd=show;cmd-arg=running-config"`). |

### 3.3 Compilable Example: 802.1X `RADIUS` Authentication/Accounting & `TACACS+` CLI Command Auditing

```frameassembly
host access_sw  { ip 10.60.1.10  mac 00:50:56:60:00:10 }
host ise_server { ip 10.60.1.200 mac 00:50:56:60:02:00 }
host sw_v6      { ip 2001:db8:60::10 }
host ise_v6     { ip 2001:db8:60::200 }

flow aaa_security_audit(nas, aaa) {
    // 1. RADIUS 802.1X authentication (automatically uses UDP port 1812)
    nas -> aaa radius access_request id 10 user "alice@corp.example.com" nas_ip 10.60.1.10 service_type 2 wait 2ms
    nas <- aaa radius access_challenge id 10 user "alice@corp.example.com" wait 2ms
    nas -> aaa radius access_request id 11 user "alice@corp.example.com" nas_ip 10.60.1.10 service_type 2 wait 2ms
    nas <- aaa radius access_accept id 11 user "alice@corp.example.com" framed_ip 10.60.20.55 service_type 2 wait 5ms

    // 2. RADIUS session accounting (automatically switches to UDP port 1813)
    nas -> aaa radius accounting_request id 12 user "alice@corp.example.com" nas_ip 10.60.1.10 framed_ip 10.60.20.55 wait 2ms
    nas <- aaa radius accounting_response id 12 wait 5ms

    // 3. TACACS+ login authentication, command authorization, and accounting over TCP port 49
    nas -> aaa tacacs authen seq 1 flags 1 session_id 900101 user "netadmin" data "tty0" wait 2ms
    nas <- aaa tacacs authen seq 2 flags 1 session_id 900101 user "netadmin" data "PASS" wait 2ms
    nas -> aaa tacacs author seq 1 flags 1 session_id 900102 user "netadmin" data "cmd=configure;cmd-arg=terminal" wait 2ms
    nas <- aaa tacacs author seq 2 flags 1 session_id 900102 user "netadmin" payload "AUTHOR_STATUS_PASS_ADD" wait 2ms
    nas -> aaa tacacs acct seq 1 flags 1 session_id 900103 user "netadmin" data "task_id=42;service=shell;cmd=reload"
}

flow radius_ipv6_audit(nas6, aaa6) {
    // Emits RFC 3162 NAS-IPv6-Address (95) and RFC 6911 Framed-IPv6-Address (168)
    nas6 -> aaa6 radius access_request id 20 user "bob@corp.example.com" nas_ip 2001:db8:60::10 service_type 2 wait 2ms
    nas6 <- aaa6 radius access_accept id 20 user "bob@corp.example.com" framed_ip 2001:db8:60:20::55
}

compile {
    aaa_security_audit(access_sw, ise_server)
    radius_ipv6_audit(sw_v6, ise_v6)
}
```

---

## 4. Centralized Logging & Network Flow Telemetry (`SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`)

Testing SIEM ingestion rules (Splunk, Elastic, Graylog, Sentinel, QRadar, Loki) or traffic-analytics collectors (ElastiFlow, Akvorado, `pmacct`, `nfcapd`, Kentik) is simple with built-in `SYSLOG`, `NETFLOW`, `IPFIX`, and `SFLOW` packet support.

### 4.1 `SYSLOG` (RFC 5424 / RFC 6587 Event Logging)

When you write a new Splunk, Elastic, Sentinel, or Graylog Grok/regex parser for a BGP flap or SSH login alert, you shouldn't have to pull a core router's fiber just to see if the alert fires. `SYSLOG` formats an RFC 5424 message (`<PRI>1 2026-10-23T00:00:00Z <HOSTNAME> <APP> <PROCID> <MSGID> - <MSG>`) over **UDP port `514`** by default, or over **TCP port `514`** when `TRANSPORT TCP` is specified. Unless you override `PRI` directly, FrameAssembly calculates `PRI = (FACILITY * 8) + SEVERITY` automatically.

| Modifier | Syntax | Default Value | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`FACILITY`** | `FACILITY <0..23>` | `1` (`user`) | Subsystem code (`0..=23`, multiplied by `8` in `PRI`). Commonly `4` (`auth`), `16` (`local0`) .. `23` (`local7`). |
| **`SEVERITY`** | `SEVERITY <0..7>` | `6` (`info`) | Urgency level (`0` = Emergency .. `7` = Debug). |
| **`PRI`** | `PRI <0..191>` | `FACILITY * 8 + SEVERITY` (`14`) | Explicit priority override inside `<PRI>`. |
| **`HOSTNAME`** | `HOSTNAME "<text>"` | Sender IP string | Originating router/switch/server hostname (`HOSTNAME` field). |
| **`APP`** | `APP "<text>"` | `"app"` | Application or daemon name (`"bgpd"`, `"sshd"`, `"ospfd"`, `"ASA"`). |
| **`PROCID`** | `PROCID "<text>"` | `"-"` | Process ID string (`"1842"`, `"901"`). |
| **`MSGID`** | `MSGID "<text>"` | `"-"` | RFC 5424 message type classifier (`"BGP-5-ADJCHANGE"`, `"SEC_LOGIN-5-LOGIN_SUCCESS"`). |
| **`MSG`** | `MSG "<text>"` | `"System notification"` | Free-form UTF-8 log message body. |
| **`TRANSPORT TCP`**| `TRANSPORT TCP` | UDP (`514`) | Sends the syslog record over TCP port `514` (`PSH ACK` frame). |

#### RFC 5424 Syslog `FACILITY` (`0..23`) & `SEVERITY` (`0..7`) Cheat Sheet

| Severity Code | Keyword / Level | Typical Meaning | Common Facility Codes | Subsystem |
| :---: | :--- | :--- | :---: | :--- |
| **`0`** | `emerg` (Emergency) | System is unusable (kernel panic, chassis power loss) | **`0` / `1`** | `kern` (Kernel) / `user` (User-level, default) |
| **`1`** | `alert` (Alert) | Immediate action required (BGP core isolation) | **`3` / `4`** | `daemon` (System daemons) / `auth` (Security/Auth) |
| **`2`** | `crit` (Critical) | Critical hardware/link condition (optical transceiver fault) | **`6` / `7`** | `lpr` (Line printer) / `news` (Network news) |
| **`3`** | `err` (Error) | Operational error (OSPF MTU mismatch, CRC errors) | **`9` / `10`** | `cron` (Clock daemon) / `authpriv` (Private security) |
| **`4`** | `warning` (Warning) | Warning threshold crossed (high CPU, BGP prefix limit 80%) | **`11` / `15`**| `ftp` (FTP daemon) / `cron2` (Scheduling daemon) |
| **`5`** | `notice` (Notice) | Normal but significant event (ACL hit, config commit) | **`16` .. `19`**| `local0` (`16`), `local1` (`17`), `local2` (`18`), `local3` (`19`) — Network OS routing/switching logs |
| **`6`** | `info` (Informational)| Routine operational message (default) | **`20` .. `23`**| `local4` (`20`), `local5` (`21`), `local6` (`22`), `local7` (`23`) — Firewall, VPN & audit logs |
| **`7`** | `debug` (Debug) | Verbose packet/state-machine trace | | *Formula:* `PRI = (FACILITY * 8) + SEVERITY` |

### 4.2 `NETFLOW`, `IPFIX` & `SFLOW` (Network Flow & Packet Sampling Telemetry)

Waiting for a hardware switch or router to export flow records—or trying to generate synthetic high-byte-count elephant flows on a laptop—makes testing ElastiFlow, Akvorado, `pmacct`, `nfcapd`, or Kentik pipelines unnecessarily slow. In `.fasm` code, you specify the exact monitored source/destination IPs, ports, protocol byte, and packet/octet counters in a single statement:
* **`NETFLOW` (Cisco NetFlow v5 — UDP `2055`):** Emits a 72-byte NetFlow v5 packet (24-byte v5 export header with `version = 5`, `count = 1`, `sys_uptime`, `unix_secs`, `flow_sequence` + 48-byte flow record).
* **`IPFIX` (IETF IP Flow Information Export v10 — RFC 7011, UDP `4739`):** Emits a 16-byte IPFIX header (`version = 0x000a`, `length`, `export_time`, `seq_no`, `domain_id`) followed by Data Set `256` carrying source/destination IPs, transport ports, protocol byte, and 64-bit packet/octet delta counters.
* **`SFLOW` (sFlow v5 — RFC 3176, UDP `6343`):** Emits a dual-stack sFlow v5 datagram header (`version = 5`, `address_type = 1` for IPv4 or `2` for IPv6, `agent_ip`, `sub_agent_id`, `seq_no`, `uptime`, `samples`) followed by a 32-byte Format `1` Flow Sample record.

| Protocol | Modifier | Syntax | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`NETFLOW`** & **`IPFIX`** | **`SRCIP`** | `SRCIP <ip>` | Exporter `src_ip` | Monitored flow source IP address inside the flow record. |
| **`NETFLOW`** & **`IPFIX`** | **`DSTIP`** | `DSTIP <ip>` | Collector `dst_ip` | Monitored flow destination IP address inside the flow record. |
| **`NETFLOW`** & **`IPFIX`** | **`SRCPORT`** | `SRCPORT <0..65535>` | Ephemeral port | Monitored flow Layer 4 source port (also sets outer packet source port). |
| **`NETFLOW`** & **`IPFIX`** | **`DSTPORT`** | `DSTPORT <0..65535>` | `2055` / `4739` | Monitored flow Layer 4 destination port. |
| **`NETFLOW`** & **`IPFIX`** | **`PROTO`** | `PROTO <0..255>` | `6` (TCP) | Monitored flow IP protocol number (`1` = ICMP, `6` = TCP, `17` = UDP, `47` = GRE, `50` = ESP). |
| **`NETFLOW`** & **`IPFIX`** | **`PACKETS`** | `PACKETS <count>` | `1` | Packet count (`dPkts` / `packetDeltaCount`) for the exported flow. |
| **`NETFLOW`** & **`IPFIX`** | **`OCTETS`** | `OCTETS <bytes>` | `64` | Byte count (`dOctets` / `octetDeltaCount`) for the exported flow. |
| **`IPFIX`** Only | **`DOMAIN_ID`** | `DOMAIN_ID <number>` | `0` | 32-bit IPFIX Observation Domain ID (`observationDomainId`) identifying the linecard/VRF. |
| **`SFLOW`** Only | **`AGENT_IP`** | `AGENT_IP <ip>` \| `AGENTIP <ip>` | Exporter `src_ip` | Switch/router sFlow Agent IPv4 or IPv6 address (`address_type` `1` or `2` set automatically). |
| **`SFLOW`** Only | **`SUB_AGENT_ID`**| `SUB_AGENT_ID <number>`| `0` | sFlow Sub-Agent ID identifying the switch blade or ASIC. |
| **`SFLOW`** Only | **`SEQ`** | `SEQ <number>` | `1` | sFlow datagram and sample sequence number. |
| **`SFLOW`** Only | **`UPTIME`** | `UPTIME <ms>` | `1000` | Switch uptime in milliseconds (`sys_uptime`). |
| **`SFLOW`** Only | **`SAMPLES`** | `SAMPLES <count>` | `1` | Number of flow sample records reported in the sFlow header (`num_samples`). |

### 4.3 Compilable Example: `SYSLOG` (UDP & TCP), `NETFLOW` v5, `IPFIX` v10 & Dual-Stack `SFLOW` v5

```frameassembly
host core_exporter { ip 10.250.10.1   mac 00:50:56:fa:00:01 }
host telemetry_col { ip 10.250.10.100 mac 00:50:56:fa:01:00 }
host leaf_v6       { ip 2001:db8:fa::1 }
host collector_v6  { ip 2001:db8:fa::100 }

flow noc_observability_pipeline(rtr, col) {
    // 1. UDP Syslog (facility 16 = local0, severity 4 = warning -> PRI 132)
    rtr -> col syslog facility 16 severity 4 hostname "core-rtr-01" app "bgpd" procid "1842" msgid "BGP-4-MAXPFX" msg "Neighbor 198.51.100.1 prefix count 85000 exceeds 80% threshold" wait 1ms

    // 2. TCP Syslog for guaranteed delivery of security audit logs (facility 10 = authpriv, severity 5 = notice)
    rtr -> col transport tcp syslog facility 10 severity 5 hostname "core-rtr-01" app "sshd" procid "4410" msgid "SEC_LOGIN" msg "Accepted publickey for netadmin from 10.254.0.10 port 54122 ssh2" wait 2ms

    // 3. Cisco NetFlow v5 export on UDP 2055 (reporting a 15,400-packet HTTPS transfer)
    rtr -> col netflow srcip 198.51.100.25 dstip 203.0.113.80 srcport 51200 dstport 443 proto 6 packets 15400 octets 21560000 wait 1ms

    // 4. IETF IPFIX (v10) export on UDP 4739 with Observation Domain ID 4001
    rtr -> col ipfix domain_id 4001 srcip 198.51.100.25 dstip 203.0.113.80 srcport 51200 dstport 443 proto 6 packets 15400 octets 21560000 wait 1ms

    // 5. sFlow v5 packet sample export on UDP 6343
    rtr -> col sflow agent_ip 10.250.10.1 sub_agent_id 1 seq 105 uptime 86400000 samples 1
}

flow ipv6_telemetry_pipeline(sw6, col6) {
    sw6 -> col6 syslog facility 23 severity 2 hostname "leaf-sw-v6" app "envmon" msgid "FAN-2-FAIL" msg "Tray 2 Fan 1 RPM below critical threshold" wait 1ms
    sw6 -> col6 sflow agent_ip 2001:db8:fa::1 sub_agent_id 2 seq 500 uptime 172800000 samples 1
}

compile {
    noc_observability_pipeline(core_exporter, telemetry_col)
    ipv6_telemetry_pipeline(leaf_v6, collector_v6)
}
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — `.fasm` file anatomy, automatic defaults vs. explicit overrides, and step-by-step Wireshark workflows.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — Practical recipes for testing SIEM/NetFlow collectors, firewall ACLs, and campus Zero-Trust NAC.
- [**Layer 2 Switching & Data-Link Protocols (`l2_protocols.md`)**](l2_protocols.md) & [**Layer 3 Control, Tunneling, VPN & Routing Protocols (`l3_protocols.md`)**](l3_protocols.md) — Pair `RADIUS`, `DHCP`, and `IPFIX` with `802.1X EAPOL`, `VLAN`, `QINQ`, `MPLS`, `BGP`, and `VXLAN`.
- [**Layer 4 Transport Protocols (`l4_transports.md`)**](l4_transports.md) — `TCP`, `UDP`, and `SCTP` transport behaviors and `transport tcp` / `transport udp` switching.
- [**Layer 7 SNMP Reference (`l7_snmp.md`)**](l7_snmp.md) — Complete guide to `SNMP1`, `SNMP2` (`GETBULK` & `INFORM`), and encrypted `SNMP3` USM (`SHA256`/`SHA512` + `AES-128`).
- [**Layer 7 Web, Cloud, VoIP & Remote Access (`l7_web_and_cloud.md`)**](l7_web_and_cloud.md) — Reference for `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `SIP`, `RTP`, `RTSP`, `STUN`, and `SSDP`.
- [**Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Complete Campus 802.1X NAC and EVPN-VXLAN IPFIX fabric captures.
- [**`.fasm` File Format & Media Type Specification (`fasm-specification.md`)**](fasm-specification.md) — Normative `text/vnd.frameassembly` media type specification, lexical rules, and `.fasm` extension disambiguation.
