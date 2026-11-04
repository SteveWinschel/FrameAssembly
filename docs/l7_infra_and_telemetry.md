# Layer 7 — Core Infrastructure, Time, AAA & Flow Telemetry (`docs/l7_infra_and_telemetry.md`)

[**Use Cases**](#infrastructure-and-telemetry-testing-use-cases) • [**Smart Ports & Multicast**](#what-frameassembly-handles-for-you) • [**DNS, mDNS & DHCP**](#1-naming-service-discovery-and-dhcp-dns-mdns-dhcp) • [**NTP & PTP**](#2-clock-sync-and-precision-timing-ntp-ptp) • [**RADIUS & TACACS+**](#3-aaa-access-and-cli-auditing-radius-tacacs) • [**Syslog & Flow Exports**](#4-logging-and-flow-telemetry-syslog-netflow-ipfix-sflow) • [**Inspect & Replay**](#inspecting-and-replaying-infrastructure-captures)

## Why Use FrameAssembly for Infrastructure & Telemetry?

Testing core infrastructure rules, SIEM parsers, and flow collectors usually demands an absurd amount of lab plumbing for five packets of traffic. If you want to verify that **Suricata** catches an unauthorized DNS `AXFR` zone transfer, check switch DHCP snooping, test **Cisco ISE** / **FreeRADIUS** attributes, or see if **Splunk** and **ElastiFlow** parse a BGP flap, your normal options are rough -> edit `bind` zone files, configure `kea-dhcp` scopes, buy a four-figure IEEE 1588 PTP grandmaster clock, or yank a fiber out of a core router just to generate one syslog line and hope nobody notices :)

With **FrameAssembly**, you write the exact query, lease, AAA exchange, or flow record in a few lines of `.fasm` packet code, compile a clean `.pcap` offline with no `sudo` or lab daemons needed, and feed it straight into **`tcpreplay`**, **Wireshark** / **`tshark`**, **Suricata**, or **Zeek**:

```frameassembly
host core_rtr { ip 10.250.0.1   mac 00:1c:73:fa:00:01 }
host sec_ops  { ip 10.250.0.100 mac 00:50:56:fa:00:64 }

flow noc_quick_check(rtr, col) {
    // Blocked C2 DNS lookup (RCODE 5 = REFUSED) + Syslog alert + IPFIX flow export
    rtr -> col dns query txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "A" wait 1ms
    rtr <- col dns response txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "A" rcode 5 wait 2ms
    rtr -> col syslog facility 16 severity 2 hostname "core-rtr-01" app "bgpd" msgid "BGP_DOWN" msg "Neighbor 198.51.100.1 Hold Timer Expired" wait 2ms
    rtr -> col ipfix domain_id 4001 srcip 198.51.100.25 dstip 203.0.113.80 srcport 52400 dstport 443 proto 6 packets 15400 octets 21560000
}

compile { noc_quick_check(core_rtr, sec_ops) }
```

```console
$ frameassembly show infra_check.fasm
$ frameassembly infra_check.fasm -o infra_check.pcap && sudo tcpreplay -i eth0 infra_check.pcap
```

| Protocol | Keyword | Default Transport & Smart Port Routing | IPv4 & IPv6 | Primary Testing Focus |
| :--- | :--- | :--- | :---: | :--- |
| **DNS** | `dns` | `UDP 53` (`TCP 53` + 2B length with `transport tcp`) | Both | RPZ sinkholes (`NXDOMAIN`/`REFUSED`), `AAAA`/`TXT`/`SRV`, `AXFR` alerts |
| **Multicast DNS** | `mdns` | `UDP 5353` -> `224.0.0.251` (v4) / `ff02::fb` (v6) | Both | Bonjour/Avahi printer & IoT discovery across campus VLANs |
| **DHCPv4 / v6** | `dhcp` | `UDP 68<->67` (v4 DORA) / `UDP 546<->547` (v6 SARR) | Both | Switch DHCP snooping, rogue DHCP offers, relay ACLs |
| **NTPv4** | `ntp` | `UDP 123` | Both | Stratum-1 GPS sync, Leap Indicator alarms, Kiss-o'-Death (`RATE`) |
| **PTPv2** | `ptp` | `UDP 319` (`sync`/`delay_req`) & `320` (General) | Both | IEEE 1588v2 two-step sync, `DSCP EF` timing queues, EUI-64 clocks |
| **RADIUS** | `radius` | `UDP 1812` (Auth) & `UDP 1813` (Accounting) | Both | 802.1X NAC challenges, VPN `Framed-IP`, accounting collectors |
| **TACACS+** | `tacacs` | `TCP 49` (stateful `PSH ACK`) | Both | Router CLI login auth, `cmd=reload` authorization, audit logs |
| **Syslog** | `syslog` | `UDP 514` (`TCP 514` with `transport tcp`) | Both | SIEM Grok/regex parsers, facility/severity routing, reliable TCP logs |
| **NetFlow v5** | `netflow`| `UDP 2055` | Both | Collector ingest, elephant-flow bandwidth alerts, DDoS accounting |
| **IPFIX (v10)** | `ipfix` | `UDP 4739` | Both | Multi-VRF `domain_id` exports, 64-bit packet/octet counters |
| **sFlow v5** | `sflow` | `UDP 6343` | Both | Switch ASIC packet-sampling pipelines over IPv4 and IPv6 |

> **Looking for `SNMP`, `SSH`, `TELNET`, `TFTP`, `FTP`, or `WHOIS`?**
> `SNMP1`, `SNMP2`, and encrypted `SNMP3` live in [**SNMPv1, SNMPv2c & Encrypted SNMPv3 (`l7_snmp.md`)**](l7_snmp.md). Remote CLI, file transfer, and WHOIS live in [**Layer 7 — Web, Cloud, Transport Security, VoIP & Remote Access (`l7_web_and_cloud.md`)**](l7_web_and_cloud.md).

## Infrastructure and Telemetry Testing Use Cases

### 1. Test DNS Sinkholes, TCP Zone Transfers (`AXFR`) & Rogue `DHCP` Without Poisoning Your Lab
Plugging a rogue DHCP server into an access switch just to verify DHCP snooping is a great way to accidentally blackhole the office subnet, and editing `bind` zones for a single **Suricata** `AXFR` test gets old fast. Script dual-stack `DHCP` DORA/SARR leases, sinkholed `DNS` replies, TCP `AXFR` transfers, and `mDNS` multicast announcements offline:

```frameassembly
host client_v4 { ip 192.168.20.100 mac 00:50:56:20:00:64 }
host infra_v4  { ip 192.168.20.1   mac 00:50:56:20:00:01 }
host client_v6 { ip 2001:db8:20::100 mac 00:50:56:62:00:64 }
host infra_v6  { ip 2001:db8:20::1   mac 00:50:56:62:00:01 }

flow ddi_and_onboarding_v4(c, s) {
    // 1. Full DHCPv4 DORA lease negotiation (auto-routes UDP 68 <-> 67)
    c -> s dhcp discover xid 0x10203040 chaddr 00:50:56:20:00:64 hostname "eng-ws-01" wait 2ms
    c <- s dhcp offer xid 0x10203040 yiaddr 192.168.20.100 siaddr 192.168.20.1 chaddr 00:50:56:20:00:64 subnet_mask 255.255.255.0 router 192.168.20.1 dns_server 192.168.20.1 lease_time 86400 wait 2ms
    c -> s dhcp request xid 0x10203040 ciaddr 192.168.20.100 yiaddr 192.168.20.100 chaddr 00:50:56:20:00:64 hostname "eng-ws-01" wait 2ms
    c <- s dhcp ack xid 0x10203040 yiaddr 192.168.20.100 siaddr 192.168.20.1 chaddr 00:50:56:20:00:64 subnet_mask 255.255.255.0 router 192.168.20.1 dns_server 192.168.20.1 lease_time 86400 wait 5ms

    // 2. Normal DNS A lookup (RCODE 0) + sinkholed C2 lookup (RCODE 3 = NXDOMAIN)
    c -> s dns query txid 1010 qname "git.corp.example.com" qtype "A" wait 1ms
    c <- s dns response txid 1010 qname "git.corp.example.com" qtype "A" rdata "192.168.20.55" rcode 0 ans_ttl 300 wait 2ms
    c -> s dns query txid 1011 qname "ransom-beacon.bad.example" qtype "A" wait 1ms
    c <- s dns response txid 1011 qname "ransom-beacon.bad.example" qtype "A" rcode 3 wait 2ms

    // 3. Unauthorized DNS Zone Transfer (AXFR) over TCP 53 (auto-prepends 2-byte RFC 1035 length)
    c -> s tcp syn srcport 53100 dstport 53 win 64240 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms
    c -> s transport tcp dns query txid 1012 qname "corp.example.com" qtype "AXFR" wait 2ms

    // 4. Apple Bonjour / Avahi mDNS printer discovery (auto-targets 224.0.0.251 / 01:00:5e:00:00:fb)
    c -> s mdns query txid 0 qname "_ipp._tcp.local" qtype "PTR" wait 2ms
    c <- s mdns response txid 0 qname "_ipp._tcp.local" qtype "PTR" rdata "floor3-printer._ipp._tcp.local" ans_ttl 120
}

flow ddi_and_onboarding_v6(c6, s6) {
    // DHCPv6 SARR (auto-routes UDP 546 <-> 547) + IPv6 AAAA lookup + mDNS to ff02::fb
    c6 -> s6 dhcp solicit xid 0xabcdef chaddr 00:50:56:62:00:64 wait 2ms
    c6 <- s6 dhcp advertise xid 0xabcdef chaddr 00:50:56:62:00:64 wait 2ms
    c6 -> s6 dhcp request xid 0xabcdef chaddr 00:50:56:62:00:64 wait 2ms
    c6 <- s6 dhcp reply xid 0xabcdef chaddr 00:50:56:62:00:64 wait 5ms
    c6 -> s6 dns query txid 2020 qname "git.corp.example.com" qtype "AAAA" wait 1ms
    c6 <- s6 dns response txid 2020 qname "git.corp.example.com" qtype "AAAA" rdata "2001:db8:20::55" ans_ttl 300 wait 2ms
    c6 -> s6 mdns query txid 0 qname "_ssh._tcp.local" qtype "PTR"
}

compile {
    ddi_and_onboarding_v4(client_v4, infra_v4)
    ddi_and_onboarding_v6(client_v6, infra_v6)
}
```

### 2. Verify IEEE 1588v2 `PTP` Grandmaster Queues & `NTP` Kiss-o'-Death Handling Without Hardware Clocks
Hardware IEEE 1588v2 Grandmaster clocks cost thousands of dollars, which is painful when you just want to check that your switches put `PTP` Event (`UDP 319`) and General (`UDP 320`) packets into the `DSCP EF` (`46`) strict-priority queue or test how clients react to a Stratum-0 `NTP` Kiss-o'-Death (`"RATE"`):

```frameassembly
host grandmaster { ip 10.158.0.1  mac 00:1c:73:00:01:01 }
host boundary_sw { ip 10.158.0.50 mac 00:1c:73:00:01:50 }

flow precision_timing_audit(gm, sw) {
    // 1. Stratum-1 GPS NTP sync + Stratum-0 Kiss-o'-Death ("RATE") throttling response
    sw -> gm dscp 46 ntp li 0 vn 4 mode 3 stratum 2 poll 6 precision -18 refid "INIT" tx_timestamp 0xe9b0000100000000 wait 1ms
    sw <- gm dscp 46 ntp li 0 vn 4 mode 4 stratum 1 poll 6 precision -24 refid "GPS"  tx_timestamp 0xe9b0000100001000 wait 5ms
    sw <- gm dscp 46 ntp li 3 vn 4 mode 4 stratum 0 poll 6 precision -24 refid "RATE" tx_timestamp 0xe9b0000200000000 wait 5ms

    // 2. IEEE 1588v2 two-step PTP cycle (auto-routes SYNC/DELAY_REQ -> 319, ANNOUNCE/FOLLOW_UP/DELAY_RESP -> 320)
    gm -> sw vlan 158 pcp 5 dscp 46 ptp announce   domain 24 seq_id 500 clock_id "GM-CLK01" wait 500us
    gm -> sw vlan 158 pcp 5 dscp 46 ptp sync       domain 24 seq_id 501 clock_id "GM-CLK01" wait 100us
    gm -> sw vlan 158 pcp 5 dscp 46 ptp follow_up  domain 24 seq_id 501 clock_id "GM-CLK01" wait 200us
    sw -> gm vlan 158 pcp 5 dscp 46 ptp delay_req  domain 24 seq_id 501 clock_id "SW-CLK50" wait 200us
    gm -> sw vlan 158 pcp 5 dscp 46 ptp delay_resp domain 24 seq_id 501 clock_id "GM-CLK01"
}

compile { precision_timing_audit(grandmaster, boundary_sw) }
```

### 3. Audit 802.1X `RADIUS` Policies & `TACACS+` CLI Blocks Without Touching Jump Boxes
Testing NAC policies or SIEM alerts for unauthorized router `reload` commands normally forces you to wrestle supplicant certificates or type dangerous commands on a live jump box. Here you can script `RADIUS` auth (`UDP 1812`), accounting (`UDP 1813`), and `TACACS+` command auditing (`TCP 49`) directly:

```frameassembly
host access_sw  { ip 10.60.1.10  mac 00:50:56:60:00:10 }
host aaa_server { ip 10.60.1.200 mac 00:50:56:60:02:00 }
host sw_v6      { ip 2001:db8:60::10 }
host aaa_v6     { ip 2001:db8:60::200 }

flow nac_and_cli_audit(nas, aaa) {
    // 1. RADIUS 802.1X MFA challenge -> Accept (UDP 1812) -> Accounting Start (auto-switches to UDP 1813)
    nas -> aaa radius access_request id 10 user "alice@corp.example" nas_ip 10.60.1.10 service_type 2 wait 2ms
    nas <- aaa radius access_challenge id 10 user "alice@corp.example" wait 2ms
    nas -> aaa radius access_request id 11 user "alice@corp.example" nas_ip 10.60.1.10 service_type 2 wait 2ms
    nas <- aaa radius access_accept id 11 user "alice@corp.example" framed_ip 10.60.20.55 service_type 2 wait 5ms
    nas -> aaa radius accounting_request id 12 user "alice@corp.example" nas_ip 10.60.1.10 framed_ip 10.60.20.55 wait 2ms
    nas <- aaa radius accounting_response id 12 wait 5ms

    // 2. TACACS+ login, privilege-15 command authorization, and reload accounting over TCP 49
    nas -> aaa tcp syn srcport 51049 dstport 49 win 64240 mss 1460 wait 1ms
    nas <- aaa tcp syn ack win 65535 mss 1460 wait 1ms
    nas -> aaa tcp ack wait 1ms
    nas -> aaa tacacs authen seq 1 flags 1 session_id 900101 user "netadmin" data "tty0" wait 2ms
    nas <- aaa tacacs authen seq 2 flags 1 session_id 900101 user "netadmin" data "PASS" wait 2ms
    nas -> aaa tacacs author seq 1 flags 1 session_id 900102 user "netadmin" data "cmd=configure;cmd-arg=terminal" wait 2ms
    nas <- aaa tacacs author seq 2 flags 1 session_id 900102 user "netadmin" payload "AUTHOR_STATUS_PASS_ADD" wait 2ms
    nas -> aaa tacacs acct   seq 1 flags 1 session_id 900103 user "netadmin" data "task_id=42;service=shell;cmd=reload"
}

flow radius_ipv6_avps(nas6, aaa6) {
    // Automatically encodes RFC 3162 NAS-IPv6-Address (95) and RFC 6911 Framed-IPv6-Address (168)
    nas6 -> aaa6 radius access_request id 20 user "bob@corp.example" nas_ip 2001:db8:60::10 service_type 2 wait 2ms
    nas6 <- aaa6 radius access_accept  id 20 user "bob@corp.example" framed_ip 2001:db8:60:20::55
}

compile {
    nac_and_cli_audit(access_sw, aaa_server)
    radius_ipv6_avps(sw_v6, aaa_v6)
}
```

### 4. Benchmark SIEM Grok Parsers & Flow Collectors (`SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`) on Demand
Waiting for a hardware router's active flow timeout or generating 20 GB of synthetic traffic on a laptop just to test **ElastiFlow**, **Akvorado**, `pmacct`, `nfcapd`, or **Splunk** alerts is a waste of an afternoon. Declare the exact byte/packet counters and syslog fields in four lines:

```frameassembly
host core_exporter { ip 10.250.10.1   mac 00:50:56:fa:00:01 }
host telemetry_col { ip 10.250.10.100 mac 00:50:56:fa:01:00 }
host leaf_v6       { ip 2001:db8:fa::1 }
host collector_v6  { ip 2001:db8:fa::100 }

flow observability_ingest(rtr, col) {
    // 1. UDP 514 Syslog warning (PRI 132) + reliable TCP 514 SSH security audit log
    rtr -> col syslog facility 16 severity 4 hostname "core-rtr-01" app "bgpd" procid "1842" msgid "BGP-4-MAXPFX" msg "Neighbor 198.51.100.1 prefix count 85000 exceeds 80% threshold" wait 1ms
    rtr -> col tcp syn srcport 51514 dstport 514 win 65535 mss 1460 wait 1ms
    rtr <- col tcp syn ack win 65535 mss 1460 wait 1ms
    rtr -> col tcp ack wait 1ms
    rtr -> col transport tcp syslog facility 10 severity 5 hostname "core-rtr-01" app "sshd" procid "4410" msgid "SEC_LOGIN" msg "Accepted publickey for netadmin from 10.254.0.10 port 54122 ssh2" wait 2ms

    // 2. NetFlow v5 (UDP 2055), IPFIX v10 (UDP 4739), and sFlow v5 (UDP 6343) elephant-flow exports
    rtr -> col netflow srcip 198.51.100.25 dstip 203.0.113.80 srcport 51200 proto 6 packets 154000 octets 215600000 wait 1ms
    rtr -> col ipfix domain_id 4001 srcip 198.51.100.25 dstip 203.0.113.80 srcport 51200 proto 6 packets 154000 octets 215600000 wait 1ms
    rtr -> col sflow agent_ip 10.250.10.1 sub_agent_id 1 seq 105 uptime 86400000 samples 1
}

flow ipv6_telemetry(sw6, col6) {
    sw6 -> col6 syslog facility 23 severity 2 hostname "leaf-sw-v6" app "envmon" msgid "FAN-2-FAIL" msg "Tray 2 Fan 1 RPM below critical threshold" wait 1ms
    sw6 -> col6 sflow agent_ip 2001:db8:fa::1 sub_agent_id 2 seq 500 uptime 172800000 samples 1
}

compile {
    observability_ingest(core_exporter, telemetry_col)
    ipv6_telemetry(leaf_v6, collector_v6)
}
```

## What FrameAssembly Handles for You

* **Message-Aware UDP Port & Multicast Routing:** `dhcp` flips between `68 <-> 67` (IPv4) and `546 <-> 547` (IPv6); `ptp` routes Event messages (`sync`, `delay_req`) to `UDP 319` and General messages (`announce`, `follow_up`, `delay_resp`) to `UDP 320`; `radius` routes Auth to `UDP 1812` and Accounting to `UDP 1813`; `mdns` targets `224.0.0.251` (`01:00:5e:00:00:fb`) or `ff02::fb` (`33:33:00:00:00:fb`) automatically.
* **RFC-Compliant DNS Compression & TCP Framing:** `dns` encodes length-prefixed labels, compresses Answer names (`0xC00C`), and prepends the mandatory 2-byte big-endian message length header whenever `transport tcp` is added.
* **Zero-Math Headers & Identities:** `syslog` computes `<PRI>` from `(facility * 8) + severity`, `ptp` derives an IEEE EUI-64 `ClockIdentity` from the sender's MAC when `clock_id` is omitted, and `dhcp` inherits the sender's MAC into `chaddr` / Option 1 DUID-LL.
* **Dual-Stack Telemetry & AAA Attributes:** `radius` switches `nas_ip` and `framed_ip` from IPv4 AVPs (`4` / `8`) to IPv6 AVPs (`95` / `168`) on IPv6 flows, and `sflow` sets `address_type` `1` (IPv4) or `2` (IPv6) automatically.

## Infrastructure & Telemetry Protocol Reference

### 1. Naming, Service Discovery and DHCP (`DNS`, `MDNS`, `DHCP`)

| Protocol | Flags / Types | Key Modifiers | Wire Behavior & Defaults |
| :--- | :--- | :--- | :--- |
| **`dns`** | `query` (default), `response` | `txid <u16>`, `qname "<domain>"`, `qtype "<type>"`, `rdata "<val>"`, `rcode <0..15>`, `ans_ttl <u32>`, `transport tcp` | `qtype`: `"A"`, `"AAAA"`, `"CNAME"`, `"NS"`, `"PTR"`, `"MX"`, `"TXT"`, `"SOA"`, `"SRV"`, `"AXFR"`, `"ANY"`; `rcode`: `0` NOERROR, `2` SERVFAIL, `3` NXDOMAIN, `5` REFUSED |
| **`mdns`** | `query` (default), `response` | Same modifiers as `dns` (`txid`, `qname`, `qtype`, `rdata`, `rcode`, `ans_ttl`) | `UDP 5353`; auto-targets `224.0.0.251` (IPv4) or `ff02::fb` (IPv6) with RFC multicast MACs |
| **`dhcp`** | v4: `discover`, `offer`, `request`, `ack`, `release`<br>v6: `solicit`, `advertise`, `request`, `reply`, `release` | `xid <u32>`, `chaddr <mac>`, `ciaddr <ipv4>`, `yiaddr <ipv4>`, `siaddr <ipv4>`, `subnet_mask <ipv4>`, `router <ipv4>`, `dns_server <ipv4>`, `hostname "<str>"`, `lease_time <u32>` | Builds 236B BOOTP + `0x63825363` cookie + TLV options on IPv4 (`68/67`) or RFC 8415 DHCPv6 + Option 1 DUID-LL on IPv6 (`546/547`) |

> **Quick Syntax Check (`dns` & `dhcp`):** `query` and `response` are standalone flags—always pass the domain name via `qname "<domain>"` (never `dns query "example.com"`). On `dhcp`, use `xid <u32>` to set the BOOTP / DHCPv6 Transaction ID.

### 2. Clock Sync and Precision Timing (`NTP`, `PTP`)

| Protocol | Sub-Keywords / Modes | Modifiers | Wire Notes & Defaults |
| :--- | :--- | :--- | :--- |
| **`ntp`** | `mode <0..7>` (`3` Client default, `4` Server, `5` Broadcast) | `li <0..3>`, `vn <1..4>`, `stratum <0..16>`, `poll <u8>`, `precision <i8>`, `refid "<4char>"`, `tx_timestamp <u64>` | 48-byte RFC 5905 frame on `UDP 123`; `stratum 0` = Kiss-o'-Death (`"RATE"`), `1` = Primary (`"GPS"`, `"PPS"`) |
| **`ptp`** | `sync` (default), `delay_req`, `follow_up`, `delay_resp`, `announce` (or `msg_type "<type>"`) | `domain <0..255>`, `seq_id <u16>`, `clock_id "<8char>"` | 44-byte IEEE 1588v2 frame; `UDP 319` (`sync`, `delay_req`) vs. `UDP 320` (`follow_up`, `delay_resp`, `announce`) |

### 3. AAA Access and CLI Auditing (`RADIUS`, `TACACS`)

| Protocol | Packet Types | Modifiers | Wire Notes & Defaults |
| :--- | :--- | :--- | :--- |
| **`radius`** | `access_request` (default), `access_accept`, `access_reject`, `access_challenge`, `accounting_request`, `accounting_response` (or `code "<name>"`) | `id <u8>`, `user "<str>"`, `nas_ip <ip>`, `service_type <u32>`, `framed_ip <ip>` | `UDP 1812` (Auth) / `UDP 1813` (Acct); `service_type`: `1` Login, `2` Framed/802.1X, `6` Admin |
| **`tacacs`** | `authen` (default), `author`, `acct` (or `type <authen\|author\|acct>`) | `seq <u8>`, `flags <u8>`, `session_id <u32>`, `user "<str>"`, `data "<str>"`, `payload "<str>"` | `TCP 49`; `flags` defaults to `0x01` (`UNENCRYPTED_FLAG`) so Wireshark dissects CLI commands |

### 4. Logging and Flow Telemetry (`SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`)

| Protocol | Modifiers | Default Port & Wire Behavior |
| :--- | :--- | :--- |
| **`syslog`** | `facility <0..23>`, `severity <0..7>`, `pri <0..191>`, `hostname "<str>"`, `app "<str>"`, `procid "<str>"`, `msgid "<str>"`, `msg "<str>"`, `transport tcp` | `UDP 514` (or `TCP 514` with `transport tcp`); RFC 5424 record with `PRI = (facility * 8) + severity` |
| **`netflow`**| `srcip <ip>`, `dstip <ip>`, `srcport <u16>`, `dstport <u16>`, `proto <u8>`, `packets <u32>`, `octets <u32>` | `UDP 2055`; 72-byte Cisco NetFlow v5 header + flow record (`proto`: `1` ICMP, `6` TCP, `17` UDP) |
| **`ipfix`** | `domain_id <u32>`, `srcip <ip>`, `dstip <ip>`, `srcport <u16>`, `dstport <u16>`, `proto <u8>`, `packets <u32>`, `octets <u32>` | `UDP 4739`; RFC 7011 IPFIX v10 header + Data Set `256` with 64-bit packet/octet counters |
| **`sflow`** | `agent_ip <ip>` (alias `agentip`), `sub_agent_id <u32>`, `seq <u32>`, `uptime <u32>`, `samples <u32>` | `UDP 6343`; dual-stack sFlow v5 header + 32-byte Format `1` Flow Sample record |

#### Handy RFC 5424 `SYSLOG` Severity & Facility Codes

| `severity` | Level | Meaning | Common `facility` | Subsystem |
| :---: | :--- | :--- | :---: | :--- |
| `0` / `1` | `emerg` / `alert` | System unusable / immediate action | `0` / `1` / `3` | `kern` / `user` (default) / `daemon` |
| `2` / `3` | `crit` / `err` | Hardware fault / operational error | `4` / `10` | `auth` / `authpriv` (security & logins) |
| `4` / `5` | `warning` / `notice` | Threshold crossed / config or ACL event | `16`..`19` | `local0`..`local3` (router & switch NOS) |
| `6` / `7` | `info` / `debug` | Routine message (`6` default) / trace | `20`..`23` | `local4`..`local7` (firewalls, VPN, audit) |

## Inspecting and Replaying Infrastructure Captures

```console
# Extract DNS queries/rcodes, Syslog messages, and IPFIX byte counters in tshark
$ tshark -r infra_check.pcap -T fields -e frame.number -e dns.qry.name -e dns.flags.rcode -e syslog.msg -e cflow.octets64

# Test Suricata rules against DNS sinkholes, rogue DHCP, or AXFR zone transfers
$ suricata -r ddi_and_onboarding.pcap -k none

# Replay syslog and flow exports into a live SIEM or collector interface
$ sudo tcpreplay -i eth0 observability_ingest.pcap
```

## Related Documentation

* [**Getting Started (`getting_started.md`)**](getting_started.md) — Core `host` / `flow` / `compile` mechanics, MAC formats, and `frameassembly show`.
* [**Real-World Use Cases (`use_cases.md`)**](use_cases.md) — Copy-paste recipes for firewall audits, QoS trunks, SIEM ingest, and OT conduits.
* [**Layer 2 — Switching & Data Link (`l2_protocols.md`)**](l2_protocols.md) — Pair `802.1X eapol` and `vlan` / `qinq` / `mpls` tags with `radius` and `dhcp`.
* [**Layer 3 — Routing, Overlays, Tunnels & VPNs (`l3_protocols.md`)**](l3_protocols.md) — Combine `ospf`, `bgp`, `bfd`, and `vxlan` with `syslog` and `ipfix`.
* [**Layer 4 — Stateful TCP, UDP & Telecom SCTP (`l4_transports.md`)**](l4_transports.md) — Stateful `tcp` handshakes, `udp`, and `transport tcp` switching.
* [**SNMPv1, SNMPv2c & Encrypted SNMPv3 (`l7_snmp.md`)**](l7_snmp.md) — Poll MIBs and fire encrypted `snmp3` `authPriv` traps alongside syslog/flow exports.
* [**Topologies & Dual-Stack (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Full Campus 802.1X NAC and EVPN-VXLAN IPFIX fabric captures.