# Practical Use Cases & Cookbook for Network Engineers

Testing a new firewall ACL, an encrypted SNMPv3 trap alert in Checkmk or Zabbix, a Shadow IT detection rule, an 802.1ad QinQ / MPLS trunk, or an industrial OT conduit usually means hours of lab cabling, MIB hunting, or fighting raw-socket scripts. Every recipe in this cookbook replaces that setup with ready-to-run `.fasm` code built from up to three sections:
- **`host` blocks** declare the devices on your network diagram (`ip` and optional `mac`, or a MAC-only `host sw1 { mac 00:1c:73:00:00:01 }` for Layer 2 switching protocols).
- **`flow(a, b)` blocks** *(optional)* group packet-by-packet exchanges between role names (`a -> b` sends forward; `a <- b` sends a reply from `b` back to `a`).
- **`compile` block** plugs your `host` devices into those flow roles in left-to-right order—or lets you write packet statements directly inside `compile { ... }` without a `flow` block—to emit the `.pcap`.

To run any recipe below:
1. Save the `.fasm` code to a file (for example, `scenario.fasm`), preview the packet ladder in your terminal with `frameassembly show scenario.fasm`, and compile with `frameassembly scenario.fasm` (writes `scenario.pcap` by default, or pass a second path like `frameassembly scenario.fasm custom.pcapng`).
2. Replay or inspect `scenario.pcap` with **`tcpreplay`**, **Wireshark** / **`tshark`**, or **Suricata** / **Zeek**.
3. Need to turn an existing `.pcap` or `.pcapng` capture into `.fasm` code so you can anonymize customer IPs or tweak headers? Run `frameassembly reverse trace.pcap` (writes `trace.fasm` by default, or pass `frameassembly reverse trace.pcap sanitized.fasm`).

---

## "I Need to Test..." $\rightarrow$ Jump to Recipe

| I Need to Test or Troubleshoot... | Protocols & Header Features Used | Jump Directly to Recipe |
| :--- | :--- | :--- |
| **Checkmk / Zabbix / PRTG / LibreNMS / `snmptrapd` alerts (`linkDown`, temperature, `Counter64` polls)** | `snmp1`, `snmp2` (`trap`, `inform`, `get`, `response`, `varbind`) | [Recipe 1A — SNMPv1 & SNMPv2c Traps, Polls & Informs](#recipe-1a--snmpv1-genericenterprise-traps--snmpv2c-polls-traps-and-informs) |
| **Encrypted SNMPv3 `authPriv` traps in Checkmk Event Console, Zabbix & PRTG (`SHA-256`/`SHA-512` + `AES-128`)** | `snmp3` (`auth sha256`/`sha512`/`md5`/`sha`, `priv aes`/`des`, `engineid`) | [Recipe 1B — Simulate Encrypted SNMPv3 `authPriv` Traps for Checkmk, Zabbix & PRTG](#recipe-1b--simulate-encrypted-snmpv3-authpriv-traps-for-checkmk-zabbix--prtg) |
| **Stateful DMZ / perimeter firewall rules with `tcpreplay` (HTTPS handshakes, `tcp rst`, stealth scans)** | `tcp` (`syn`, `rst ack`, out-of-state `ack`, `fin psh urg`), `vlan`, `icmp` (`code 13`) | [Recipe 2A — Stateful Firewall Policy Audit](#recipe-2a--dmz--perimeter-firewall-policy-audit-handshakes-rejections-out-of-state--stealth-probes) |
| **VPN / WAN blackhole MTU issues (`df` bit), IPv4 fragment reassembly, or BCP 38 IP spoofing** | `df`, `ipid`, `mf`, `fragoffset`, `icmp` (`destunreach code 4`), spoofed `host` | [Recipe 2B — Path MTU (`df`), IPv4 Fragmentation & Anti-Spoofing](#recipe-2b--path-mtu-discovery-df-ipv4-fragmentation-mf--fragoffset--spoofed-source-egress-filtering) |
| **Switch 802.1Q trunk queues, 802.1p CoS priority (`pcp`/`dei`), and VoIP/Video `dscp` QoS** | `vlan`, `pcp`, `dei`, `dscp` (`46` EF, `34` AF41, `48` CS6, `8` CS1), `ecn`, `rtp`, `bfd` | [Recipe 3A — 802.1Q Trunk & DiffServ QoS Verification](#recipe-3a--8021q-trunk--voice--video--scavenger-diffserv-qos-verification) |
| **Carrier Metro Ethernet 802.1ad `qinq` double-tagging or MPLS L3VPN label forwarding** | `qinq`, `innervlan`, `mpls` (`exp`, `bos`, `mplsttl`), `dscp` | [Recipe 3B — Carrier 802.1ad `qinq` & MPLS WAN Backhaul](#recipe-3b--carrier-8021ad-qinq-double-tagging--mpls-wan-backhaul-verification) |
| **SIEM syslog parsers (`UDP`/`TCP 514`) or flow collectors (ElastiFlow, Akvorado, `nfdump`)** | `syslog` (`transport tcp`), `netflow` (v5), `ipfix` (v10), `sflow` (v5) | [Recipe 4A — SIEM & Flow Collector Ingest](#recipe-4a--siem--flow-collector-ingest-syslog-over-udptcp-netflow-v5-ipfix-v10--sflow-v5) |
| **Suricata / Zeek / Snort IDS rules, DNS sinkholes, TLS 1.3 `sni` filtering, or WAF headers** | `dns` (`rcode 5`), `tls` (`clienthello`, `sni`, `alpn`, `alert`), `http` (`header`, `body`) | [Recipe 4B — IDS/IPS & DPI Signature Validation](#recipe-4b--idsips--dpi-signature-validation-dns-sinkhole-tls-13-snialpn--custom-http-headers) |
| **Shadow IT uploads, unauthorized `quic` / DoH on UDP 443, rogue `dhcp` servers, or `mdns`/`ssdp`** | `tls` (`sni`), `quic` (`initial`), `dhcp` (`discover`, `offer`), `mdns`, `ssdp` | [Recipe 4C — Shadow IT & Unauthorized Network Activity Detection QA](#recipe-4c--shadow-it--unauthorized-network-activity-detection-qa) |
| **Industrial OT firewall ACLs & SCADA sensors (`read` vs. `write`/`operate`) without physical PLCs** | `modbus`, `s7comm`, `dnp3` (auto CRC-16), `bacnet`, `ethernetip`, `opcua` | [Recipe 5 — Purdue Level 1–3.5 OT / SCADA Conduit Validation](#recipe-5--purdue-level-135-conduit-validation-modbus-s7comm-dnp3-bacnet-ethernetip--opcua) |
| **Application stalls caused by a full receive buffer (`TCP ZeroWindow` & Window Update)** | `tcp` (`win 0`, Keep-Alive probe, `win 32768`), `http` (`post`, `202 Accepted`) | [Recipe 6A — TCP Zero-Window Stall & Recovery Reproducer](#recipe-6a--application-troubleshooting-reproducer-tcp-zero-window-stall--window-update-recovery) |
| **Core router & gateway HA failover timeline (`bfd` down $\rightarrow$ `ospf`/`bgp` $\rightarrow$ `vrrp`/`hsrp`/GARP)** | `bfd`, `ospf`, `bgp`, `vrrp`, `hsrp`, `arp` (`gratuitous`) | [Recipe 6B — Routing & First-Hop Redundancy HA Failover](#recipe-6b--routing--first-hop-redundancy-failover-bfd--ospf--bgp--vrrp--hsrp--gratuitous-arp) |
| **Decompiling & anonymizing customer `.pcap` traces for vendor TAC tickets (`frameassembly reverse`)** | `frameassembly reverse` (`host1`, `host2`, IP/SNI scrubbing, auto checksum/SEQ recalc) | [Recipe 6C — Decompiling & Anonymizing Customer `.pcap` Captures](#recipe-6c--decompiling--anonymizing-customer-pcap-captures-for-vendor-support-tickets-frameassembly-reverse) |

---

## Table of Contents

1. [Simulating SNMP Traps & Polls for Checkmk, Zabbix & PRTG (`snmp1`, `snmp2` & Encrypted `snmp3`)](#1-simulating-snmp-traps--polls-for-checkmk-zabbix--prtg-snmp1-snmp2--encrypted-snmp3)
   * [Recipe 1A — `snmp1` Generic/Enterprise Traps & `snmp2` Polls, Traps, and Informs](#recipe-1a--snmpv1-genericenterprise-traps--snmpv2c-polls-traps-and-informs)
   * [Recipe 1B — Simulate Encrypted SNMPv3 `authPriv` Traps for Checkmk, Zabbix & PRTG](#recipe-1b--simulate-encrypted-snmpv3-authpriv-traps-for-checkmk-zabbix--prtg)
2. [Stateful Firewall Rule, VLAN Trunk & ACL Testing with `tcpreplay`](#2-stateful-firewall-rule-vlan-trunk--acl-testing-with-tcpreplay)
   * [Recipe 2A — DMZ & Perimeter Firewall Policy Audit (Handshakes, Rejections, Out-of-State & Stealth Probes)](#recipe-2a--dmz--perimeter-firewall-policy-audit-handshakes-rejections-out-of-state--stealth-probes)
   * [Recipe 2B — Path MTU Discovery (`df`), IPv4 Fragmentation (`mf` + `fragoffset`) & Spoofed Source Egress Filtering](#recipe-2b--path-mtu-discovery-df-ipv4-fragmentation-mf--fragoffset--spoofed-source-egress-filtering)
3. [Testing VLAN Trunks, Carrier QinQ, MPLS & DiffServ QoS Policies](#3-testing-vlan-trunks-carrier-qinq-mpls--diffserv-qos-policies)
   * [Recipe 3A — 802.1Q Trunk & Voice / Video / Scavenger DiffServ QoS Verification](#recipe-3a--8021q-trunk--voice--video--scavenger-diffserv-qos-verification)
   * [Recipe 3B — Carrier 802.1ad `qinq` Double-Tagging & MPLS WAN Backhaul Verification](#recipe-3b--carrier-8021ad-qinq-double-tagging--mpls-wan-backhaul-verification)
4. [Validating SIEMs, Flow Collectors, IDS/IPS & Shadow IT Detection](#4-validating-siems-flow-collectors-idsips--shadow-it-detection)
   * [Recipe 4A — SIEM & Flow Collector Ingest (`syslog` over UDP/TCP, `netflow` v5, `ipfix` v10 & `sflow` v5)](#recipe-4a--siem--flow-collector-ingest-syslog-over-udptcp-netflow-v5-ipfix-v10--sflow-v5)
   * [Recipe 4B — IDS/IPS & DPI Signature Validation (DNS Sinkhole, TLS 1.3 `sni`/`alpn` & Custom HTTP Headers)](#recipe-4b--idsips--dpi-signature-validation-dns-sinkhole-tls-13-snialpn--custom-http-headers)
   * [Recipe 4C — Shadow IT & Unauthorized Network Activity Detection QA](#recipe-4c--shadow-it--unauthorized-network-activity-detection-qa)
5. [Stateful OT Firewall & SCADA ACL Testing with `tcpreplay` (Without Physical PLCs)](#5-stateful-ot-firewall--scada-acl-testing-with-tcpreplay-without-physical-plcs)
   * [Recipe 5 — Purdue Level 1–3.5 Conduit Validation (`modbus`, `s7comm`, `dnp3`, `bacnet`, `ethernetip` & `opcua`)](#recipe-5--purdue-level-135-conduit-validation-modbus-s7comm-dnp3-bacnet-ethernetip--opcua)
6. [Decompiling Customer `.pcap` Captures (`reverse`) & Zero-Noise Incident Reproducers](#6-decompiling-customer-pcap-captures-reverse--zero-noise-incident-reproducers)
   * [Recipe 6A — Application Troubleshooting Reproducer: TCP Zero-Window Stall & Window Update Recovery](#recipe-6a--application-troubleshooting-reproducer-tcp-zero-window-stall--window-update-recovery)
   * [Recipe 6B — Routing & First-Hop Redundancy Failover (`bfd` + `ospf` + `bgp` + `vrrp` / `hsrp` + Gratuitous `arp`)](#recipe-6b--routing--first-hop-redundancy-failover-bfd--ospf--bgp--vrrp--hsrp--gratuitous-arp)
   * [Recipe 6C — Decompiling & Anonymizing Customer `.pcap` Captures for Vendor Support Tickets (`frameassembly reverse`)](#recipe-6c--decompiling--anonymizing-customer-pcap-captures-for-vendor-support-tickets-frameassembly-reverse)

---

## 1. Simulating SNMP Traps & Polls for Checkmk, Zabbix & PRTG (`snmp1`, `snmp2` & Encrypted `snmp3`)

When setting up trap alerting in **Checkmk** Event Console, **Zabbix**, **PRTG**, **LibreNMS**, **SolarWinds**, or **`snmptrapd`**, testing end-to-end alert delivery manually is painful:
* You cannot yank fiber uplinks out of a core switch or overheat chassis power supplies in production just to verify that an on-call pager fires on `linkDown` or thermal alarms.
* Net-SNMP's `snmptrap` CLI demands a dozen cryptic positional flags (`-v 3 -l authPriv -e 0x8000... -u ... -a SHA-256 -A ... -x AES -X ... -Z boots,time`), local MIB files, and manual source-IP spoofing if the receiver filters alerts by switch IP.

FrameAssembly replaces all of that with a few lines of `.fasm` code plus `frameassembly` and `tcpreplay`—encoding ASN.1 BER varbinds, preserving the exact switch source IP and VLAN tag, and computing RFC 3414 / 3826 / 7860 SNMPv3 USM key localization, HMAC digests, and DES/AES encryption automatically.

### Recipe 1A — SNMPv1 Generic/Enterprise Traps & SNMPv2c Polls, Traps, and Informs

Save as `snmp_v1_v2c_alerts.fasm`:

```frameassembly
host core_switch {
    ip 10.100.0.254
    mac 00:1c:73:a0:00:fe
}

host nms_collector {
    ip 10.100.0.10
    mac 00:50:56:a0:00:10
}

flow snmp_v1_and_v2c_verification(sw, nms) {
    // 1. SNMPv1 generic linkDown trap (gentrap 2, spectrap 0) for interface index 5
    sw -> nms snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.1.1 agentip 10.100.0.254 gentrap 2 spectrap 0 sysuptime 125000 varbind 1.3.6.1.2.1.2.2.1.1.5 int 5 varbind 1.3.6.1.2.1.2.2.1.2.5 string "GigabitEthernet0/5" wait 5ms

    // 2. SNMPv1 vendor enterprise-specific trap (gentrap 6, spectrap 1 = chassis temperature alarm)
    sw -> nms snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.9.13.3 agentip 10.100.0.254 gentrap 6 spectrap 1 sysuptime 125100 varbind 1.3.6.1.4.1.9.9.13.1.3.1.3.1 gauge32 84 wait 10ms

    // 3. SNMPv2c GET poll from NMS and switch RESPONSE with sysName.0 and sysUpTime.0
    nms -> sw snmp2 get community "noc_ro" reqid 1001 varbind 1.3.6.1.2.1.1.5.0 null varbind 1.3.6.1.2.1.1.3.0 null wait 2ms
    nms <- sw snmp2 response community "noc_ro" reqid 1001 varbind 1.3.6.1.2.1.1.5.0 string "core-sw-01.dc1.example.com" varbind 1.3.6.1.2.1.1.3.0 timeticks 8640000 wait 10ms

    // 4. SNMPv2c linkUp trap (1.3.6.1.6.3.1.1.5.4) with 64-bit interface counter (Counter64)
    sw -> nms snmp2 trap community "noc_traps" reqid 2001 sysuptime 125500 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.31.1.1.1.1.5 string "TenGigabitEthernet1/1/5" varbind 1.3.6.1.2.1.31.1.1.1.6.5 counter64 9876543210 wait 10ms

    // 5. SNMPv2c acknowledged InformRequest and NMS Response from UDP port 162
    sw -> nms snmp2 inform community "noc_traps" reqid 2002 sysuptime 126000 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.2.2.1.8.5 int 1 wait 2ms
    sw <- nms snmp2 response community "noc_traps" srcport 162 reqid 2002 varbind 1.3.6.1.2.1.2.2.1.8.5 int 1
}

compile {
    snmp_v1_and_v2c_verification(core_switch, nms_collector)
}
```

#### Compile, Inspect & Replay:
```bash
frameassembly snmp_v1_v2c_alerts.fasm snmp_v1_v2c_alerts.pcap

# Verify PDU types, community strings, and varbind OIDs in tshark
tshark -r snmp_v1_v2c_alerts.pcap -Y "snmp" -V

# Replay traps toward your monitoring server on eth0
sudo tcpreplay -i eth0 snmp_v1_v2c_alerts.pcap
```

### Recipe 1B — Simulate Encrypted SNMPv3 `authPriv` Traps for Checkmk, Zabbix & PRTG

Unlike SNMPv3 `GET` polling (where the NMS discovers the switch's EngineID first), **SNMPv3 traps are unidirectional**: **Checkmk**'s Event Console (`Credentials for SNMPv3 traps`), **Zabbix** (`snmptrapd.conf` `createUser -e`), and **PRTG**'s SNMP Trap Receiver silently drop `authPriv` traps if the `engineid`, `engineboots`, `enginetime`, authentication hash, or AES privacy key has even a single mismatch—and debugging silent drops without a known-good packet capture is miserable.

This recipe synthesizes authenticated, encrypted **SNMPv3 USM (`authPriv`)** packets with explicit `engineid`, `engineboots`, `enginetime`, and `contextname` across **RFC 7860 SHA-2** (`sha256`, `sha512`) + **RFC 3826 `aes` (AES-128-CFB)** as well as legacy **RFC 3414 `md5`/`sha`** + **`des`** for older UPS/PDU hardware—preserving the real switch IP (`10.100.0.250`) so Checkmk host matching and Zabbix SNMP trapper items trigger exactly as they will in production.

Save as `snmp_v3_encrypted.fasm`:

```frameassembly
host dist_router {
    ip 10.100.0.250
    mac 00:1c:73:a0:00:fa
}

host trap_receiver {
    ip 10.100.0.10
    mac 00:50:56:a0:00:10
}

flow snmpv3_usm_authpriv_suite(rtr, nms) {
    // 1. Modern SNMPv3 authPriv TRAP for Checkmk Event Console / Zabbix / PRTG: HMAC-SHA256 + AES-128-CFB
    rtr -> nms snmp3 trap user "ops_sha256_aes" engineid "80001f8880001c73a000fa" engineboots 14 enginetime 86400 contextname "dc1_vrf" auth sha256 "AuthSecret_SHA256_2026!" priv aes "PrivSecret_AES128_2026!" reqid 3001 oid 1.3.6.1.4.1.9.9.13.3.0.1 varbind 1.3.6.1.2.1.1.5.0 string "dist-rtr-01.dc1" varbind 1.3.6.1.4.1.9.9.13.1.3.1.3.1 gauge32 89 wait 10ms

    // 2. High-security SNMPv3 authPriv INFORM + NMS RESPONSE: HMAC-SHA512 + AES-128-CFB
    rtr -> nms snmp3 inform user "sec_sha512_aes" engineid "80001f8880001c73a000fa" engineboots 14 enginetime 86405 contextname "dc1_vrf" auth sha512 "HighSecAuth_SHA512_Key!" priv aes "HighSecPriv_AES128_Key!" reqid 3002 oid 1.3.6.1.6.3.1.1.5.5 varbind 1.3.6.1.2.1.1.5.0 string "dist-rtr-01.dc1" wait 2ms
    rtr <- nms snmp3 response srcport 162 user "sec_sha512_aes" engineid "80001f8880001c73a000fa" engineboots 14 enginetime 86405 contextname "dc1_vrf" auth sha512 "HighSecAuth_SHA512_Key!" priv aes "HighSecPriv_AES128_Key!" reqid 3002 varbind 1.3.6.1.2.1.1.5.0 string "dist-rtr-01.dc1" wait 10ms

    // 3. Legacy SNMPv3 authPriv TRAPs for older UPS/branch appliances: HMAC-MD5 + DES and HMAC-SHA1 + DES
    rtr -> nms snmp3 trap user "legacy_ups_md5" engineid "80001f8880001c73a000fa" engineboots 3 enginetime 43200 auth md5 "LegacyUpsAuthMD5!" priv des "LegacyUpsPrivDES!" reqid 3003 oid 1.3.6.1.2.1.33.2.0.1 varbind 1.3.6.1.2.1.33.1.2.1.0 int 3 wait 10ms
    rtr -> nms snmp3 trap user "legacy_rtr_sha1" engineid "80001f8880001c73a000fa" engineboots 3 enginetime 43210 auth sha "LegacyRtrAuthSHA1!" priv des "LegacyRtrPrivDES!" reqid 3004 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.2.2.1.1.2 int 2
}

compile {
    snmpv3_usm_authpriv_suite(dist_router, trap_receiver)
}
```

#### Compile, Decrypt in Wireshark & Replay into Checkmk / Zabbix / PRTG:
```bash
frameassembly snmp_v3_encrypted.fasm snmp_v3_encrypted.pcap

# Inspect SNMPv3 USM header fields (EngineID, Boots, Time, User, Auth/Priv parameters)
tshark -r snmp_v3_encrypted.pcap -T fields -e frame.number -e snmp.msgUserName -e snmp.msgAuthoritativeEngineID -e snmp.msgAuthoritativeEngineBoots -e snmp.msgAuthoritativeEngineTime

# Replay directly toward your Checkmk site, Zabbix snmptrapd host, or PRTG probe interface
sudo tcpreplay -i eth0 snmp_v3_encrypted.pcap

# Decrypt the ScopedPDU in Wireshark GUI to verify varbinds before touching NMS settings:
#   Edit -> Preferences -> Protocols -> SNMP -> Users Table -> Edit...
#   Engine ID: 80001f8880001c73a000fa | Username: ops_sha256_aes
#   Auth model: SHA2-256 | Auth password: AuthSecret_SHA256_2026!
#   Priv protocol: AES   | Priv password: PrivSecret_AES128_2026!
wireshark snmp_v3_encrypted.pcap &
```

---

## 2. Stateful Firewall Rule, VLAN Trunk & ACL Testing with `tcpreplay`

Standard Linux utilities (`ping`, `curl`, `nc`) run through the local kernel's TCP/IP stack, so you cannot emit an out-of-state `ack` packet without an active socket, bundle a permitted HTTPS handshake and a rejected `rst ack` into a single test file, or test how **Palo Alto**, **FortiGate**, **CheckPoint**, or `nftables` handles fragmented packets and spoofed source IPs across 802.1Q VLAN trunks.

### Recipe 2A — DMZ & Perimeter Firewall Policy Audit (Handshakes, Rejections, Out-of-State & Stealth Probes)

Save as `firewall_dmz_audit.fasm`:

```frameassembly
host untrusted_client {
    ip 198.51.100.42
    mac 00:0c:29:11:22:33
}

host dmz_reverse_proxy {
    ip 203.0.113.10
    mac 00:1b:21:aa:bb:cc
}

flow perimeter_acl_audit(ext, dmz) {
    // 1. Permitted TCP port 443 (HTTPS) 3-way handshake with modern TCP options
    ext -> dmz tcp syn srcport 51001 dstport 443 win 64240 mss 1460 wscale 7 sackperm wait 1ms
    ext <- dmz tcp syn ack win 65535 mss 1460 wscale 7 sackperm wait 1ms
    ext -> dmz tcp ack wait 5ms

    // 2. Blocked MySQL port 3306 connection attempt rejected immediately with TCP RST+ACK
    ext -> dmz tcp syn srcport 51002 dstport 3306 win 64240 mss 1460 wait 1ms
    ext <- dmz tcp rst ack wait 5ms

    // 3. Out-of-state TCP ACK scan on SSH port 22 (verifies stateful firewall drops unsolicited ACKs)
    ext -> dmz tcp ack srcport 51003 dstport 22 seq 85000 acknum 42000 win 1024 wait 5ms

    // 4. Christmas-tree stealth probe (FIN + PSH + URG) on SMB port 445
    ext -> dmz tcp fin psh urg srcport 51004 dstport 445 win 1024 urgent 1 wait 5ms

    // 5. Blocked ICMP ping across DMZ VLAN 40 answered with ICMP Destination Unreachable,
    //    Code 13 (Communication Administratively Prohibited by ACL)
    ext -> dmz vlan 40 ttl 64 icmp echorequest id 900 seq 1 payload "DMZ_PING_AUDIT" wait 1ms
    ext <- dmz vlan 40 ttl 64 icmp destunreach code 13
}

compile {
    perimeter_acl_audit(untrusted_client, dmz_reverse_proxy)
}
```

#### Compile, Inspect & Replay:
```bash
frameassembly firewall_dmz_audit.fasm firewall_dmz_audit.pcap

# Verify TCP flags, ports, and ICMP unreachable code
tshark -r firewall_dmz_audit.pcap

# Replay into a SPAN/TAP sensor port (or split client/server NICs across an inline firewall via tcpprep + tcpreplay -i eth1 -I eth2)
sudo tcpreplay -i eth1 firewall_dmz_audit.pcap
```

### Recipe 2B — Path MTU Discovery (`df`), IPv4 Fragmentation (`mf` + `fragoffset`) & Spoofed Source Egress Filtering

When tuning IPSec/GRE/VXLAN tunnel overhead or auditing anti-spoofing (BCP 38 / uRPF) rules, you need to verify that:
1. Oversized packets with **Don't Fragment (`df`)** trigger **ICMP Destination Unreachable, Code 4 (Fragmentation Needed and DF Set)** instead of being silently blackholed.
2. Legitimate **IPv4 fragments (`mf` + `fragoffset`)** sharing an `ipid` are reassembled by stateful inspection.
3. Packets from a **spoofed RFC 1918 / external source IP** on an internal port are dropped by ingress/egress ACLs.

Save as `firewall_mtu_frag_spoof.fasm`:

```frameassembly
host branch_client {
    ip 10.40.10.25
    mac 00:1c:73:40:10:25
}

host wan_firewall {
    ip 10.40.10.1
    mac 00:1c:73:40:10:01
}

// Host representing a spoofed external source IP on the same physical LAN MAC
host spoofed_source {
    ip 198.51.100.250
    mac 00:1c:73:40:10:25
}

flow mtu_fragmentation_and_bcp38(client, fw, spoof) {
    // 1. Path MTU Discovery probe with Don't Fragment (df) bit set
    //    Firewall responds with ICMP Type 3, Code 4 (Fragmentation Needed and DF Set)
    client -> fw df ipid 0x3100 ttl 64 udp srcport 55100 dstport 443 payload "PMTUD_PROBE_DO_NOT_FRAGMENT_PAYLOAD" wait 1ms
    client <- fw ttl 64 icmp destunreach code 4 wait 5ms

    // 2. IPv4 Fragmentation inspection test (both fragments share IPID 0x4242):
    //    Fragment 1: MF bit set, fragment offset 0 (first 16 bytes = 2 x 8-byte blocks)
    client -> fw ipid 0x4242 mf fragoffset 0 ttl 64 icmp echorequest id 77 seq 1 payload "FRAG_BLOCK_ONE_A" wait 1ms
    //    Fragment 2: MF bit cleared, fragment offset 2 (starts at byte 16)
    client -> fw ipid 0x4242 fragoffset 2 ttl 64 icmp echorequest id 77 seq 1 payload "FRAG_BLOCK_TWO_B" wait 2ms
    client <- fw ttl 64 icmp echoreply id 77 seq 1 payload "FRAG_REASSEMBLED_OK" wait 5ms

    // 3. BCP 38 / uRPF anti-spoofing test: internal MAC attempting to send with an external source IP
    spoof -> fw ttl 64 udp srcport 59999 dstport 53 payload "SPOOFED_EGRESS_TEST"
}

compile {
    mtu_fragmentation_and_bcp38(branch_client, wan_firewall, spoofed_source)
}
```

#### Compile, Inspect & Replay:
```bash
frameassembly firewall_mtu_frag_spoof.fasm firewall_mtu_frag_spoof.pcap

# Check IPv4 DF/MF flags, fragment offsets, and IP IDs
tshark -r firewall_mtu_frag_spoof.pcap -T fields -e frame.number -e ip.src -e ip.dst -e ip.id -e ip.flags.df -e ip.flags.mf -e ip.frag_offset -e icmp.code

# Replay against the firewall inside test port
sudo tcpreplay -i eth2 firewall_mtu_frag_spoof.pcap
```

---

## 3. Testing VLAN Trunks, Carrier QinQ, MPLS & DiffServ QoS Policies

Standard desktop NIC drivers often strip 802.1Q tags before packets reach user space, and normal applications cannot set 802.1p Priority Code Points (`pcp`), Drop Eligible Indicators (`dei`), outer 802.1ad `qinq` S-tags, or MPLS `exp` bits. FrameAssembly writes these headers directly at the Ethernet layer so you can verify switch QoS queues, trunk allowed-VLAN lists, and WAN shapers with `tcpreplay`.

### Recipe 3A — 802.1Q Trunk & Voice / Video / Scavenger DiffServ QoS Verification

Save as `qos_diffserv_trunk.fasm`:

```frameassembly
host access_switch {
    ip 10.20.0.10
    mac 00:1c:73:20:00:10
}

host wan_edge_router {
    ip 10.20.0.1
    mac 00:1c:73:20:00:01
}

flow verify_qos_queues(sw, wan) {
    // 1. Voice VLAN 110: 802.1p CoS 5 (PCP 5, DEI 0) + DiffServ EF (DSCP 46) carrying VoIP RTP audio
    sw -> wan vlan 110 pcp 5 dei 0 dscp 46 rtp pt 0 seq 101 timestamp 1600 ssrc 0x11223344 payload "G711_ULAW_20MS_VOICE" wait 20ms

    // 2. Video Conferencing VLAN 120: 802.1p CoS 4 (PCP 4, DEI 0) + DiffServ AF41 (DSCP 34) + ECN Capable (ECN 2)
    sw -> wan vlan 120 pcp 4 dei 0 dscp 34 ecn 2 rtp pt 96 seq 500 timestamp 90000 ssrc 0x55667788 marker 1 payload "H264_VIDEO_KEYFRAME" wait 10ms

    // 3. Network Control VLAN 10: 802.1p CoS 6 (PCP 6) + DiffServ CS6 (DSCP 48)
    sw -> wan vlan 10 pcp 6 dei 0 dscp 48 ttl 255 bfd state 3 mydisc 1 yourdisc 2 mintx 50000 minrx 50000 mult 3 wait 10ms

    // 4. Scavenger / Bulk Backup VLAN 300: 802.1p CoS 1 (PCP 1), Drop-Eligible (DEI 1) + DiffServ CS1 (DSCP 8)
    sw -> wan vlan 300 pcp 1 dei 1 dscp 8 udp srcport 49500 dstport 873 payload "NIGHTLY_BACKUP_BULK_BLOCK"
}

compile {
    verify_qos_queues(access_switch, wan_edge_router)
}
```

#### Compile, Inspect & Replay:
```bash
frameassembly qos_diffserv_trunk.fasm qos_diffserv_trunk.pcap

# Verify VLAN ID, 802.1p Priority (PCP), Drop Eligible (DEI), DSCP, and ECN markings
tshark -r qos_diffserv_trunk.pcap -T fields -e frame.number -e vlan.id -e vlan.priority -e vlan.dei -e ip.dsfield.dscp -e ip.dsfield.ecn

# Replay onto an 802.1Q trunk port connected to your switch or WAN router
sudo tcpreplay -i eth0 qos_diffserv_trunk.pcap
```

### Recipe 3B — Carrier 802.1ad `qinq` Double-Tagging & MPLS WAN Backhaul Verification

Save as `carrier_qinq_mpls.fasm`:

```frameassembly
host metro_pe_west {
    ip 172.16.250.1
    mac 00:1c:73:fe:00:01
}

host metro_pe_east {
    ip 172.16.250.2
    mac 00:1c:73:fe:00:02
}

flow carrier_backhaul_test(west, east) {
    // 1. IEEE 802.1ad QinQ double-tagged frame:
    //    Provider S-VLAN 2500 (0x88a8) + Customer C-VLAN 110 (0x8100), DSCP 46
    west -> east qinq 2500 innervlan 110 dscp 46 icmp echorequest id 301 seq 1 payload "QINQ_CUSTOMER_A_VOICE" wait 5ms
    west <- east qinq 2500 innervlan 110 dscp 46 icmp echoreply id 301 seq 1 payload "QINQ_CUSTOMER_A_VOICE" wait 5ms

    // 2. IEEE 802.1ad QinQ for a second customer C-VLAN 220 inside the same S-VLAN 2500
    west -> east qinq 2500 innervlan 220 dscp 18 udp srcport 51000 dstport 51000 payload "QINQ_CUSTOMER_B_DATA" wait 5ms

    // 3. MPLS L3VPN high-priority packet (Label 24010, EXP 5, Bottom-of-Stack 1, MPLS TTL 64)
    west -> east mpls 24010 exp 5 bos 1 mplsttl 64 ttl 63 dscp 46 icmp echorequest id 401 seq 1 payload "MPLS_EXP5_PROBE" wait 5ms

    // 4. MPLS best-effort packet (Label 24020, EXP 0, Bottom-of-Stack 1, MPLS TTL 64)
    west -> east mpls 24020 exp 0 bos 1 mplsttl 64 ttl 63 dscp 0 udp srcport 52000 dstport 52000 payload "MPLS_EXP0_BEST_EFFORT"
}

compile {
    carrier_backhaul_test(metro_pe_west, metro_pe_east)
}
```

#### Compile, Inspect & Replay:
```bash
frameassembly carrier_qinq_mpls.fasm carrier_qinq_mpls.pcap

# Extract outer/inner VLAN IDs and MPLS label/EXP/TTL fields
tshark -r carrier_qinq_mpls.pcap -T fields -e frame.number -e vlan.id -e mpls.label -e mpls.exp -e mpls.bottom -e mpls.ttl
```

---

## 4. Validating SIEMs, Flow Collectors, IDS/IPS & Shadow IT Detection

Before deploying a new SIEM parser, flow collector (**ElastiFlow**, **Akvorado**, **pmacct**, **nfdump**), NDR sensor, or IDS/IPS ruleset (**Suricata**, **Zeek**, **Snort**), you need to verify that your pipeline extracts every field and fires the expected alerts—without polluting your test with thousands of unrelated background packets.

### Recipe 4A — SIEM & Flow Collector Ingest (`syslog` over UDP/TCP, `netflow` v5, `ipfix` v10 & `sflow` v5)

Save as `siem_and_flow_collectors.fasm`:

```frameassembly
host core_router {
    ip 10.250.0.1
    mac 00:1c:73:fa:00:01
}

host telemetry_collector {
    ip 10.250.0.100
    mac 00:50:56:fa:00:64
}

flow telemetry_ingest_test(rtr, col) {
    // 1. RFC 5424 Syslog over UDP port 514 (Facility 16 = local0, Severity 2 = Critical)
    rtr -> col syslog facility 16 severity 2 hostname "core-rtr-01.dc1" app "bgpd" procid "1842" msgid "BGP_PEER_DOWN" msg "BGP-3-NOTIFICATION: neighbor 198.51.100.1 Hold Timer Expired" wait 2ms

    // 2. RFC 5424 Syslog over TCP port 514 (3-way handshake + TCP-transported Syslog frame)
    rtr -> col tcp syn srcport 51514 dstport 514 win 65535 mss 1460 wait 1ms
    rtr <- col tcp syn ack win 65535 mss 1460 wait 1ms
    rtr -> col tcp ack wait 1ms
    rtr -> col transport tcp syslog facility 4 severity 4 hostname "core-rtr-01.dc1" app "sshd" procid "9012" msgid "SSH_AUTH_FAIL" msg "Failed password for admin from 198.51.100.99 port 54122 ssh2" wait 5ms

    // 3. Cisco NetFlow v5 export datagram (UDP 2055) reporting an HTTPS flow
    rtr -> col netflow srcip 198.51.100.25 dstip 203.0.113.80 srcport 52400 dstport 443 proto 6 packets 15400 octets 21560000 wait 5ms

    // 4. RFC 7011 IPFIX (NetFlow v10, UDP 4739) export in Observation Domain 4001
    rtr -> col ipfix domainid 4001 srcip 198.51.100.25 dstip 203.0.113.80 srcport 52400 dstport 443 proto 6 packets 15400 octets 21560000 wait 5ms

    // 5. sFlow v5 switched packet/counter sample datagram (UDP 6343)
    rtr -> col sflow agentip 10.250.0.1 subagentid 1 uptime 86400000 samples 8 seq 101
}

compile {
    telemetry_ingest_test(core_router, telemetry_collector)
}
```

#### Compile, Inspect & Replay:
```bash
frameassembly siem_and_flow_collectors.fasm siem_and_flow_collectors.pcap

# Inspect Syslog, NetFlow, IPFIX, and sFlow packets
tshark -r siem_and_flow_collectors.pcap

# Replay toward your SIEM / Flow Collector test listener
sudo tcpreplay -i eth0 siem_and_flow_collectors.pcap
```

### Recipe 4B — IDS/IPS & DPI Signature Validation (DNS Sinkhole, TLS 1.3 `sni`/`alpn` & Custom HTTP Headers)

This recipe builds a focused capture containing three classic NSM/IDS detection triggers:
1. A DNS lookup for a suspicious domain answered with `rcode 5` (`REFUSED`) by a DNS sinkhole.
2. A full TCP 3-way handshake followed by a **TLS 1.3 `clienthello`** carrying a custom `sni` and `alpn`, terminated by a TLS `alert`.
3. An HTTP `post` request with custom `useragent`, `uri`, and `header` fields rejected by a WAF (`status 403`).

Save as `ids_dpi_validation.fasm`:

```frameassembly
host workstation {
    ip 10.40.5.25
    mac 00:50:56:40:05:25
}

host security_gateway {
    ip 10.40.5.1
    mac 00:1c:73:40:05:01
}

flow ids_signature_verification(client, gw) {
    // 1. DNS query for a policy-blocked domain answered with RCODE 5 (REFUSED)
    client -> gw dns query txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "a" wait 1ms
    client <- gw dns response txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "a" rcode 5 wait 5ms

    // 2. TLS 1.3 ClientHello with custom SNI and ALPN over a tracked TCP handshake on port 443
    client -> gw tcp syn srcport 53443 dstport 443 win 65535 mss 1460 wait 1ms
    client <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    client -> gw tcp ack wait 1ms
    client -> gw tls clienthello sni "c2-panel.bad-domain.test" ciphersuite 4866 alpn "h2" wait 2ms
    client <- gw tls alert payload "ACCESS_DENIED_BY_SNI_POLICY" wait 5ms

    // 3. HTTP request with custom URI, User-Agent, and custom X-Api-Token header on port 80
    client -> gw tcp syn srcport 53080 dstport 80 win 65535 mss 1460 wait 1ms
    client <- gw tcp syn ack win 65535 mss 1460 wait 1ms
    client -> gw tcp ack wait 1ms
    client -> gw http post uri "/admin/export-secrets" hosthdr "internal-portal.local" useragent "ScannerBot/2.1" contenttype "application/json" header "X-Api-Token" "test-token-998877" body "{\"dump\":true}" wait 2ms
    client <- gw http status 403 reason "Forbidden" contenttype "application/json" body "{\"error\":\"blocked_by_waf\"}"
}

compile {
    ids_signature_verification(workstation, security_gateway)
}
```

#### Compile & Feed Directly into `tshark`, Suricata, or Zeek:
```bash
frameassembly ids_dpi_validation.fasm ids_dpi_validation.pcap

# Extract DNS query name, TLS SNI, and HTTP URI/User-Agent in tshark
tshark -r ids_dpi_validation.pcap -T fields -e frame.number -e dns.qry.name -e tls.handshake.extensions_server_name -e http.request.uri -e http.user_agent

# Test Suricata rules offline against the generated PCAP (writes fast.log / eve.json to ./suricata_out/)
suricata -r ids_dpi_validation.pcap -l ./suricata_out/ -k none

# Or generate Zeek logs (dns.log, ssl.log, http.log, conn.log) offline
zeek -C -r ids_dpi_validation.pcap
```

### Recipe 4C — Shadow IT & Unauthorized Network Activity Detection QA

Security teams regularly write SIEM correlation rules, NDR policies, and switch DHCP-snooping / NAC alerts for **Shadow IT** and **rogue LAN devices**—yet those rules rarely get tested end-to-end because nobody wants to stand up a rogue DHCP server or upload corporate files to unapproved SaaS/AI endpoints on the production LAN.

This recipe verifies four high-priority Shadow IT and unauthorized LAN activity detections in a single capture:
1. **Unapproved SaaS / AI Upload (`tls` `sni`)**: Workstation initiating a TLS 1.3 connection to an unapproved file-sharing or AI service (`sni "shadow-ai-upload.example.net"`).
2. **Unauthorized `quic` / DoH Bypass on UDP `443`**: Browser attempting HTTP/3 `quic` (`initial`) / encrypted DNS-over-HTTPS on UDP `443` to bypass corporate DNS inspection.
3. **Rogue `dhcp` Server on an Access VLAN**: An unauthorized travel router (`10.40.5.99`) answering a client `dhcp discover` with a competing `dhcp offer` (`router 10.40.5.99`, external `dnsserver 1.1.1.1`).
4. **Unauthorized `mdns` & `ssdp` Discovery**: Consumer IoT / casting chatter (`_airplay._tcp.local` over `mdns` and UPnP `ssdp msearch`) on a segmented enterprise VLAN.

Save as `shadow_it_audit.fasm`:

```frameassembly
host corp_laptop { ip 10.40.5.25  mac 00:50:56:40:05:25 }
host rogue_box   { ip 10.40.5.99  mac 00:50:56:40:05:99 }
host sec_gateway { ip 10.40.5.1   mac 00:1c:73:40:05:01 }
host lan_bcast   { ip 255.255.255.255 mac ff:ff:ff:ff:ff:ff }
host mdns_mcast  { ip 224.0.0.251 }
host ssdp_mcast  { ip 239.255.255.250 }

flow shadow_it_and_rogue_lan_qa(ws, rogue, gw, bcast, mdns_grp, ssdp_grp) {
    // 1. Rogue SaaS / AI upload attempt over TLS 1.3 SNI on VLAN 40
    ws -> gw vlan 40 tcp syn srcport 54443 dstport 443 win 65535 mss 1460 wait 1ms
    ws <- gw vlan 40 tcp syn ack win 65535 mss 1460 wait 1ms
    ws -> gw vlan 40 tcp ack wait 1ms
    ws -> gw vlan 40 tls clienthello sni "shadow-ai-upload.example.net" ciphersuite 4866 alpn "h2" wait 2ms
    ws <- gw vlan 40 tls alert payload "BLOCKED_SHADOW_IT_SNI" wait 5ms

    // 2. Unauthorized QUIC / DoH bypass attempt over UDP port 443
    ws -> gw vlan 40 dstport 443 quic initial version 1 dcid "a1b2c3d4e5f60708" scid "1122334455667788" pktnum 1 payload "DOH_OR_QUIC_SHADOW_SAAS" wait 5ms

    // 3. Rogue DHCP server offering a competing default gateway and external DNS on VLAN 40
    ws    -> bcast vlan 40 dhcp discover xid 0x7701 chaddr 00:50:56:40:05:25 hostname "corp-laptop-25" wait 2ms
    rogue -> ws    vlan 40 dhcp offer xid 0x7701 yiaddr 10.40.5.200 siaddr 10.40.5.99 chaddr 00:50:56:40:05:25 subnetmask 255.255.255.0 router 10.40.5.99 dnsserver 1.1.1.1 leasetime 3600 wait 5ms

    // 4. Unauthorized mDNS AirPlay casting & UPnP SSDP discovery on corporate VLAN 40
    rogue -> mdns_grp vlan 40 mdns query qname "_airplay._tcp.local" qtype "ptr" wait 2ms
    rogue -> ssdp_grp vlan 40 ssdp msearch st "ssdp:all"
}

compile {
    shadow_it_and_rogue_lan_qa(corp_laptop, rogue_box, sec_gateway, lan_bcast, mdns_mcast, ssdp_mcast)
}
```

#### Compile & Validate Against Suricata, Zeek, or NDR SPAN Ports:
```bash
frameassembly shadow_it_audit.fasm shadow_it_audit.pcap

# Verify TLS SNI, QUIC DCID, rogue DHCP server IP, mDNS query, and SSDP M-SEARCH in tshark
tshark -r shadow_it_audit.pcap

# Validate Suricata / Zeek detections or replay into your NDR sensor's SPAN interface
suricata -r shadow_it_audit.pcap -l ./suricata_shadow_it/ -k none
sudo tcpreplay -i eth0 shadow_it_audit.pcap
```

---

## 5. Stateful OT Firewall & SCADA ACL Testing with `tcpreplay` (Without Physical PLCs)

In industrial networks (Purdue Model Levels 1 through 3.5), firewall rules and OT security sensors (**Claroty**, **Dragos**, **Nozomi Networks**, **Palo Alto / Fortinet OT profiles**, **Suricata ICS rules**) inspect function codes deep inside industrial protocols—allowing `read` polls from an historian while blocking `write` or `operate` commands—and drop mid-stream TCP packets unless a valid 3-way TCP handshake precedes the OT payload.

FrameAssembly natively builds all **6 core industrial OT protocols**—including stateful TCP `SEQ`/`ACK` tracking and automatic **IEEE 1815 DNP3 CRC-16** calculation over every header and 16-byte data block.

### Recipe 5 — Purdue Level 1–3.5 Conduit Validation (`modbus`, `s7comm`, `dnp3`, `bacnet`, `ethernetip` & `opcua`)

Save as `ot_scada_conduit_test.fasm`:

```frameassembly
host scada_hmi {
    ip 192.168.100.10
    mac 00:1b:21:a0:00:10
}

host plant_plc {
    ip 192.168.100.50
    mac 00:0e:8c:a0:00:50
}

flow purdue_conduit_audit(hmi, plc) {
    // 1. Modbus TCP (Port 502): Stateful TCP handshake + Read Holding Registers (0x03) + Write Single Register (0x06)
    hmi -> plc vlan 110 pcp 6 tcp syn srcport 50502 dstport 502 win 64240 mss 1460 wait 1ms
    hmi <- plc vlan 110 pcp 6 tcp syn ack win 64240 mss 1460 wait 1ms
    hmi -> plc vlan 110 pcp 6 tcp ack wait 1ms
    hmi -> plc vlan 110 pcp 6 modbus readholdingregisters txid 101 unitid 1 addr 40001 count 4 wait 2ms
    hmi <- plc vlan 110 pcp 6 modbus readholdingregisters txid 101 unitid 1 count 4 isresponse wait 5ms
    hmi -> plc vlan 110 pcp 6 modbus writesingleregister txid 102 unitid 1 addr 40001 value 1500 wait 5ms

    // 2. Siemens S7comm (ISO-on-TCP Port 102): Setup Communication + Read Data Block DB1
    hmi -> plc vlan 110 pcp 6 s7comm setupcomm rosctr "job" pduref 201 wait 2ms
    hmi -> plc vlan 110 pcp 6 s7comm readvar rosctr "job" pduref 202 area 0x84 dbnum 1 offset 0 count 8 wait 5ms

    // 3. IEEE 1815 DNP3 (Port 20000): Class 0 Integrity Poll + Control Relay Output Block (SELECT / OPERATE)
    //    (FrameAssembly computes IEEE 1815 CRC-16 checksums automatically)
    hmi -> plc vlan 110 pcp 6 dnp3 read src 1 dst 10 group 60 variation 1 wait 2ms
    hmi <- plc vlan 110 pcp 6 dnp3 func "response" src 10 dst 1 group 30 variation 1 wait 5ms
    hmi -> plc vlan 110 pcp 6 dnp3 select src 1 dst 10 group 12 variation 1 wait 2ms
    hmi -> plc vlan 110 pcp 6 dnp3 operate src 1 dst 10 group 12 variation 1 wait 5ms

    // 4. BACnet/IP (UDP Port 47808): ReadProperty Present_Value (Property 85) + WriteProperty
    hmi -> plc vlan 110 pcp 5 bacnet readproperty invokeid 10 objecttype 0 objectinstance 1 propertyid 85 wait 2ms
    hmi -> plc vlan 110 pcp 5 bacnet writeproperty invokeid 11 objecttype 1 objectinstance 1 propertyid 85 value 72 wait 5ms

    // 5. ODVA EtherNet/IP & CIP (Port 44818): RegisterSession + SendRRData CIP Get_Attribute_Single
    hmi -> plc vlan 110 pcp 6 ethernetip registersession sessionhandle 0x00010203 wait 2ms
    hmi -> plc vlan 110 pcp 6 ethernetip sendrrdata sessionhandle 0x00010203 cipservice 0x0e cipclass 0x04 cipinstance 100 cipattr 3 wait 5ms

    // 6. OPC UA Binary (Port 4840): Hello (HEL) -> Acknowledge (ACK) -> SecureChannel Message (MSG)
    hmi -> plc vlan 110 pcp 6 opcua msgtype "hel" chunktype "f" endpointurl "opc.tcp://192.168.100.50:4840" wait 2ms
    hmi <- plc vlan 110 pcp 6 opcua msgtype "ack" chunktype "f" wait 2ms
    hmi -> plc vlan 110 pcp 6 opcua msgtype "msg" chunktype "f" securechannelid 1 tokenid 1 seqnum 1 reqid 500 nodeid "ns=2;s=Turbine.RPM"
}

compile {
    purdue_conduit_audit(scada_hmi, plant_plc)
}
```

#### Compile, Inspect & Replay:
```bash
frameassembly ot_scada_conduit_test.fasm ot_scada_conduit_test.pcap

# Inspect all 6 industrial protocols in tshark
tshark -r ot_scada_conduit_test.pcap

# Replay across your OT zone firewall or passive OT sensor SPAN port
sudo tcpreplay -i eth1 ot_scada_conduit_test.pcap
```

---

## 6. Decompiling Customer `.pcap` Captures (`reverse`) & Zero-Noise Incident Reproducers

Attaching a live `tcpdump` capture to a vendor TAC case, an internal Jira ticket, or a team runbook has two major downsides:
1. Live captures contain **customer subnets, internal hostnames, TLS `sni` strings, and unrelated background chatter**.
2. Binary `.pcap` files cannot be reviewed in a Git pull request or adjusted when someone asks *"What happens if the timer is 50ms instead?"*

### Recipe 6A — Application Troubleshooting Reproducer: TCP Zero-Window Stall & Window Update Recovery

Save as `reproducer_zero_window.fasm`:

```frameassembly
host app_client {
    ip 10.50.1.10
    mac 00:50:56:50:01:10
}

host overloaded_backend {
    ip 10.50.1.20
    mac 00:50:56:50:01:20
}

flow tcp_zero_window_reproducer(c, s) {
    // 1. 3-way handshake on port 8080
    c -> s tcp syn srcport 54000 dstport 8080 win 65535 mss 1460 wscale 7 sackperm wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wscale 7 sackperm wait 1ms
    c -> s tcp ack wait 1ms

    // 2. Client sends an HTTP POST batch payload
    c -> s http post uri "/api/v1/ingest" hosthdr "ingest.internal" contenttype "application/json" body "{\"batch_id\":4091,\"records\":500}" wait 2ms

    // 3. Server's receive buffer fills up: advertises TCP Zero Window (win 0)
    c <- s tcp ack win 0 wait 250ms

    // 4. Client sends a 1-byte TCP Keep-Alive / Zero-Window probe; server is still full (win 0)
    c -> s tcp ack payload "X" wait 1ms
    c <- s tcp ack win 0 wait 250ms

    // 5. Server drains its buffer, sends a TCP Window Update (win 32768), and returns HTTP 202 Accepted
    c <- s tcp ack win 32768 wait 2ms
    c <- s http status 202 reason "Accepted" contenttype "application/json" body "{\"status\":\"queued\"}" wait 1ms

    // 6. Graceful connection close
    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

compile {
    tcp_zero_window_reproducer(app_client, overloaded_backend)
}
```

#### Compile & Inspect Window Stall in `tshark`:
```bash
frameassembly reproducer_zero_window.fasm reproducer_zero_window.pcap

# View the exact TCP window progression and Wireshark's automatic ZeroWindow annotations
tshark -r reproducer_zero_window.pcap
```

### Recipe 6B — Routing & First-Hop Redundancy Failover (`bfd` + `ospf` + `bgp` + `vrrp` / `hsrp` + Gratuitous `arp`)

This recipe captures an entire core failover timeline in 10 frames: sub-second `bfd` session establishment and failure detection, `ospf` and `bgp` routing convergence, `vrrp` + `hsrp` active gateway election, and a **Gratuitous ARP** broadcast updating downstream switch CAM tables.

Save as `routing_ha_failover.fasm`:

```frameassembly
host core_rtr_a   { ip 10.0.0.1   mac 00:00:5e:00:01:0a }
host core_rtr_b   { ip 10.0.0.2   mac 00:1c:73:00:00:02 }
host ospf_mcast   { ip 224.0.0.5 }
host vrrp_mcast   { ip 224.0.0.18 }
host hsrp_mcast   { ip 224.0.0.2 }
host lan_bcast    { ip 10.0.0.255 mac ff:ff:ff:ff:ff:ff }

flow core_ha_convergence(rtr_a, rtr_b, ospf_all, vrrp_all, hsrp_all, bcast) {
    // 1. BFD session Up (state 3) with 50ms TX/RX intervals and multiplier 3, followed by BFD Down (state 1, diag 1)
    rtr_a -> rtr_b ttl 255 dscp 48 bfd state 3 diag 0 mydisc 101 yourdisc 202 mintx 50000 minrx 50000 mult 3 wait 50ms
    rtr_a <- rtr_b ttl 255 dscp 48 bfd state 1 diag 1 mydisc 202 yourdisc 101 mintx 50000 minrx 50000 mult 3 wait 2ms

    // 2. OSPF Area 0 multicast Hello and Link-State Update (LSU) flooding the topology change
    rtr_a -> ospf_all ttl 1 dscp 48 ospf hello routerid 10.0.0.1 areaid 0 hellointerval 10 deadinterval 40 priority 120 wait 2ms
    rtr_a -> ospf_all ttl 1 dscp 48 ospf lsu routerid 10.0.0.1 areaid 0 wait 5ms

    // 3. eBGP peering (TCP 179) advertising failover next-hop for 172.16.0.0/16
    rtr_a -> rtr_b ttl 255 dscp 48 bgp open asn 65001 holdtime 90 bgpid 10.0.0.1 wait 2ms
    rtr_a <- rtr_b ttl 255 dscp 48 bgp open asn 65002 holdtime 90 bgpid 10.0.0.2 wait 2ms
    rtr_a -> rtr_b ttl 255 dscp 48 bgp update asn 65001 prefix "172.16.0.0/16" nexthop 10.0.0.1 wait 5ms

    // 4. VRRPv3 Master advertisement (VRID 10, Priority 200) and HSRP Active advertisement (Group 10, State 16)
    rtr_a -> vrrp_all ttl 255 dscp 48 vrrp version 3 vrid 10 priority 200 advint 1 vip 10.0.0.254 wait 2ms
    rtr_a -> hsrp_all ttl 1 dscp 48 hsrp group 10 priority 150 state 16 auth "cisco123" vip 10.0.0.253 hellotime 3 holdtime 10 wait 2ms

    // 5. Gratuitous ARP broadcast announcing that VIP 10.0.0.254 now resides on Router A's VRRP MAC
    rtr_a -> bcast arp reply gratuitous sendermac 00:00:5e:00:01:0a senderip 10.0.0.254 targetmac ff:ff:ff:ff:ff:ff targetip 10.0.0.254
}

compile {
    core_ha_convergence(core_rtr_a, core_rtr_b, ospf_mcast, vrrp_mcast, hsrp_mcast, lan_bcast)
}
```

#### Compile & Inspect Control-Plane Convergence:
```bash
frameassembly routing_ha_failover.fasm

# View the full sequence of BFD, OSPF, BGP, VRRP, HSRP, and Gratuitous ARP frames
tshark -r routing_ha_failover.pcap
```

### Recipe 6C — Decompiling & Anonymizing Customer `.pcap` Captures for Vendor Support Tickets (`frameassembly reverse`)

Tools like `tcprewrite` can swap outer IP addresses, but they cannot scrub internal DNS `qname`s, TLS `sni` hostnames, HTTP `hosthdr` headers, or Syslog/SNMP strings—because changing Layer 7 string lengths invalidates every downstream IP length, TCP/UDP checksum, and TCP `SEQ`/`ACK` offset in the stream.

`frameassembly reverse` solves that workflow end-to-end:
1. Run `frameassembly reverse` on your `tcpdump` or Wireshark `.pcap` / `.pcapng` capture to decompile it into `.fasm` code (`host1`, `host2`, ...).
2. Replace customer IPs and MACs in the `host` blocks with RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`), scrub internal `sni` / `qname` / `hosthdr` strings, and delete unrelated background lines.
3. Recompile with `frameassembly sanitized_ticket.fasm sanitized_ticket.pcap`—FrameAssembly recalculates all Ethernet/IP/TCP/UDP lengths, L3/L4 checksums, and TCP `SEQ`/`ACK` numbers automatically. Encrypted payloads (such as SNMPv3 `authPriv`, TLS application data, SSH, or IPsec `esp`) are kept intact as `tcp` or `udp` statements with `payload` / `hexpayload` so their wire bytes remain untouched.

```bash
# 1. Decompile customer_incident.pcap -> sanitized_ticket.fasm
frameassembly reverse customer_incident.pcap sanitized_ticket.fasm
```

Edit `sanitized_ticket.fasm` to replace internal addresses and hostnames:

```frameassembly
host host1 { ip 192.0.2.10 mac 00:11:22:33:44:01 }
host host2 { ip 198.51.100.20 mac 00:11:22:33:44:02 }

compile {
    host1 -> host2 vlan 100 tcp syn srcport 54321 dstport 443 win 64240 mss 1460 wait 1ms
    host1 <- host2 vlan 100 tcp syn ack win 64240 mss 1460 wait 1ms
    host1 -> host2 vlan 100 tcp ack wait 1ms
    host1 -> host2 vlan 100 tls clienthello sni "sanitized-portal.example.com" ciphersuite 4865 alpn "h2" wait 2ms
    host1 <- host2 vlan 100 tcp rst ack
}
```

```bash
# 2. Preview the packet ladder and compile sanitized_ticket.pcap for the vendor TAC ticket
frameassembly show sanitized_ticket.fasm
frameassembly sanitized_ticket.fasm sanitized_ticket.pcap
```

For quick Layer 2 switching reproducers (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`), you can also declare MAC-only `host` blocks without `ip` and write packet statements directly inside `compile { ... }`:

```frameassembly
host sw1 { mac 00:1c:73:00:00:01 }
host sw2 { mac 00:1c:73:00:00:02 }

compile {
    sw1 -> sw2 lldp chassisid "00:1c:73:00:00:01" portid "Ethernet1/1" ttl 120 sysname "core-sw1" wait 2ms
    sw1 <- sw2 lacp actorsys 00:1c:73:00:00:02 actorkey 10 actorport 1 actorstate 0x3f partnersys 00:1c:73:00:00:01 partnerkey 10 partnerport 1 partnerstate 0x3f wait 2ms
    sw1 -> sw2 stp rstp rootid "4096/00:1c:73:00:00:01" bridgeid "4096/00:1c:73:00:00:01" portid 0x8001 cost 0 flags 0x3c
}
```

---

## Where to Go Next

* **[Getting Started Guide (`getting_started.md`)](getting_started.md)** — Step-by-step introduction to `.fasm` code, automatic TCP `SEQ`/`ACK` tracking, cross-layer tags, reading error messages, AI copy-paste prompt, and using `tshark` / `tcpreplay`.
* **Layer-by-Layer Reference Guides:**
  * [Layer 2 Switching & Data-Link (`l2_protocols.md`)](l2_protocols.md) — `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls`
  * [Layer 3 Control, Tunneling, VPN & Routing (`l3_protocols.md`)](l3_protocols.md) — `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow`
  * [Layer 4 Transports (`l4_transports.md`)](l4_transports.md) — `tcp`, `udp`, `sctp`
  * [Layer 7 SNMPv1/v2c/v3 (`l7_snmp.md`)](l7_snmp.md) — `snmp1`, `snmp2`, `snmp3`
  * [Layer 7 Infrastructure, Time, AAA & Telemetry (`l7_infra_and_telemetry.md`)](l7_infra_and_telemetry.md) — `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow`
  * [Layer 7 Web, Cloud, Security, VoIP & Remote Access (`l7_web_and_cloud.md`)](l7_web_and_cloud.md) — `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp`
  * [Layer 7 Mail, Auth, Storage, Databases & Messaging (`l7_mail_auth_storage_db.md`)](l7_mail_auth_storage_db.md) — `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp`
  * [Layer 7 Industrial Control Systems & SCADA/OT (`l7_industrial_ot.md`)](l7_industrial_ot.md) — `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua`
  * [Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)](topologies_and_dual_stack.md) — Full enterprise, EVPN-VXLAN, and 802.1X NAC topologies
  * [`.fasm` File Format & Media Type Specification (`fasm-specification.md`)](fasm-specification.md) — Formal `text/vnd.frameassembly` specification, UTF-8 encoding rules, and `.fasm` extension disambiguation
  * [For Nerds: Architecture, Rust Library API & Formal Grammars (`for_nerds.md`)](for_nerds.md) — Rust library API, internal architecture, and `EBNF`/`GBNF`/`Lark` grammars
