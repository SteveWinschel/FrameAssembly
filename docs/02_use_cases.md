# Practical Use Cases & Cookbook for Network Engineers

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

Every network team owns at least one story about the afternoon they had to prove the problem was not "the network". This cookbook is the evidence locker: thirteen copy-paste recipes for FrameAssembly 3.0.0, each starting from a problem you have probably already had and ending with a `.pcap` you can replay, dissect, or attach to a ticket.

Nothing here needs a lab, a MIB directory, a second laptop running a half-working Python virtualenv, or a maintenance window.

## How a Recipe Works

Every recipe is `.frasm` code made of up to three parts:

- **`host` blocks** describe the boxes on your network diagram: an `ip` and an optional `mac`, or a MAC-only `host sw1 { mac 00:1c:73:00:00:01 }` for Layer 2 switching protocols.
- **`flow(a, b)` blocks** *(optional)* group a packet-by-packet exchange between role names. Direction is written like this:

  ```text
  a -> b   forward packet: a sends to b
  a <- b   reply packet: b sends back to a
  ```

- **One `compile` block** plugs real `host` devices into the flow roles, left to right. You can also skip the `flow` and write packet statements directly inside `compile { ... }`.

## Run Any Recipe

1. Save the code to a file such as `scenario.frasm`. Preview the packet ladder with `frameassembly show scenario.frasm`, then compile with `frameassembly scenario.frasm` (writes `scenario.pcap`) or pass your own output name: `frameassembly scenario.frasm custom.pcapng`.
2. Replay or inspect the result with **`tcpreplay`**, **Wireshark** / **`tshark`**, or **Suricata** / **Zeek**.
3. Got a real capture instead? `frameassembly reverse trace.pcap` writes `trace.frasm` (or name it: `frameassembly reverse trace.pcap sanitized.frasm`), ready for anonymizing and tweaking. Recipe 6C walks through it.

---

## Find Your Problem

| The problem on your desk | What the recipe uses | Recipe |
| :--- | :--- | :--- |
| **The Checkmk / Zabbix / PRTG / LibreNMS alert for `linkDown` or chassis temperature has never been seen to fire** | `snmp1`, `snmp2` (`trap`, `inform`, `get`, `response`, `varbind`) | [Recipe 1A — Link Down at 2 a.m.: SNMPv1 and SNMPv2c Traps, Polls and Informs](#recipe-1a--link-down-at-2-am-snmpv1-and-snmpv2c-traps-polls-and-informs) |
| **SNMPv3 `authPriv` traps vanish without a log line** | `snmp3` (`auth sha256`/`sha512`/`md5`/`sha`, `priv aes`/`des`, `engineid`) | [Recipe 1B — Encrypted SNMPv3 `authPriv` Traps for Checkmk, Zabbix and PRTG](#recipe-1b--encrypted-snmpv3-authpriv-traps-for-checkmk-zabbix-and-prtg) |
| **The firewall policy says "allow 443, drop the rest" and nobody has tested "the rest"** | `tcp` (`syn`, `rst ack`, out-of-state `ack`, `fin psh urg`), `vlan`, `icmp` (`code 13`) | [Recipe 2A — DMZ Firewall Policy Audit: Handshakes, Rejections, Out-of-State and Stealth Probes](#recipe-2a--dmz-firewall-policy-audit-handshakes-rejections-out-of-state-and-stealth-probes) |
| **The VPN pings fine and hangs on the first real file; or someone suspects spoofed source IPs inside** | `df`, `ipid`, `mf`, `fragoffset`, `icmp` (`destunreach code 4`), spoofed `host` | [Recipe 2B — Path MTU, IPv4 Fragmentation and Spoofed Sources](#recipe-2b--path-mtu-ipv4-fragmentation-and-spoofed-sources) |
| **Voice sounds underwater and the QoS policy "is definitely correct"** | `vlan`, `pcp`, `dei`, `dscp` (`46` EF, `34` AF41, `48` CS6, `8` CS1), `ecn`, `rtp`, `bfd` | [Recipe 3A — 802.1Q Trunk and Voice / Video / Scavenger DiffServ QoS](#recipe-3a--8021q-trunk-and-voice--video--scavenger-diffserv-qos) |
| **The carrier's "transparent Ethernet" needs checking: `qinq` S-tags or MPLS labels** | `qinq`, `innervlan`, `mpls` (`exp`, `bos`, `mplsttl`), `dscp` | [Recipe 3B — Carrier 802.1ad `qinq` Double-Tagging and MPLS Backhaul](#recipe-3b--carrier-8021ad-qinq-double-tagging-and-mpls-backhaul) |
| **The SIEM parser only works on the vendor's sample log; the flow collector is unproven** | `syslog` (`transport tcp`), `netflow` (v5), `ipfix` (v10), `sflow` (v5) | [Recipe 4A — SIEM and Flow Collector Ingest: `syslog`, NetFlow v5, IPFIX and sFlow](#recipe-4a--siem-and-flow-collector-ingest-syslog-netflow-v5-ipfix-and-sflow) |
| **The IDS rule has never seen a hit outside the rule author's imagination** | `dns` (`rcode 5`), `tls` (`clienthello`, `sni`, `alpn`, `alert`), `http` (`header`, `body`) | [Recipe 4B — IDS/IPS and DPI Signatures: DNS Sinkhole, TLS 1.3 SNI/ALPN and Custom HTTP Headers](#recipe-4b--idsips-and-dpi-signatures-dns-sinkhole-tls-13-snialpn-and-custom-http-headers) |
| **Shadow IT, QUIC/DoH around the proxy, a rogue DHCP server, chatty casting devices** | `tls` (`sni`), `quic` (`initial`), `dhcp` (`discover`, `offer`), `mdns`, `ssdp` | [Recipe 4C — Shadow IT and Rogue LAN Devices](#recipe-4c--shadow-it-and-rogue-lan-devices) |
| **The OT firewall must allow `read` and refuse `write`, and there is no spare PLC** | `modbus`, `s7comm`, `dnp3` (auto CRC-16), `bacnet`, `ethernetip`, `opcua` | [Recipe 5 — Purdue Level 1–3.5 Conduit Validation: `modbus`, `s7comm`, `dnp3`, `bacnet`, `ethernetip` and `opcua`](#recipe-5--purdue-level-135-conduit-validation-modbus-s7comm-dnp3-bacnet-ethernetip-and-opcua) |
| **The app froze and someone already blamed DNS** | `tcp` (`win 0`, probe, `win 32768`), `http` (`post`, `202 Accepted`) | [Recipe 6A — TCP Zero-Window Stall and Window Update Recovery](#recipe-6a--tcp-zero-window-stall-and-window-update-recovery) |
| **Failover took "a bit": what actually happened, in which order** | `bfd`, `ospf`, `bgp`, `vrrp`, `hsrp`, `arp` (`gratuitous`) | [Recipe 6B — Routing and First-Hop Redundancy Failover: `bfd`, `ospf`, `bgp`, `vrrp`, `hsrp` and Gratuitous `arp`](#recipe-6b--routing-and-first-hop-redundancy-failover-bfd-ospf-bgp-vrrp-hsrp-and-gratuitous-arp) |
| **The vendor wants a capture, and the capture contains the customer** | `frameassembly reverse` (`host1`, `host2`, IP/SNI scrubbing, automatic checksum and SEQ recalculation) | [Recipe 6C — Anonymizing Customer `.pcap` Captures for Vendor Support: `frameassembly reverse`](#recipe-6c--anonymizing-customer-pcap-captures-for-vendor-support-frameassembly-reverse) |

---

## Table of Contents

1. [1. SNMP Alerts That Actually Fire](#1-snmp-alerts-that-actually-fire)
   * [Recipe 1A — Link Down at 2 a.m.: SNMPv1 and SNMPv2c Traps, Polls and Informs](#recipe-1a--link-down-at-2-am-snmpv1-and-snmpv2c-traps-polls-and-informs)
   * [Recipe 1B — Encrypted SNMPv3 `authPriv` Traps for Checkmk, Zabbix and PRTG](#recipe-1b--encrypted-snmpv3-authpriv-traps-for-checkmk-zabbix-and-prtg)
2. [2. Firewall Rules and ACLs, Tested Outside the Kernel](#2-firewall-rules-and-acls-tested-outside-the-kernel)
   * [Recipe 2A — DMZ Firewall Policy Audit: Handshakes, Rejections, Out-of-State and Stealth Probes](#recipe-2a--dmz-firewall-policy-audit-handshakes-rejections-out-of-state-and-stealth-probes)
   * [Recipe 2B — Path MTU, IPv4 Fragmentation and Spoofed Sources](#recipe-2b--path-mtu-ipv4-fragmentation-and-spoofed-sources)
3. [3. VLAN, QoS, QinQ and MPLS Without a Packet Generator License](#3-vlan-qos-qinq-and-mpls-without-a-packet-generator-license)
   * [Recipe 3A — 802.1Q Trunk and Voice / Video / Scavenger DiffServ QoS](#recipe-3a--8021q-trunk-and-voice--video--scavenger-diffserv-qos)
   * [Recipe 3B — Carrier 802.1ad `qinq` Double-Tagging and MPLS Backhaul](#recipe-3b--carrier-8021ad-qinq-double-tagging-and-mpls-backhaul)
4. [4. Proving Your Detection Stack Works](#4-proving-your-detection-stack-works)
   * [Recipe 4A — SIEM and Flow Collector Ingest: `syslog`, NetFlow v5, IPFIX and sFlow](#recipe-4a--siem-and-flow-collector-ingest-syslog-netflow-v5-ipfix-and-sflow)
   * [Recipe 4B — IDS/IPS and DPI Signatures: DNS Sinkhole, TLS 1.3 SNI/ALPN and Custom HTTP Headers](#recipe-4b--idsips-and-dpi-signatures-dns-sinkhole-tls-13-snialpn-and-custom-http-headers)
   * [Recipe 4C — Shadow IT and Rogue LAN Devices](#recipe-4c--shadow-it-and-rogue-lan-devices)
5. [5. Industrial OT: Allow the Read, Refuse the Write](#5-industrial-ot-allow-the-read-refuse-the-write)
   * [Recipe 5 — Purdue Level 1–3.5 Conduit Validation: `modbus`, `s7comm`, `dnp3`, `bacnet`, `ethernetip` and `opcua`](#recipe-5--purdue-level-135-conduit-validation-modbus-s7comm-dnp3-bacnet-ethernetip-and-opcua)
6. [6. Incident Reproducers and Anonymized Captures](#6-incident-reproducers-and-anonymized-captures)
   * [Recipe 6A — TCP Zero-Window Stall and Window Update Recovery](#recipe-6a--tcp-zero-window-stall-and-window-update-recovery)
   * [Recipe 6B — Routing and First-Hop Redundancy Failover: `bfd`, `ospf`, `bgp`, `vrrp`, `hsrp` and Gratuitous `arp`](#recipe-6b--routing-and-first-hop-redundancy-failover-bfd-ospf-bgp-vrrp-hsrp-and-gratuitous-arp)
   * [Recipe 6C — Anonymizing Customer `.pcap` Captures for Vendor Support: `frameassembly reverse`](#recipe-6c--anonymizing-customer-pcap-captures-for-vendor-support-frameassembly-reverse)

---

## 1. SNMP Alerts That Actually Fire

The only completely honest way to test a `linkDown` alert is to take a link down. Production teams tend to object, especially on Fridays at 16:55, and nobody has ever recovered from "let's see if PagerDuty rings" as a change description. The alternatives are not better:

* Net-SNMP's `snmptrap` wants a dozen positional flags (`-v 3 -l authPriv -e 0x8000... -u ... -a SHA-256 -A ... -x AES -X ... -Z boots,time`), local MIB files, and a spoofed source IP if the receiver filters alerts by switch address.
* Overheating a power supply for the thermal alarm is a hardware warranty conversation.

FrameAssembly needs a few lines of `.frasm` code instead. It encodes the ASN.1 BER varbinds, keeps the real switch source IP and VLAN tag, and handles RFC 3414 / 3826 / 7860 SNMPv3 key localization, HMAC digests, and DES/AES encryption.

### Recipe 1A — Link Down at 2 a.m.: SNMPv1 and SNMPv2c Traps, Polls and Informs

Start with the traps your NMS has been politely ignoring. This capture holds a v1 generic `linkDown`, a v1 enterprise trap for a chassis temperature alarm, a v2c GET and RESPONSE pair, a v2c `linkUp` trap with a `Counter64`, and an acknowledged v2c inform answered from UDP 162.

Save as `snmp_v1_v2c_alerts.frasm`:

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

Compile, verify, replay:

```bash
frameassembly snmp_v1_v2c_alerts.frasm snmp_v1_v2c_alerts.pcap

# Verify PDU types, community strings, and varbind OIDs in tshark
tshark -r snmp_v1_v2c_alerts.pcap -Y "snmp" -V

# Replay traps toward your monitoring server on eth0
sudo tcpreplay -i eth0 snmp_v1_v2c_alerts.pcap
```

### Recipe 1B — Encrypted SNMPv3 `authPriv` Traps for Checkmk, Zabbix and PRTG

SNMPv3 traps fail the way a locked door fails: silently, with no hint as to which key was wrong. Unlike v3 polling, where the NMS first asks the device for its EngineID, **v3 traps are one-way**. The receiver must already know the `engineid`, and **Checkmk**'s Event Console (`Credentials for SNMPv3 traps`), **Zabbix** (`snmptrapd.conf` with `createUser -e`), and **PRTG**'s trap receiver drop an `authPriv` trap if the `engineid`, `engineboots`, `enginetime`, authentication hash, or AES key is off by a single character. Debugging that without a known-good capture is a hobby for people who have run out of other hobbies.

This recipe builds authenticated, encrypted **USM `authPriv`** packets with explicit `engineid`, `engineboots`, `enginetime`, and `contextname`. It covers **RFC 7860 SHA-2** (`sha256`, `sha512`) with **RFC 3826 `aes`** (AES-128-CFB), plus legacy **RFC 3414 `md5`/`sha`** with **`des`** for the UPS and PDU hardware nobody dares to replace. The router keeps its real address (`10.100.0.250`), so Checkmk host matching and Zabbix SNMP trapper items behave exactly as they will in production.

Save as `snmp_v3_encrypted.frasm`:

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

Compile, decrypt in Wireshark, replay into your NMS:

```bash
frameassembly snmp_v3_encrypted.frasm snmp_v3_encrypted.pcap

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

## 2. Firewall Rules and ACLs, Tested Outside the Kernel

`ping`, `curl`, and `nc` all run through the local TCP/IP stack, which is considerate of them and fatal to a firewall audit. The kernel will not emit an out-of-state `ack` without a socket, will not bundle a permitted HTTPS handshake and a rejected `rst ack` in one file, and will not hand you a spoofed source address or a hand-built fragment. FrameAssembly writes the packets you describe, so **Palo Alto**, **FortiGate**, **CheckPoint**, or `nftables` can be tested across an 802.1Q trunk with `tcpreplay`, and nobody has to do TCP sequence math on a sticky note.

### Recipe 2A — DMZ Firewall Policy Audit: Handshakes, Rejections, Out-of-State and Stealth Probes

The change request said "allow 443, block everything else". "Everything else" deserves at least one test packet per bad habit. This capture contains a permitted HTTPS handshake, a refused MySQL attempt, an unsolicited ACK on SSH, a Christmas-tree probe on SMB, and a ping across DMZ VLAN 40 that earns an ICMP "administratively prohibited" (code 13).

Save as `firewall_dmz_audit.frasm`:

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

Compile, inspect, replay:

```bash
frameassembly firewall_dmz_audit.frasm firewall_dmz_audit.pcap

# Verify TCP flags, ports, and ICMP unreachable code
tshark -r firewall_dmz_audit.pcap

# Replay into a SPAN/TAP sensor port (or split client/server NICs across an inline firewall via tcpprep + tcpreplay -i eth1 -I eth2)
sudo tcpreplay -i eth1 firewall_dmz_audit.pcap
```

### Recipe 2B — Path MTU, IPv4 Fragmentation and Spoofed Sources

The VPN pings perfectly and hangs on the first real file transfer. Congratulations, it is MTU, and it is always MTU, except on the days it is DNS. Tunnel overhead from IPsec, GRE, or VXLAN eats the headroom, and a DF packet that hits the limit should trigger a message rather than a silent blackhole. The same capture also covers anti-spoofing (BCP 38 / uRPF). Three checks:

1. A packet with **Don't Fragment (`df`)** set must be answered with **ICMP Destination Unreachable, Code 4** (fragmentation needed and DF set).
2. **IPv4 fragments (`mf` + `fragoffset`)** sharing one `ipid` must be reassembled by stateful inspection.
3. A packet carrying a **spoofed external source IP** on an internal port must be dropped by the ingress or egress ACL.

Save as `firewall_mtu_frag_spoof.frasm`:

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

Compile, inspect, replay:

```bash
frameassembly firewall_mtu_frag_spoof.frasm firewall_mtu_frag_spoof.pcap

# Check IPv4 DF/MF flags, fragment offsets, and IP IDs
tshark -r firewall_mtu_frag_spoof.pcap -T fields -e frame.number -e ip.src -e ip.dst -e ip.id -e ip.flags.df -e ip.flags.mf -e ip.frag_offset -e icmp.code

# Replay against the firewall inside test port
sudo tcpreplay -i eth2 firewall_mtu_frag_spoof.pcap
```

---

## 3. VLAN, QoS, QinQ and MPLS Without a Packet Generator License

Desktop NIC drivers like to strip 802.1Q tags before anything reaches user space, and ordinary applications cannot set 802.1p priority (`pcp`), the drop-eligible bit (`dei`), outer 802.1ad `qinq` S-tags, or MPLS `exp` bits. FrameAssembly writes those headers at the Ethernet layer, so queues, trunk allow-lists, and WAN shapers can be checked with `tcpreplay` instead of with opinions.

### Recipe 3A — 802.1Q Trunk and Voice / Video / Scavenger DiffServ QoS

Voice sounds like a robot at the bottom of a pool, and the carrier insists the QoS policy is correct. Send one frame per traffic class with distinct markings and see which queue each one lands in: voice (VLAN 110, CoS 5, DSCP EF), video (VLAN 120, CoS 4, AF41, ECN), network control (VLAN 10, CoS 6, CS6) and bulk backup (VLAN 300, CoS 1, drop-eligible, CS1).

Save as `qos_diffserv_trunk.frasm`:

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

Compile, inspect, replay:

```bash
frameassembly qos_diffserv_trunk.frasm qos_diffserv_trunk.pcap

# Verify VLAN ID, 802.1p Priority (PCP), Drop Eligible (DEI), DSCP, and ECN markings
tshark -r qos_diffserv_trunk.pcap -T fields -e frame.number -e vlan.id -e vlan.priority -e vlan.dei -e ip.dsfield.dscp -e ip.dsfield.ecn

# Replay onto an 802.1Q trunk port connected to your switch or WAN router
sudo tcpreplay -i eth0 qos_diffserv_trunk.pcap
```

### Recipe 3B — Carrier 802.1ad `qinq` Double-Tagging and MPLS Backhaul

Your provider sold you "transparent Ethernet", so test how transparent. This capture sends two customers through one provider S-VLAN (2500) with different customer C-VLANs, then adds an MPLS L3VPN packet with EXP 5 and a best-effort packet with EXP 0, so you can see whether the markings survive the trip.

Save as `carrier_qinq_mpls.frasm`:

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

Compile and inspect:

```bash
frameassembly carrier_qinq_mpls.frasm carrier_qinq_mpls.pcap

# Extract outer/inner VLAN IDs and MPLS label/EXP/TTL fields
tshark -r carrier_qinq_mpls.pcap -T fields -e frame.number -e vlan.id -e mpls.label -e mpls.exp -e mpls.bottom -e mpls.ttl
```

---

## 4. Proving Your Detection Stack Works

A SIEM parser that works on the vendor's sample log works on exactly the vendor's sample log. Before a new SIEM, flow collector (**ElastiFlow**, **Akvorado**, **pmacct**, **nfdump**), NDR sensor, or IDS/IPS ruleset (**Suricata**, **Zeek**, **Snort**) goes into production, feed it a small capture where every packet has a reason to be there, instead of a thousand unrelated background frames you now have to explain.

### Recipe 4A — SIEM and Flow Collector Ingest: `syslog`, NetFlow v5, IPFIX and sFlow

Log pipelines are the one part of the stack where "it received something" counts as a pass. This capture sends an RFC 5424 syslog message over UDP 514, another over TCP 514 (with its handshake), a NetFlow v5 datagram reporting an HTTPS flow, an IPFIX export in observation domain 4001, and an sFlow v5 sample datagram. If a field is missing in the collector, it is missing on purpose.

Save as `siem_and_flow_collectors.frasm`:

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

Compile, inspect, replay:

```bash
frameassembly siem_and_flow_collectors.frasm siem_and_flow_collectors.pcap

# Inspect Syslog, NetFlow, IPFIX, and sFlow packets
tshark -r siem_and_flow_collectors.pcap

# Replay toward your SIEM / Flow Collector test listener
sudo tcpreplay -i eth0 siem_and_flow_collectors.pcap
```

### Recipe 4B — IDS/IPS and DPI Signatures: DNS Sinkhole, TLS 1.3 SNI/ALPN and Custom HTTP Headers

Most IDS rules are written against a blog post and deployed on faith. This capture has three classic detection triggers:

1. A DNS lookup for a suspicious domain, answered with `rcode 5` (`REFUSED`) by a sinkhole.
2. A TCP handshake followed by a **TLS 1.3 `clienthello`** with a custom `sni` and `alpn`, ended by a TLS `alert`.
3. An HTTP `post` with custom `useragent`, `uri`, and `header` fields, rejected by a WAF with `status 403`.

Save as `ids_dpi_validation.frasm`:

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

Compile and feed `tshark`, Suricata, or Zeek:

```bash
frameassembly ids_dpi_validation.frasm ids_dpi_validation.pcap

# Extract DNS query name, TLS SNI, and HTTP URI/User-Agent in tshark
tshark -r ids_dpi_validation.pcap -T fields -e frame.number -e dns.qry.name -e tls.handshake.extensions_server_name -e http.request.uri -e http.user_agent

# Test Suricata rules offline against the generated PCAP (writes fast.log / eve.json to ./suricata_out/)
suricata -r ids_dpi_validation.pcap -l ./suricata_out/ -k none

# Or generate Zeek logs (dns.log, ssl.log, http.log, conn.log) offline
zeek -C -r ids_dpi_validation.pcap
```

### Recipe 4C — Shadow IT and Rogue LAN Devices

Everyone writes correlation rules for Shadow IT and rogue devices. Almost nobody tests them, because nobody wants to stand up a rogue DHCP server on the production LAN or upload corporate files to an unapproved AI service just to see if an alert fires. One capture covers four detections:

1. **Unapproved SaaS or AI upload (`tls` `sni`)**: a workstation opens TLS 1.3 to `shadow-ai-upload.example.net`.
2. **`quic` / DoH bypass on UDP `443`**: a browser tries HTTP/3 (`initial`) to slip past corporate DNS inspection.
3. **Rogue `dhcp` server**: a travel router (`10.40.5.99`) answers a `dhcp discover` with a competing `dhcp offer` (`router 10.40.5.99`, external `dnsserver 1.1.1.1`).
4. **`mdns` and `ssdp` chatter**: consumer casting traffic (`_airplay._tcp.local`, UPnP `msearch`) on a segmented enterprise VLAN.

Save as `shadow_it_audit.frasm`:

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

Compile and validate against Suricata, Zeek, or an NDR SPAN port:

```bash
frameassembly shadow_it_audit.frasm shadow_it_audit.pcap

# Verify TLS SNI, QUIC DCID, rogue DHCP server IP, mDNS query, and SSDP M-SEARCH in tshark
tshark -r shadow_it_audit.pcap

# Validate Suricata / Zeek detections or replay into your NDR sensor's SPAN interface
suricata -r shadow_it_audit.pcap -l ./suricata_shadow_it/ -k none
sudo tcpreplay -i eth0 shadow_it_audit.pcap
```

---

## 5. Industrial OT: Allow the Read, Refuse the Write

Industrial security sensors (**Claroty**, **Dragos**, **Nozomi Networks**, **Palo Alto / Fortinet OT profiles**, **Suricata ICS rules**) look deep into the protocol. They need to allow a historian's `read` poll, block the `write` or `operate` command, and drop mid-stream TCP packets that arrive without a proper handshake. Purdue Model levels 1 through 3.5 are not the place to run experiments, and borrowing a PLC from the plant for a firewall test is how you meet the plant manager.

FrameAssembly builds all **six core industrial protocols** with stateful TCP `SEQ`/`ACK` tracking and automatic **IEEE 1815 DNP3 CRC-16** calculation over every header and 16-byte data block.

### Recipe 5 — Purdue Level 1–3.5 Conduit Validation: `modbus`, `s7comm`, `dnp3`, `bacnet`, `ethernetip` and `opcua`

One HMI talks to one imaginary PLC over every industrial protocol you are likely to meet on the conduit: Modbus TCP (handshake, read holding registers, write single register), S7comm (setup communication, read DB1), DNP3 (class 0 poll, select, operate), BACnet/IP (ReadProperty, WriteProperty), EtherNet/IP with CIP, and OPC UA binary (HEL, ACK, MSG).

Save as `ot_scada_conduit_test.frasm`:

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

Compile, inspect, replay:

```bash
frameassembly ot_scada_conduit_test.frasm ot_scada_conduit_test.pcap

# Inspect all 6 industrial protocols in tshark
tshark -r ot_scada_conduit_test.pcap

# Replay across your OT zone firewall or passive OT sensor SPAN port
sudo tcpreplay -i eth1 ot_scada_conduit_test.pcap
```

---

## 6. Incident Reproducers and Anonymized Captures

Attaching a live `tcpdump` to a vendor TAC case, a Jira ticket, or a runbook has two problems. The capture contains **customer subnets, internal hostnames, TLS `sni` strings, and a great deal of unrelated chatter**. And a binary `.pcap` cannot be reviewed in a Git pull request, or adjusted when someone asks *"what happens if the timer is 50 ms instead?"* The recipes below turn an incident into a few lines of `.frasm` code that anyone can read, diff, and replay.

### Recipe 6A — TCP Zero-Window Stall and Window Update Recovery

The ticket reads "the app froze for a few seconds, probably DNS". It was not DNS. The server's receive buffer filled up, advertised a zero window, and the client waited, politely, for it to drain. This reproducer shows the whole story: handshake, HTTP POST, `win 0`, a one-byte probe that also gets `win 0`, a window update to 32768, the `202 Accepted`, and a graceful close.

Save as `reproducer_zero_window.frasm`:

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

Compile and inspect the stall in `tshark`:

```bash
frameassembly reproducer_zero_window.frasm reproducer_zero_window.pcap

# View the exact TCP window progression and Wireshark's automatic ZeroWindow annotations
tshark -r reproducer_zero_window.pcap
```

### Recipe 6B — Routing and First-Hop Redundancy Failover: `bfd`, `ospf`, `bgp`, `vrrp`, `hsrp` and Gratuitous `arp`

"Failover took a bit" is not a measurement. This capture lays an entire core failover out as 10 frames: `bfd` session up and then down, `ospf` hello and link-state update, `bgp` open and update, `vrrp` and `hsrp` active-gateway advertisements, and a **gratuitous ARP** that refreshes the downstream switches' CAM tables. Arrange the `wait` timings to match your own convergence budget and see where the milliseconds go.

Save as `routing_ha_failover.frasm`:

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

Compile and inspect control-plane convergence:

```bash
frameassembly routing_ha_failover.frasm

# View the full sequence of BFD, OSPF, BGP, VRRP, HSRP, and Gratuitous ARP frames
tshark -r routing_ha_failover.pcap
```

### Recipe 6C — Anonymizing Customer `.pcap` Captures for Vendor Support: `frameassembly reverse`

`tcprewrite` can swap outer IP addresses, but it cannot scrub internal DNS `qname`s, TLS `sni` hostnames, HTTP `hosthdr` values, or syslog and SNMP strings. Changing a Layer 7 string changes its length, and that invalidates every downstream IP length, TCP/UDP checksum, and TCP `SEQ`/`ACK` offset in the stream. Doing it by hand is how you lose a Thursday.

`frameassembly reverse` handles the whole round trip:

1. Run `frameassembly reverse` on your `tcpdump` or Wireshark `.pcap` / `.pcapng` to decompile it into `.frasm` code with `host1`, `host2`, and so on.
2. Replace customer IPs and MACs in the `host` blocks with RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`), scrub internal `sni`, `qname`, and `hosthdr` strings, and delete unrelated background lines.
3. Recompile with `frameassembly sanitized_ticket.frasm sanitized_ticket.pcap`. FrameAssembly recalculates the Ethernet, IP, TCP, and UDP lengths, the L3/L4 checksums, and the TCP `SEQ`/`ACK` numbers. Encrypted payloads (SNMPv3 `authPriv`, TLS application data, SSH, IPsec `esp`) stay intact as `tcp` or `udp` statements with `payload` / `hexpayload`, so their wire bytes are not touched.

```bash
# 1. Decompile customer_incident.pcap -> sanitized_ticket.frasm
frameassembly reverse customer_incident.pcap sanitized_ticket.frasm
```

Edit `sanitized_ticket.frasm` to replace internal addresses and hostnames:

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

Preview the ladder, then compile the capture for the ticket:

```bash
# 2. Preview the packet ladder and compile sanitized_ticket.pcap for the vendor TAC ticket
frameassembly show sanitized_ticket.frasm
frameassembly sanitized_ticket.frasm sanitized_ticket.pcap
```

Layer 2 reproducers (`lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`) do not need IP addresses at all. Declare MAC-only `host` blocks and write the statements directly inside `compile { ... }`:

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

Next stops: [Getting Started](01_getting_started.md) for the first-hour walkthrough, and the [Docs Index](README.md) for the per-protocol reference guides.
