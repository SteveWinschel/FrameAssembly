# Practical Use Cases & Scenarios

Each recipe below is a complete, compilable `.fasm` file solving a common packet-crafting task. Save any snippet to a `.fasm` file, compile it with `frameassembly <file>.fasm -o out.pcap`, and open `out.pcap` in Wireshark or inject it onto a test interface with `tcpreplay`.

---

## 1. Testing Firewall Rules, ACLs & Stateful Inspection

Standard tools like `ping` and `curl` only test normal OS-initiated connections. When validating firewall rulesets, DMZ segmentation, or stateless ACLs, you often need specific source ports, rejected port probes, out-of-state TCP flags, or `DF` MTU probes in a single repeatable capture:

```frameassembly
host external_client {
    ip 198.51.100.42
    mac 00:0c:29:11:22:33
}

host dmz_gateway {
    ip 203.0.113.10
    mac 00:1b:21:aa:bb:cc
}

flow firewall_policy_audit(ext, gw) {
    // 1. Permitted HTTPS 3-way handshake
    ext -> gw tcp syn srcport 51001 dstport 443 wait 1ms
    ext <- gw tcp syn ack wait 1ms
    ext -> gw tcp ack wait 5ms

    // 2. Blocked database port 3306 SYN and immediate RST+ACK rejection
    ext -> gw tcp syn srcport 51002 dstport 3306 wait 1ms
    ext <- gw tcp rst ack wait 5ms

    // 3. Out-of-state ACK probe on SSH port 22 (verifies stateful table drops)
    ext -> gw tcp ack srcport 51003 dstport 22 seq 8000 acknum 8000 wait 5ms

    // 4. Unusual flag combination (FIN + PSH + URG) for intrusion prevention checks
    ext -> gw tcp fin psh urg srcport 51004 dstport 445 wait 5ms

    // 5. Blocked ping answered with ICMP Administratively Prohibited (Code 13)
    ext -> gw df ttl 64 icmp echo_request id 99 seq 1 payload "ACL_PING_TEST" wait 1ms
    ext <- gw icmp dest_unreach code 13
}

compile {
    firewall_policy_audit(external_client, dmz_gateway)
}
```

---

## 2. Simulating SNMPv1, SNMPv2c & Encrypted SNMPv3 Traps

Testing monitoring alert rules (Zabbix, Checkmk, LibreNMS, PRTG, `snmptrapd`) normally means waiting for real device faults or wrestling with MIB dependencies and SNMPv3 key-localization flags. This scenario emits legacy `SNMPv1`, `SNMPv2c`, and encrypted `SNMPv3` (`SHA-256` + `AES-128`) traps directly:

```frameassembly
host core_switch {
    ip 10.100.0.254
    mac 00:1c:73:a0:00:fe
}

host nms_collector {
    ip 10.100.0.10
    mac 00:50:56:a0:00:10
}

flow snmp_alert_simulation(sw, nms) {
    // SNMPv1 linkDown generic trap (gentrap 2) on interface index 5
    sw -> nms snmp1 trap community "public" enterprise 1.3.6.1.4.1.9.1.1 agentip 10.100.0.254 gentrap 2 spectrap 0 sysuptime 125000 varbind 1.3.6.1.2.1.2.2.1.1.5 int 5 wait 10ms

    // SNMPv2c linkUp trap (1.3.6.1.6.3.1.1.5.4) with interface description
    sw -> nms snmp2 trap community "noc_traps" reqid 201 sysuptime 125500 oid 1.3.6.1.6.3.1.1.5.4 varbind 1.3.6.1.2.1.31.1.1.1.1.5 string "TenGigabitEthernet1/1/5" wait 10ms

    // Encrypted SNMPv3 USM authPriv trap (HMAC-SHA256 + AES-128) for high chassis temperature
    sw -> nms snmp3 trap user "nms_v3_ops" engineid "80001f8880001c73a000fe" engineboots 4 enginetime 86400 auth sha256 "TrapAuthSecret2026!" priv aes "TrapPrivSecret2026!" reqid 301 oid 1.3.6.1.4.1.9.9.13.3.0.1 varbind 1.3.6.1.2.1.1.5.0 string "core-sw-01" varbind 1.3.6.1.4.1.9.9.13.1.3.1.3.1 gauge32 84
}

compile {
    snmp_alert_simulation(core_switch, nms_collector)
}
```

---

## 3. Verifying VLAN Trunks, Carrier QinQ & DiffServ QoS Policies

Desktop operating systems often strip 802.1Q VLAN tags or restrict unprivileged DSCP markings. FrameAssembly stamps exact Layer 2 `VLAN` / `PCP`, 802.1ad `QINQ`, `MPLS` `EXP`, and Layer 3 `DSCP` values onto frames for switch trunk and WAN shaper verification:

```frameassembly
host branch_cpe { ip 10.20.0.10 mac 00:1c:73:20:00:10 }
host hq_concentrator { ip 10.20.0.1 mac 00:1c:73:20:00:01 }

flow qos_and_trunk_check(branch, hq) {
    // Voice VLAN 110: CoS 5 + DSCP 46 (Expedited Forwarding)
    branch -> hq vlan 110 pcp 5 dscp 46 rtp pt 0 seq 1 timestamp 160 ssrc 0x11223344 payload "G711_VOICE_20MS" wait 20ms

    // Video VLAN 120: CoS 4 + DSCP 34 (AF41)
    branch -> hq vlan 120 pcp 4 dscp 34 rtp pt 96 seq 1 timestamp 3600 ssrc 0x55667788 marker 1 payload "H264_KEYFRAME" wait 10ms

    // Double-tagged 802.1ad QinQ service trunk (S-VLAN 2500, C-VLAN 300, Drop-Eligible)
    branch -> hq qinq 2500 inner_vlan 300 pcp 1 dei 1 dscp 8 udp srcport 49100 dstport 873 payload "BULK_RSYNC_BLOCK"
}

compile {
    qos_and_trunk_check(branch_cpe, hq_concentrator)
}
```

---

## 4. Validating IDS/IPS Rules, TLS SNI Filtering & DNS Policies

Generate deterministic, noise-free `.pcap` inputs (`suricata -r test.pcap` or `zeek -r test.pcap`) to verify signature detection, TLS `SNI` inspection, HTTP header matching, and DNS sinkhole responses:

```frameassembly
host endpoint { ip 10.40.5.25 mac 00:50:56:40:05:25 }
host gateway  { ip 10.40.5.1  mac 00:1c:73:40:05:01 }

flow ids_and_sni_validation(client, gw) {
    // DNS lookup blocked by policy (RCODE 5 = REFUSED)
    client -> gw dns query txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "A" wait 1ms
    client <- gw dns response txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "A" rcode 5 wait 5ms

    // TLS 1.3 ClientHello carrying a specific SNI and ALPN for DPI inspection
    client -> gw tcp syn srcport 53443 dstport 443 wait 1ms
    client <- gw tcp syn ack wait 1ms
    client -> gw tcp ack wait 1ms
    client -> gw tls client_hello sni "unapproved-saas.example.net" ciphersuite 4866 alpn "h2" wait 2ms
    client <- gw tls alert payload "ACCESS_DENIED_SNI_POLICY"
}

compile {
    ids_and_sni_validation(endpoint, gateway)
}
```

---

## 5. Testing SIEM Syslog & Flow Telemetry Collectors

Verify that your log and flow ingestion pipeline parses RFC 5424 Syslog, Cisco NetFlow v5, IPFIX (NetFlow v10), and sFlow v5 datagrams accurately:

```frameassembly
host border_router  { ip 10.250.0.1   mac 00:1c:73:fa:00:01 }
host telemetry_node { ip 10.250.0.100 mac 00:50:56:fa:00:64 }

flow noc_telemetry_ingest(rtr, col) {
    rtr -> col syslog facility 16 severity 2 hostname "border-rtr-01" app "bgpd" procid "1842" msg "BGP-3-NOTIFICATION: peer 198.51.100.1 Hold Timer Expired" wait 2ms
    rtr -> col netflow srcip 198.51.100.25 dstip 203.0.113.80 srcport 52400 dstport 443 proto 6 packets 15400 octets 21560000 wait 2ms
    rtr -> col ipfix domain_id 4001 srcip 198.51.100.25 dstip 203.0.113.80 srcport 52400 dstport 443 proto 6 packets 15400 octets 21560000 wait 2ms
    rtr -> col sflow agent_ip 10.250.0.1 sub_agent_id 1 uptime 86400000 samples 8
}

compile {
    noc_telemetry_ingest(border_router, telemetry_node)
}
```

---

## 6. Routing, BFD & Gateway Failover Simulation

Build control-plane captures combining sub-second BFD liveness, OSPF/BGP peering, and VRRP + Gratuitous ARP virtual IP takeover:

```frameassembly
host core_a { ip 10.0.0.1 mac 00:00:5e:00:01:0a }
host core_b { ip 10.0.0.2 mac 00:1c:73:00:00:02 }
host lan_bc { ip 10.0.0.255 mac ff:ff:ff:ff:ff:ff }

flow control_plane_convergence(a, b, bcast) {
    a -> b bfd state 3 my_disc 101 your_disc 202 min_tx 50000 min_rx 50000 mult 3 ttl 255 wait 1ms
    a -> b ospf hello router_id 1.1.1.1 area_id 0 hello_interval 10 dead_interval 40 ttl 1 wait 2ms
    a -> b bgp open asn 65001 holdtime 90 bgpid 1.1.1.1 ttl 255 wait 2ms
    a <- b bgp open asn 65002 holdtime 90 bgpid 2.2.2.2 ttl 255 wait 2ms
    a -> b bgp update asn 65001 prefix "172.16.0.0/16" nexthop 10.0.0.1 ttl 255 wait 5ms

    // VRRPv3 Master advertisement + Gratuitous ARP claiming VIP 10.0.0.254
    a -> b vrrp version 3 vrid 10 priority 200 adv_int 1 vip 10.0.0.254 ttl 255 wait 1ms
    a -> bcast arp reply gratuitous sendermac 00:00:5e:00:01:0a senderip 10.0.0.254 targetmac ff:ff:ff:ff:ff:ff targetip 10.0.0.254
}

compile {
    control_plane_convergence(core_a, core_b, lan_bc)
}
```

---

## 7. Industrial / OT Firewall & Dissector Testing

Validate IEC 62443 industrial firewall rules and OT security sensors across Modbus TCP, Siemens S7comm, DNP3, and OPC UA without physical PLCs:

```frameassembly
host scada_hmi { ip 192.168.100.10 mac 00:1b:21:a0:00:10 }
host plant_plc { ip 192.168.100.50 mac 00:0e:8c:a0:00:50 }

flow ot_conduit_polling(hmi, plc) {
    hmi -> plc vlan 110 pcp 6 modbus func "READ_HOLDING_REGISTERS" txid 1 unitid 1 addr 40001 count 4 wait 2ms
    hmi <- plc vlan 110 pcp 6 modbus func "READ_HOLDING_REGISTERS" txid 1 unitid 1 count 4 is_response wait 5ms
    hmi -> plc vlan 110 pcp 6 s7comm rosctr "JOB" func "READ_VAR" pdu_ref 10 area 0x84 db_num 1 offset 0 count 8 wait 5ms
    hmi -> plc vlan 110 pcp 6 opcua msg_type "HEL" chunk_type "F" endpoint_url "opc.tcp://192.168.100.50:4840"
}

compile {
    ot_conduit_polling(scada_hmi, plant_plc)
}
```