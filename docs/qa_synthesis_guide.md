# FrameAssembly Natural-Language Prompt to `.fasm` Synthesis Guide (LLM SFT, RAG & Constrained Decoding)

This guide provides **30 canonical Natural-Language Prompt $\rightarrow$ Compilable `.fasm` Solution pairs** across Layers 2, 3, 4, and 7, designed for Large Language Model (LLM) Supervised Fine-Tuning (SFT), Direct Preference Optimization (DPO), Retrieval-Augmented Generation (RAG), in-context few-shot prompting, and grammar-constrained decoding using [`grammar.ebnf`](../grammar.ebnf), [`frameassembly.gbnf`](../frameassembly.gbnf), and [`frameassembly.lark`](../frameassembly.lark).

---

## 1. Constrained Decoding & Zero-Hallucination Code Generation (`llama.cpp`, `vLLM`, `Outlines`, `XGrammar`)

FrameAssembly ships three synchronized formal grammar specifications in the repository root:
1. **[`grammar.ebnf`](../grammar.ebnf)** — ISO/IEC 14977 Extended Backus-Naur Form (`EBNF`) reference grammar.
2. **[`frameassembly.gbnf`](../frameassembly.gbnf)** — GGML BNF (`GBNF`) grammar for `llama.cpp` (`llama-cli`, `llama-server`).
3. **[`frameassembly.lark`](../frameassembly.lark)** — Earley/LALR Lark grammar for `vLLM`, `Outlines`, `Guidance`, `XGrammar`, and `llguidance`.

### 1.1 `llama.cpp` Constrained Decoding Example
```bash
llama-cli \
  -m qwen2.5-coder-7b-instruct-q8_0.gguf \
  --grammar-file frameassembly.gbnf \
  -p "Write a FrameAssembly (.fasm) program that performs a TCP 3-way handshake between 10.0.0.1 and 10.0.0.2 on port 443 and sends a TLS ClientHello with SNI 'secure.example.com'." \
  > generated.fasm && frameassembly generated.fasm -o synthesized.pcap
```

### 1.2 Canonical Pre-Training & SFT Header Convention
Every `.fasm` file in the FrameAssembly training corpus (`examples/`) follows four strict structural invariants:
- **Line 1 (`// PROMPT:`)**: Natural-language prompt describing the network engineering scenario.
- **Line 2 (`// TOKENS:`)**: Comma-separated list of exact uppercase lexer tokens used in the file.
- **Block Headers (`// INSTRUCTION:`)**: Precedes every `HOST`, `FLOW`, and `COMPILE` declaration.
- **Zero Deprecated Aliases**: Uses `IP` (never `IPV4`/`IPV6`), `SRCPORT`/`DSTPORT` (never `SPORT`/`DPORT`), `ACKNUM` (never `ACK_NUM`), `TTL` (never `HOP_LIMIT`), `QINQ <outer> INNER_VLAN <inner>`, and `REQID` (never `REQ_ID`).

---

## 2. Layer 2 Ethernet, VLAN, MPLS & Link Control Q&A Pairs (Q1–Q7)

### Q1: ARP Broadcast Request, Unicast Reply & Gratuitous ARP Announcement
**Prompt**: *"Write a FrameAssembly program where host `192.168.1.10` (`00:11:22:33:44:55`) sends an ARP Request for gateway `192.168.1.1` (`aa:bb:cc:dd:ee:ff`), receives a unicast ARP Reply after 2ms, and broadcasts a Gratuitous ARP announcement."*

```frameassembly
// PROMPT: ARP broadcast request, unicast reply, and Gratuitous ARP announcement on a local Ethernet subnet.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, ARP, REQUEST, REPLY, GRATUITOUS, DSTMAC, SHA, SPA, THA, TPA, WAIT, COMPILE

// INSTRUCTION: Define the local host and default gateway with explicit IPv4 and MAC addresses.
host host_a  { ip 192.168.1.10 mac 00:11:22:33:44:55 }
host gateway { ip 192.168.1.1  mac aa:bb:cc:dd:ee:ff }

// INSTRUCTION: Execute ARP request, unicast reply, and RFC 5227 Gratuitous ARP announcement.
flow arp_resolution_and_garp(h, gw) {
    h -> gw arp request dstmac ff:ff:ff:ff:ff:ff tha 00:00:00:00:00:00
    h <- gw arp reply wait 2ms
    h -> gw arp gratuitous dstmac ff:ff:ff:ff:ff:ff sha 00:11:22:33:44:55 spa 192.168.1.10 tpa 192.168.1.10 wait 2ms
}

// INSTRUCTION: Compile the ARP resolution and Gratuitous ARP flow.
compile {
    arp_resolution_and_garp(host_a, gateway)
}
```

---

### Q2: IEEE 802.1Q VLAN Tagging & 802.1ad QinQ Provider Bridging
**Prompt**: *"Synthesize an 802.1Q single-tagged frame (VLAN 200, PCP 5, DEI 0) and an 802.1ad QinQ double-tagged frame (outer S-VLAN 1000, inner C-VLAN 200, PCP 5) between `10.1.0.1` and `10.1.0.2`."*

```frameassembly
// PROMPT: IEEE 802.1Q single-tagged VLAN frame and 802.1ad QinQ double-tagged Metro Ethernet frame.
// TOKENS: HOST, IP, FLOW, ->, VLAN, QINQ, INNER_VLAN, PCP, DEI, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Define Provider Edge (PE) routers pe1 and pe2.
host pe1 { ip 10.1.0.1 }
host pe2 { ip 10.1.0.2 }

// INSTRUCTION: Send an 802.1Q VLAN 200 frame followed by an 802.1ad QinQ (1000/200) frame.
flow vlan_and_qinq_tagging(a, b) {
    a -> b vlan 200 pcp 5 dei 0 payload "802.1Q Voice VLAN Frame"
    a -> b qinq 1000 inner_vlan 200 pcp 5 dei 0 payload "802.1ad QinQ Metro Ethernet Frame" wait 2ms
}

// INSTRUCTION: Compile the VLAN and QinQ tagging scenario.
compile {
    vlan_and_qinq_tagging(pe1, pe2)
}
```

---

### Q3: MPLS Label Switching (`MPLS`, `EXP`, `BOS`, `MPLS_TTL`)
**Prompt**: *"Model an ingress Label Edge Router (`10.200.0.1`) sending an MPLS-labeled packet (`LABEL 24010`, `EXP 5`, `BOS 1`, `MPLS_TTL 64`) to a core Label Switch Router (`10.200.0.2`)."*

```frameassembly
// PROMPT: MPLS label encapsulation with 20-bit label 24010, Traffic Class EXP 5, BOS 1, and TTL 64.
// TOKENS: HOST, IP, FLOW, ->, MPLS, EXP, BOS, MPLS_TTL, PAYLOAD, COMPILE

// INSTRUCTION: Define ingress LER and core transit LSR endpoints.
host ingress_ler { ip 10.200.0.1 }
host transit_lsr { ip 10.200.0.2 }

// INSTRUCTION: Encapsulate payload with MPLS label 24010 and Traffic Class 5 (EF).
flow mpls_lsp_forward(ler, lsr) {
    ler -> lsr mpls 24010 exp 5 bos 1 mpls_ttl 64 payload "MPLS L3VPN Customer Frame"
}

// INSTRUCTION: Compile the MPLS label switching flow.
compile {
    mpls_lsp_forward(ingress_ler, transit_lsr)
}
```

---

### Q4: Spanning Tree Protocol (`STP`) & Link Layer Discovery Protocol (`LLDP`)
**Prompt**: *"Synthesize an IEEE 802.1D STP Configuration BPDU and an IEEE 802.1AB LLDP neighbor advertisement between two switches."*

```frameassembly
// PROMPT: IEEE 802.1D Spanning Tree Configuration BPDU and IEEE 802.1AB LLDP neighbor discovery exchange.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, STP, ROOT_ID, BRIDGE_ID, COST, PORT_ID, HELLO_TIME, MAX_AGE, FORWARD_DELAY, LLDP, CHASSIS_ID, TTL, SYSNAME, SYSDESC, WAIT, COMPILE

// INSTRUCTION: Define root core switch and distribution switch with explicit MAC addresses.
host core_sw { ip 10.0.0.1 mac 00:1c:73:00:00:01 }
host dist_sw { ip 10.0.0.2 mac 00:1c:73:00:00:02 }

// INSTRUCTION: Transmit an STP root BPDU followed by bidirectional LLDP advertisements.
flow stp_and_lldp_discovery(core, dist) {
    core -> dist stp root_id "4096/00:1c:73:00:00:01" bridge_id "4096/00:1c:73:00:00:01" cost 0 max_age 20 hello_time 2 forward_delay 15
    core -> dist lldp chassis_id "core-sw-01.dc" port_id "Ethernet1/1" ttl 120 sysname "core-sw-01" sysdesc "Arista EOS" wait 2ms
    core <- dist lldp chassis_id "dist-sw-01.dc" port_id "Ethernet49/1" ttl 120 sysname "dist-sw-01" sysdesc "Cisco NX-OS" wait 2ms
}

// INSTRUCTION: Compile the STP and LLDP control-plane flow.
compile {
    stp_and_lldp_discovery(core_sw, dist_sw)
}
```

---

### Q5: IEEE 802.3ad LACP Link Aggregation & 802.1X EAPOL Authentication
**Prompt**: *"Write a `.fasm` script that negotiates an LACP port-channel (`ACTOR_KEY 10`, `PARTNER_KEY 10`) and performs an 802.1X EAPOL-Start and EAP-Identity handshake."*

```frameassembly
// PROMPT: IEEE 802.3ad LACP link aggregation sync and IEEE 802.1X EAPOL port authentication handshake.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, LACP, ACTOR_SYS, ACTOR_KEY, ACTOR_PORT, ACTOR_STATE, PARTNER_SYS, PARTNER_KEY, PARTNER_PORT, PARTNER_STATE, EAPOL, VERSION, TYPE, START, EAP_PACKET, EAP_CODE, EAP_ID, EAP_METHOD, IDENTITY, WAIT, COMPILE

// INSTRUCTION: Define two aggregation endpoints with MAC addresses.
host node_a { ip 10.0.10.1 mac 00:1b:21:01:02:03 }
host node_b { ip 10.0.10.2 mac 00:1b:21:04:05:06 }

// INSTRUCTION: Synchronize LACP actor/partner state and run 802.1X EAPOL identity verification.
flow lacp_and_eapol_bringup(a, b) {
    a -> b lacp actor_sys 00:1b:21:01:02:03 actor_key 10 actor_port 1 actor_state 0x3d partner_sys 00:1b:21:04:05:06 partner_key 10 partner_port 1 partner_state 0x3d
    a -> b eapol version 2 type start wait 2ms
    a <- b eapol version 2 type eap_packet eap_code 1 eap_id 1 eap_method 1 wait 2ms
    a -> b eapol version 2 type eap_packet eap_code 2 eap_id 1 eap_method 1 identity "host/node-a.corp.example" wait 2ms
}

// INSTRUCTION: Compile the LACP and EAPOL port bring-up flow.
compile {
    lacp_and_eapol_bringup(node_a, node_b)
}
```

---

## 3. Layer 3 Control Plane, Routing & Tunneling Q&A Pairs (Q6–Q9)

### Q6: Polymorphic Dual-Stack ICMPv4 & ICMPv6 Echo Flow
**Prompt**: *"Write a single polymorphic FrameAssembly `FLOW` that performs an ICMP Echo Request and Echo Reply, and invoke it over both IPv4 (`10.0.0.10` -> `8.8.8.8`) and IPv6 (`2001:db8::10` -> `2001:4860:4860::8888`)."*

```frameassembly
// PROMPT: Polymorphic dual-stack ICMPv4 and ICMPv6 Echo Request and Echo Reply using a single reusable FLOW.
// TOKENS: HOST, IP, FLOW, ->, <-, ICMP, ECHO_REQUEST, ECHO_REPLY, ID, SEQ, TTL, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare IPv4 endpoints and IPv6 endpoints.
host client_v4 { ip 10.0.0.10 }
host dns_v4    { ip 8.8.8.8 }
host client_v6 { ip 2001:db8::10 }
host dns_v6    { ip 2001:4860:4860::8888 }

// INSTRUCTION: Define a polymorphic ping flow that works over both IPv4 and IPv6.
flow dual_stack_ping(src, dst) {
    src -> dst icmp echo_request id 100 seq 1 ttl 64 payload "polymorphic-ping"
    src <- dst icmp echo_reply id 100 seq 1 ttl 57 payload "polymorphic-ping" wait 5ms
}

// INSTRUCTION: Compile the flow for IPv4 and IPv6 endpoint pairs.
compile {
    dual_stack_ping(client_v4, dns_v4)
    dual_stack_ping(client_v6, dns_v6)
}
```

---

### Q7: IPv6 Neighbor Discovery (`NDP`) & Multicast Listener Discovery (`MLD`)
**Prompt**: *"Simulate IPv6 SLAAC Router Solicitation/Advertisement, Neighbor Solicitation/Advertisement (`TARGET 2001:db8::1`), and MLDv2 multicast group join (`GROUP ff02::1:ff00:1`)."*

```frameassembly
// PROMPT: IPv6 Neighbor Discovery (ROUTER_SOLICIT, ROUTER_ADVERT, NEIGHBOR_SOLICIT, NEIGHBOR_ADVERT) and MLDv2 multicast listener report.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, NDP, ROUTER_SOLICIT, ROUTER_ADVERT, NEIGHBOR_SOLICIT, NEIGHBOR_ADVERT, TARGET, SLLA, TLLA, ROUTER_LIFETIME, TTL, MLD, REPORT, VERSION, GROUP, WAIT, COMPILE

// INSTRUCTION: Define IPv6 host and router with link-local/global addresses and MACs.
host host_v6   { ip 2001:db8::100 mac 00:11:22:33:44:66 }
host router_v6 { ip 2001:db8::1   mac aa:bb:cc:dd:ee:66 }

// INSTRUCTION: Execute ROUTER_SOLICIT, ROUTER_ADVERT, NEIGHBOR_SOLICIT, NEIGHBOR_ADVERT, and MLDv2 Report.
flow ipv6_ndp_and_mld(h, r) {
    h -> r ndp router_solicit slla 00:11:22:33:44:66 ttl 255
    h <- r ndp router_advert slla aa:bb:cc:dd:ee:66 router_lifetime 1800 ttl 255 wait 2ms
    h -> r ndp neighbor_solicit target 2001:db8::1 slla 00:11:22:33:44:66 ttl 255 wait 2ms
    h <- r ndp neighbor_advert target 2001:db8::1 tlla aa:bb:cc:dd:ee:66 ttl 255 wait 2ms
    h -> r mld report version 2 group ff02::1:ff00:100 wait 2ms
}

// INSTRUCTION: Compile the IPv6 NDP and MLDv2 onboarding flow.
compile {
    ipv6_ndp_and_mld(host_v6, router_v6)
}
```

---

### Q8: OSPF Adjacency, BGP-4 Route Exchange, BFD & VRRPv3
**Prompt**: *"Write a `.fasm` script where router `10.0.0.1` (ASN 65001) establishes BFD, sends an OSPF Hello in Area 0, exchanges BGP OPEN/KEEPALIVE/UPDATE messages with `10.0.0.2` (ASN 65002), and advertises VRRPv3 VRID 10."*

```frameassembly
// PROMPT: Control-plane routing convergence combining BFD, OSPFv2 Hello, BGP-4 peering/update, and VRRPv3 master heartbeat.
// TOKENS: HOST, IP, FLOW, ->, <-, BFD, STATE, MY_DISC, YOUR_DISC, MIN_TX, MIN_RX, MULT, OSPF, HELLO, ROUTER_ID, AREA_ID, BGP, OPEN, KEEPALIVE, UPDATE, ASN, HOLDTIME, BGPID, PREFIX, NEXTHOP, VRRP, VRID, PRIORITY, VIP, WAIT, COMPILE

// INSTRUCTION: Define two core routers r1 and r2.
host r1 { ip 10.0.0.1 }
host r2 { ip 10.0.0.2 }

// INSTRUCTION: Bring up BFD, OSPF Area 0, eBGP peering, and VRRPv3 virtual gateway redundancy.
flow routing_control_plane(a, b) {
    a -> b bfd state 3 my_disc 101 your_disc 202 min_tx 50000 min_rx 50000 mult 3
    a -> b ospf hello router_id 1.1.1.1 area_id 0 wait 2ms
    a -> b bgp open asn 65001 holdtime 180 bgpid 1.1.1.1 wait 2ms
    a <- b bgp open asn 65002 holdtime 180 bgpid 2.2.2.2 wait 2ms
    a -> b bgp keepalive wait 1ms
    a -> b bgp update asn 65001 prefix "172.16.0.0/16" nexthop 10.0.0.1 wait 2ms
    a -> b vrrp vrid 10 priority 200 vip 10.0.0.254 wait 2ms
}

// INSTRUCTION: Compile the routing control-plane scenario.
compile {
    routing_control_plane(r1, r2)
}
```

---

### Q9: Network Overlays (`GRE`, `VXLAN`, `GENEVE`) & VPNs (`IKEV2`, `ESP`, `AH`, `WIREGUARD`)
**Prompt**: *"Synthesize tunnel and VPN packets across GRE (`GRE_KEY 100`), VXLAN (`VNI 5000`), GENEVE (`VNI 6000`), IPsec (`IKEV2`, `ESP`, `AH`), and WireGuard (`TYPE INITIATION`, `TYPE DATA`)."*

```frameassembly
// PROMPT: Multi-tunnel overlay and cryptographic VPN showcase covering GRE, VXLAN, GENEVE, IKEv2, ESP, AH, and WireGuard.
// TOKENS: HOST, IP, FLOW, ->, <-, GRE, GRE_KEY, SEQ, VXLAN, VNI, GENEVE, IKEV2, SA_INIT, INITIATOR_SPI, RESPONDER_SPI, MSGID, ESP, SPI, AH, WIREGUARD, TYPE, INITIATION, DATA, SENDER, RECEIVER, COUNTER, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Define two WAN tunnel gateways gw1 and gw2.
host gw1 { ip 198.51.100.1 }
host gw2 { ip 203.0.113.1 }

// INSTRUCTION: Transmit GRE, VXLAN, GENEVE, IKEv2/ESP/AH, and WireGuard frames.
flow overlay_and_vpn_showcase(a, b) {
    a -> b gre gre_key 100 seq 1 payload "GRE Encapsulated Frame"
    a -> b vxlan vni 5000 payload "VXLAN VNI 5000 Tenant Frame" wait 1ms
    a -> b geneve vni 6000 payload "GENEVE VNI 6000 Cloud Frame" wait 1ms
    a -> b ikev2 sa_init initiator_spi 0x1122334455667788 responder_spi 0 msgid 0 wait 2ms
    a -> b esp spi 0xabcdef01 seq 1 payload "IPsec ESP Ciphertext" wait 1ms
    a -> b ah spi 0xabcdef02 seq 1 payload "IPsec AH Authenticated Packet" wait 1ms
    a -> b wireguard type initiation sender 0x01020304 payload "WG_NOISE_INIT" wait 1ms
    a -> b wireguard type data receiver 0x01020304 counter 1 payload "WireGuard ChaCha20Poly1305" wait 1ms
}

// INSTRUCTION: Compile the overlay and VPN tunnel showcase.
compile {
    overlay_and_vpn_showcase(gw1, gw2)
}
```

---

## 4. Layer 4 Transport & Layer 7 Application Q&A Pairs (Q10–Q16)

### Q10: Stateful TCP 3-Way Handshake, HTTP/1.1 GET & Graceful FIN Teardown
**Prompt**: *"Establish a TCP connection from `10.0.1.50:52000` to `10.0.1.10:80` with MSS 1460, WSCALE 7, and SACK_PERM, send an HTTP GET request for `/healthz`, receive an HTTP 200 OK JSON response, and close with a FIN/ACK teardown."*

```frameassembly
// PROMPT: Stateful TCP 3-way handshake, HTTP/1.1 GET /healthz request/response, and graceful FIN teardown.
// TOKENS: HOST, IP, FLOW, ->, <-, TCP, SYN, ACK, FIN, SRCPORT, DSTPORT, MSS, WSCALE, SACK_PERM, HTTP, GET, RESPONSE, URI, HOST_HDR, STATUS, REASON, CONTENT_TYPE, BODY, WAIT, COMPILE

// INSTRUCTION: Define client and web server endpoints.
host client { ip 10.0.1.50 }
host server { ip 10.0.1.10 }

// INSTRUCTION: Execute TCP handshake, HTTP GET/200 exchange, and TCP FIN teardown.
flow web_healthcheck(c, s) {
    c -> s tcp syn srcport 52000 dstport 80 mss 1460 wscale 7 sack_perm
    c <- s tcp syn ack mss 1460 wscale 7 sack_perm wait 1ms
    c -> s tcp ack wait 1ms
    c -> s http get uri "/healthz" host_hdr "service.internal" wait 2ms
    c <- s http response status 200 reason "OK" content_type "application/json" body "{\"ok\":true}" wait 2ms
    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

// INSTRUCTION: Compile the stateful TCP and HTTP healthcheck flow.
compile {
    web_healthcheck(client, server)
}
```

---

### Q11: SCTP 4-Way Association Handshake (`INIT`, `INIT_ACK`, `COOKIE_ECHO`, `COOKIE_ACK`, `DATA`, `SACK`)
**Prompt**: *"Construct an SCTP 4-way handshake on telecom signaling port 3868 followed by a `DATA` chunk and `SACK` acknowledgment."*

```frameassembly
// PROMPT: RFC 4960 SCTP 4-way association setup, DATA transmission, and SACK acknowledgment.
// TOKENS: HOST, IP, FLOW, ->, <-, SCTP, SRCPORT, DSTPORT, VTAG, CHUNK, INIT, INIT_ACK, COOKIE_ECHO, COOKIE_ACK, DATA, SACK, STREAM, SEQ, PPID, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Define 5G AMF and gNodeB signaling endpoints.
host amf_node { ip 10.50.0.1 }
host gnb_node { ip 10.50.0.2 }

// INSTRUCTION: Perform SCTP 4-way handshake and exchange NGAP signaling data.
flow sctp_ngap_signaling(a, b) {
    a -> b sctp srcport 38412 dstport 38412 vtag 0 chunk init
    a <- b sctp srcport 38412 dstport 38412 vtag 0x11223344 chunk init_ack wait 1ms
    a -> b sctp srcport 38412 dstport 38412 vtag 0x11223344 chunk cookie_echo wait 1ms
    a <- b sctp srcport 38412 dstport 38412 vtag 0x55667788 chunk cookie_ack wait 1ms
    a -> b sctp srcport 38412 dstport 38412 vtag 0x11223344 chunk data stream 1 seq 1 ppid 60 payload "NGAP_InitialUEMessage" wait 2ms
    a <- b sctp srcport 38412 dstport 38412 vtag 0x55667788 chunk sack seq 1 wait 1ms
}

// INSTRUCTION: Compile the SCTP signaling association flow.
compile {
    sctp_ngap_signaling(amf_node, gnb_node)
}
```

---

### Q12: Encrypted SNMPv3 USM `authPriv` (`HMAC-SHA256` + `AES`) Polling
**Prompt**: *"Synthesize an SNMPv3 `GET` request and encrypted `RESPONSE` between `192.168.10.5` and `192.168.10.1` using USM user `netadmin`, `SHA256` authentication, and `AES` encryption."*

```frameassembly
// PROMPT: SNMPv3 USM authPriv encrypted GET and RESPONSE using HMAC-SHA256 authentication and AES CFB-128 privacy.
// TOKENS: HOST, IP, FLOW, ->, <-, SNMP3, GET, RESPONSE, USER, ENGINEID, ENGINEBOOTS, ENGINETIME, AUTH, SHA256, PRIV, AES, REQID, VARBIND, NULLVAL, STRING, WAIT, COMPILE

// INSTRUCTION: Define the NMS polling manager and core router agent.
host nms    { ip 192.168.10.5 }
host router { ip 192.168.10.1 }

// INSTRUCTION: Poll sysDescr.0 over SNMPv3 authPriv (SHA256 + AES).
flow snmpv3_encrypted_poll(mgr, agt) {
    mgr -> agt snmp3 get user "netadmin" engineid "80001f88801122334455" engineboots 10 enginetime 5000 auth sha256 "MyAuthSecretKey99!" priv aes "MyPrivSecretKey99!" reqid 1 varbind 1.3.6.1.2.1.1.1.0 nullval
    mgr <- agt snmp3 response user "netadmin" engineid "80001f88801122334455" engineboots 10 enginetime 5001 auth sha256 "MyAuthSecretKey99!" priv aes "MyPrivSecretKey99!" reqid 1 varbind 1.3.6.1.2.1.1.1.0 string "Linux core-router 6.8.0" wait 2ms
}

// INSTRUCTION: Compile the SNMPv3 authPriv polling flow.
compile {
    snmpv3_encrypted_poll(nms, router)
}
```

---

### Q13: Industrial OT / ICS (`MODBUS`, `DNP3`, `S7COMM`, `OPCUA`)
**Prompt**: *"Synthesize a SCADA HMI polling a PLC via Modbus TCP (`READ_HOLDING_REGISTERS`), DNP3 (`READ`), Siemens S7comm (`READ_VAR`), and OPC UA (`HEL`/`ACK`/`MSG`)."*

```frameassembly
// PROMPT: Multi-protocol ICS/SCADA polling flow combining Modbus TCP, IEEE 1815 DNP3, Siemens S7comm, and IEC 62541 OPC UA.
// TOKENS: HOST, IP, FLOW, ->, <-, MODBUS, FUNC, TXID, UNITID, ADDR, COUNT, IS_RESPONSE, DNP3, SRC, DST, SEQ, GROUP, VARIATION, S7COMM, ROSCTR, PDU_REF, AREA, DB_NUM, OFFSET, OPCUA, MSG_TYPE, CHUNK_TYPE, ENDPOINT_URL, SECURE_CHANNEL_ID, TOKEN_ID, SEQ_NUM, REQID, NODE_ID, WAIT, COMPILE

// INSTRUCTION: Define SCADA HMI master and multi-protocol industrial PLC.
host scada_hmi { ip 192.168.100.10 }
host plc_node  { ip 192.168.100.50 }

// INSTRUCTION: Poll the PLC over Modbus TCP, DNP3, Siemens S7comm, and OPC UA.
flow industrial_ot_poll(hmi, plc) {
    hmi -> plc modbus func "READ_HOLDING_REGISTERS" txid 1 unitid 1 addr 40001 count 4
    hmi <- plc modbus func "READ_HOLDING_REGISTERS" txid 1 unitid 1 count 4 is_response wait 2ms
    hmi -> plc dnp3 func "READ" src 1 dst 50 seq 1 group 60 variation 1 wait 2ms
    hmi <- plc dnp3 func "RESPONSE" src 50 dst 1 seq 1 group 30 variation 1 wait 2ms
    hmi -> plc s7comm rosctr "JOB" func "READ_VAR" pdu_ref 10 area 0x84 db_num 1 offset 0 count 4 wait 2ms
    hmi -> plc opcua msg_type "HEL" chunk_type "F" endpoint_url "opc.tcp://192.168.100.50:4840" wait 2ms
    hmi <- plc opcua msg_type "ACK" chunk_type "F" wait 2ms
    hmi -> plc opcua msg_type "MSG" chunk_type "F" secure_channel_id 1 token_id 1 seq_num 1 reqid 1 node_id "ns=2;s=BoilerTemp" wait 2ms
}

// INSTRUCTION: Compile the industrial OT polling scenario.
compile {
    industrial_ot_poll(scada_hmi, plc_node)
}
```

---

## 5. Cross-References

- **[`docs/architecture_and_grammar.md`](./architecture_and_grammar.md)** — Complete EBNF/GBNF/Lark grammar rules and compiler architecture.
- **[`docs/topologies_and_dual_stack.md`](./topologies_and_dual_stack.md)** — Multi-host enterprise, cloud, 5G, and ICS topologies (`examples/topologies/`).
