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
HOST host_a  { IP 192.168.1.10 MAC 00:11:22:33:44:55 }
HOST gateway { IP 192.168.1.1  MAC aa:bb:cc:dd:ee:ff }

// INSTRUCTION: Execute ARP request, unicast reply, and RFC 5227 Gratuitous ARP announcement.
FLOW arp_resolution_and_garp(h, gw) {
    h -> gw ARP REQUEST DSTMAC ff:ff:ff:ff:ff:ff THA 00:00:00:00:00:00
    h <- gw ARP REPLY WAIT 2ms
    h -> gw ARP GRATUITOUS DSTMAC ff:ff:ff:ff:ff:ff SHA 00:11:22:33:44:55 SPA 192.168.1.10 TPA 192.168.1.10 WAIT 2ms
}

// INSTRUCTION: Compile the ARP resolution and Gratuitous ARP flow.
COMPILE {
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
HOST pe1 { IP 10.1.0.1 }
HOST pe2 { IP 10.1.0.2 }

// INSTRUCTION: Send an 802.1Q VLAN 200 frame followed by an 802.1ad QinQ (1000/200) frame.
FLOW vlan_and_qinq_tagging(a, b) {
    a -> b VLAN 200 PCP 5 DEI 0 PAYLOAD "802.1Q Voice VLAN Frame"
    a -> b QINQ 1000 INNER_VLAN 200 PCP 5 DEI 0 PAYLOAD "802.1ad QinQ Metro Ethernet Frame" WAIT 2ms
}

// INSTRUCTION: Compile the VLAN and QinQ tagging scenario.
COMPILE {
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
HOST ingress_ler { IP 10.200.0.1 }
HOST transit_lsr { IP 10.200.0.2 }

// INSTRUCTION: Encapsulate payload with MPLS label 24010 and Traffic Class 5 (EF).
FLOW mpls_lsp_forward(ler, lsr) {
    ler -> lsr MPLS 24010 EXP 5 BOS 1 MPLS_TTL 64 PAYLOAD "MPLS L3VPN Customer Frame"
}

// INSTRUCTION: Compile the MPLS label switching flow.
COMPILE {
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
HOST core_sw { IP 10.0.0.1 MAC 00:1c:73:00:00:01 }
HOST dist_sw { IP 10.0.0.2 MAC 00:1c:73:00:00:02 }

// INSTRUCTION: Transmit an STP root BPDU followed by bidirectional LLDP advertisements.
FLOW stp_and_lldp_discovery(core, dist) {
    core -> dist STP ROOT_ID "4096/00:1c:73:00:00:01" BRIDGE_ID "4096/00:1c:73:00:00:01" COST 0 MAX_AGE 20 HELLO_TIME 2 FORWARD_DELAY 15
    core -> dist LLDP CHASSIS_ID "core-sw-01.dc" PORT_ID "Ethernet1/1" TTL 120 SYSNAME "core-sw-01" SYSDESC "Arista EOS" WAIT 2ms
    core <- dist LLDP CHASSIS_ID "dist-sw-01.dc" PORT_ID "Ethernet49/1" TTL 120 SYSNAME "dist-sw-01" SYSDESC "Cisco NX-OS" WAIT 2ms
}

// INSTRUCTION: Compile the STP and LLDP control-plane flow.
COMPILE {
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
HOST node_a { IP 10.0.10.1 MAC 00:1b:21:01:02:03 }
HOST node_b { IP 10.0.10.2 MAC 00:1b:21:04:05:06 }

// INSTRUCTION: Synchronize LACP actor/partner state and run 802.1X EAPOL identity verification.
FLOW lacp_and_eapol_bringup(a, b) {
    a -> b LACP ACTOR_SYS 00:1b:21:01:02:03 ACTOR_KEY 10 ACTOR_PORT 1 ACTOR_STATE 0x3d PARTNER_SYS 00:1b:21:04:05:06 PARTNER_KEY 10 PARTNER_PORT 1 PARTNER_STATE 0x3d
    a -> b EAPOL VERSION 2 TYPE START WAIT 2ms
    a <- b EAPOL VERSION 2 TYPE EAP_PACKET EAP_CODE 1 EAP_ID 1 EAP_METHOD 1 WAIT 2ms
    a -> b EAPOL VERSION 2 TYPE EAP_PACKET EAP_CODE 2 EAP_ID 1 EAP_METHOD 1 IDENTITY "host/node-a.corp.example" WAIT 2ms
}

// INSTRUCTION: Compile the LACP and EAPOL port bring-up flow.
COMPILE {
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
HOST client_v4 { IP 10.0.0.10 }
HOST dns_v4    { IP 8.8.8.8 }
HOST client_v6 { IP 2001:db8::10 }
HOST dns_v6    { IP 2001:4860:4860::8888 }

// INSTRUCTION: Define a polymorphic ping flow that works over both IPv4 and IPv6.
FLOW dual_stack_ping(src, dst) {
    src -> dst ICMP ECHO_REQUEST ID 100 SEQ 1 TTL 64 PAYLOAD "polymorphic-ping"
    src <- dst ICMP ECHO_REPLY ID 100 SEQ 1 TTL 57 PAYLOAD "polymorphic-ping" WAIT 5ms
}

// INSTRUCTION: Compile the flow for IPv4 and IPv6 endpoint pairs.
COMPILE {
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
HOST host_v6   { IP 2001:db8::100 MAC 00:11:22:33:44:66 }
HOST router_v6 { IP 2001:db8::1   MAC aa:bb:cc:dd:ee:66 }

// INSTRUCTION: Execute ROUTER_SOLICIT, ROUTER_ADVERT, NEIGHBOR_SOLICIT, NEIGHBOR_ADVERT, and MLDv2 Report.
FLOW ipv6_ndp_and_mld(h, r) {
    h -> r NDP ROUTER_SOLICIT SLLA 00:11:22:33:44:66 TTL 255
    h <- r NDP ROUTER_ADVERT SLLA aa:bb:cc:dd:ee:66 ROUTER_LIFETIME 1800 TTL 255 WAIT 2ms
    h -> r NDP NEIGHBOR_SOLICIT TARGET 2001:db8::1 SLLA 00:11:22:33:44:66 TTL 255 WAIT 2ms
    h <- r NDP NEIGHBOR_ADVERT TARGET 2001:db8::1 TLLA aa:bb:cc:dd:ee:66 TTL 255 WAIT 2ms
    h -> r MLD REPORT VERSION 2 GROUP ff02::1:ff00:100 WAIT 2ms
}

// INSTRUCTION: Compile the IPv6 NDP and MLDv2 onboarding flow.
COMPILE {
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
HOST r1 { IP 10.0.0.1 }
HOST r2 { IP 10.0.0.2 }

// INSTRUCTION: Bring up BFD, OSPF Area 0, eBGP peering, and VRRPv3 virtual gateway redundancy.
FLOW routing_control_plane(a, b) {
    a -> b BFD STATE 3 MY_DISC 101 YOUR_DISC 202 MIN_TX 50000 MIN_RX 50000 MULT 3
    a -> b OSPF HELLO ROUTER_ID 1.1.1.1 AREA_ID 0 WAIT 2ms
    a -> b BGP OPEN ASN 65001 HOLDTIME 180 BGPID 1.1.1.1 WAIT 2ms
    a <- b BGP OPEN ASN 65002 HOLDTIME 180 BGPID 2.2.2.2 WAIT 2ms
    a -> b BGP KEEPALIVE WAIT 1ms
    a -> b BGP UPDATE ASN 65001 PREFIX "172.16.0.0/16" NEXTHOP 10.0.0.1 WAIT 2ms
    a -> b VRRP VRID 10 PRIORITY 200 VIP 10.0.0.254 WAIT 2ms
}

// INSTRUCTION: Compile the routing control-plane scenario.
COMPILE {
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
HOST gw1 { IP 198.51.100.1 }
HOST gw2 { IP 203.0.113.1 }

// INSTRUCTION: Transmit GRE, VXLAN, GENEVE, IKEv2/ESP/AH, and WireGuard frames.
FLOW overlay_and_vpn_showcase(a, b) {
    a -> b GRE GRE_KEY 100 SEQ 1 PAYLOAD "GRE Encapsulated Frame"
    a -> b VXLAN VNI 5000 PAYLOAD "VXLAN VNI 5000 Tenant Frame" WAIT 1ms
    a -> b GENEVE VNI 6000 PAYLOAD "GENEVE VNI 6000 Cloud Frame" WAIT 1ms
    a -> b IKEV2 SA_INIT INITIATOR_SPI 0x1122334455667788 RESPONDER_SPI 0 MSGID 0 WAIT 2ms
    a -> b ESP SPI 0xabcdef01 SEQ 1 PAYLOAD "IPsec ESP Ciphertext" WAIT 1ms
    a -> b AH SPI 0xabcdef02 SEQ 1 PAYLOAD "IPsec AH Authenticated Packet" WAIT 1ms
    a -> b WIREGUARD TYPE INITIATION SENDER 0x01020304 PAYLOAD "WG_NOISE_INIT" WAIT 1ms
    a -> b WIREGUARD TYPE DATA RECEIVER 0x01020304 COUNTER 1 PAYLOAD "WireGuard ChaCha20Poly1305" WAIT 1ms
}

// INSTRUCTION: Compile the overlay and VPN tunnel showcase.
COMPILE {
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
HOST client { IP 10.0.1.50 }
HOST server { IP 10.0.1.10 }

// INSTRUCTION: Execute TCP handshake, HTTP GET/200 exchange, and TCP FIN teardown.
FLOW web_healthcheck(c, s) {
    c -> s TCP SYN SRCPORT 52000 DSTPORT 80 MSS 1460 WSCALE 7 SACK_PERM
    c <- s TCP SYN ACK MSS 1460 WSCALE 7 SACK_PERM WAIT 1ms
    c -> s TCP ACK WAIT 1ms
    c -> s HTTP GET URI "/healthz" HOST_HDR "service.internal" WAIT 2ms
    c <- s HTTP RESPONSE STATUS 200 REASON "OK" CONTENT_TYPE "application/json" BODY "{\"ok\":true}" WAIT 2ms
    c -> s TCP FIN ACK WAIT 1ms
    c <- s TCP FIN ACK WAIT 1ms
    c -> s TCP ACK
}

// INSTRUCTION: Compile the stateful TCP and HTTP healthcheck flow.
COMPILE {
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
HOST amf_node { IP 10.50.0.1 }
HOST gnb_node { IP 10.50.0.2 }

// INSTRUCTION: Perform SCTP 4-way handshake and exchange NGAP signaling data.
FLOW sctp_ngap_signaling(a, b) {
    a -> b SCTP SRCPORT 38412 DSTPORT 38412 VTAG 0 CHUNK INIT
    a <- b SCTP SRCPORT 38412 DSTPORT 38412 VTAG 0x11223344 CHUNK INIT_ACK WAIT 1ms
    a -> b SCTP SRCPORT 38412 DSTPORT 38412 VTAG 0x11223344 CHUNK COOKIE_ECHO WAIT 1ms
    a <- b SCTP SRCPORT 38412 DSTPORT 38412 VTAG 0x55667788 CHUNK COOKIE_ACK WAIT 1ms
    a -> b SCTP SRCPORT 38412 DSTPORT 38412 VTAG 0x11223344 CHUNK DATA STREAM 1 SEQ 1 PPID 60 PAYLOAD "NGAP_InitialUEMessage" WAIT 2ms
    a <- b SCTP SRCPORT 38412 DSTPORT 38412 VTAG 0x55667788 CHUNK SACK SEQ 1 WAIT 1ms
}

// INSTRUCTION: Compile the SCTP signaling association flow.
COMPILE {
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
HOST nms    { IP 192.168.10.5 }
HOST router { IP 192.168.10.1 }

// INSTRUCTION: Poll sysDescr.0 over SNMPv3 authPriv (SHA256 + AES).
FLOW snmpv3_encrypted_poll(mgr, agt) {
    mgr -> agt SNMP3 GET USER "netadmin" ENGINEID "80001f88801122334455" ENGINEBOOTS 10 ENGINETIME 5000 AUTH SHA256 "MyAuthSecretKey99!" PRIV AES "MyPrivSecretKey99!" REQID 1 VARBIND 1.3.6.1.2.1.1.1.0 NULLVAL
    mgr <- agt SNMP3 RESPONSE USER "netadmin" ENGINEID "80001f88801122334455" ENGINEBOOTS 10 ENGINETIME 5001 AUTH SHA256 "MyAuthSecretKey99!" PRIV AES "MyPrivSecretKey99!" REQID 1 VARBIND 1.3.6.1.2.1.1.1.0 STRING "Linux core-router 6.8.0" WAIT 2ms
}

// INSTRUCTION: Compile the SNMPv3 authPriv polling flow.
COMPILE {
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
HOST scada_hmi { IP 192.168.100.10 }
HOST plc_node  { IP 192.168.100.50 }

// INSTRUCTION: Poll the PLC over Modbus TCP, DNP3, Siemens S7comm, and OPC UA.
FLOW industrial_ot_poll(hmi, plc) {
    hmi -> plc MODBUS FUNC "READ_HOLDING_REGISTERS" TXID 1 UNITID 1 ADDR 40001 COUNT 4
    hmi <- plc MODBUS FUNC "READ_HOLDING_REGISTERS" TXID 1 UNITID 1 COUNT 4 IS_RESPONSE WAIT 2ms
    hmi -> plc DNP3 FUNC "READ" SRC 1 DST 50 SEQ 1 GROUP 60 VARIATION 1 WAIT 2ms
    hmi <- plc DNP3 FUNC "RESPONSE" SRC 50 DST 1 SEQ 1 GROUP 30 VARIATION 1 WAIT 2ms
    hmi -> plc S7COMM ROSCTR "JOB" FUNC "READ_VAR" PDU_REF 10 AREA 0x84 DB_NUM 1 OFFSET 0 COUNT 4 WAIT 2ms
    hmi -> plc OPCUA MSG_TYPE "HEL" CHUNK_TYPE "F" ENDPOINT_URL "opc.tcp://192.168.100.50:4840" WAIT 2ms
    hmi <- plc OPCUA MSG_TYPE "ACK" CHUNK_TYPE "F" WAIT 2ms
    hmi -> plc OPCUA MSG_TYPE "MSG" CHUNK_TYPE "F" SECURE_CHANNEL_ID 1 TOKEN_ID 1 SEQ_NUM 1 REQID 1 NODE_ID "ns=2;s=BoilerTemp" WAIT 2ms
}

// INSTRUCTION: Compile the industrial OT polling scenario.
COMPILE {
    industrial_ot_poll(scada_hmi, plc_node)
}
```

---

## 5. Cross-References

- **[`docs/architecture_and_grammar.md`](./architecture_and_grammar.md)** — Complete EBNF/GBNF/Lark grammar rules and compiler architecture.
- **[`docs/topologies_and_dual_stack.md`](./topologies_and_dual_stack.md)** — Multi-host enterprise, cloud, 5G, and ICS topologies (`examples/topologies/`).
