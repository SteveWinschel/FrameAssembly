## 2026-10-25T14:22:33Z
From: f0e4cf46-ddf0-4dfb-bd39-ca7c67c506fe (parent / orchestrator_2)

You are the Protocol RFC Matrix & QA Surveyor (teamwork_preview_spec_miner).
Your working directory is `/home/steve/frameassembly/.agents/teamwork/spec_miner_protocols/`.
Read `/home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md` (specifically section `## 2026-10-25T14:19:19Z`) and `/home/steve/frameassembly/.agents/teamwork/orchestrator_2/context.md`.

YOUR MISSION:
Exhaustively investigate and document the Protocol RFC Matrix and QA verification landscape:
1. Enumerate all 81 protocols across L2, L3, L4, and L7 implemented in FrameAssembly:
   - L2: ARP, VLAN, QINQ, LLDP, STP, LACP, EAPOL, MPLS
   - L3: ICMP, NDP, IGMP, MLD, GRE, VXLAN, GENEVE, IPSEC, ESP, AH, IKEV2, WIREGUARD, OSPF, BGP, RIP, VRRP, HSRP, PIM, BFD, OPENFLOW
   - L4: TCP, UDP, SCTP
   - L7: SNMP1, SNMP2, SNMP3, DNS, MDNS, DHCP, NTP, PTP, RADIUS, TACACS, SYSLOG, NETFLOW, IPFIX, SFLOW, HTTP, HTTP2, GRPC, WEBSOCKET, TLS, QUIC, TFTP, FTP, SSH, TELNET, WHOIS, SIP, RTP, RTSP, STUN, SSDP, SMTP, IMAP, POP3, KERBEROS, LDAP, SMB, NFS, REDIS, MEMCACHED, MYSQL, POSTGRES, MQTT, COAP, AMQP, MODBUS, BACNET, DNP3, S7COMM, ETHERNETIP, OPCUA
   - Map exact RFC numbers, default ports, wire structures, and header fields.
2. Investigate external dissector verification patterns for these 81 protocols:
   - Wireshark/`tshark` display filters and dissector validation
   - `tcpdump` / libpcap decode filters
   - `Suricata` protocol parsers & alerts
   - `Zeek` protocol analyzers
3. Investigate `/home/steve/frameassembly/tests/corpus_verification_tests.rs`:
   - Understand how it extracts and verifies ````frameassembly` and ````fasm` code blocks inside `.agents/skills/**/*.md`, `docs/*.md`, and `README.md`.
   - Identify any existing `.fasm` syntax errors or potential pitfalls in skill markdown blocks (e.g. invalid modifiers, `+5ms` prefixes, missing `HOST`/`FLOW`/`COMPILE` blocks) to guarantee 100% test pass.
4. Survey requirements for executable QA helper scripts (`scripts/*.sh`) across skills.

HARD CONSTRAINTS:
- You are read-only. Do NOT modify any file outside your directory `/home/steve/frameassembly/.agents/teamwork/spec_miner_protocols/`.
- Do NOT touch `src/`, `Cargo.toml`, or `Cargo.lock`.
- Deliver your comprehensive survey report to `/home/steve/frameassembly/.agents/teamwork/spec_miner_protocols/survey_report.md` and write a standard `handoff.md` in your directory.
- Use `send_message` to report your completion back to your caller (orchestrator_2).
