# Layer 4 Transport Example Scenarios

[← All Examples](../README.md) • [Layer 4 Transport Guide](../../docs/05_l4_transports.md) • [Use-Case Cookbook](../../docs/02_use_cases.md)

This folder holds **100 `.frasm` scenarios** across all **3 Layer 4 transport protocols**: **TCP**, **UDP**, and **SCTP**. Every folder starts with a minimal 2-block `<proto>_default_frame.frasm` starter (`host` + `compile`, zero `flow` block) followed by 31+ realistic captures for firewall testing, session tracking, QoS, and telecom signaling.

Preview or compile any scenario from the repository root:

```console
$ frameassembly show examples/l4/tcp/tcp_default_frame.frasm
$ frameassembly examples/l4/tcp/tcp_firewall_acl_blocked_port_scan.frasm temp/fw_audit.pcap
```

## All 3 Layer 4 Transports

| Transport | Directory | IP Protocol | Wireshark Filter | Starter (2-Block) | Featured Scenarios | Count |
| :--- | :--- | :---: | :--- | :--- | :--- | :---: |
| **TCP** | [`tcp/`](tcp/) | `6` | `tcp` | [`tcp_default_frame.frasm`](tcp/tcp_default_frame.frasm) | [`tcp_3_way_handshake.frasm`](tcp/tcp_3_way_handshake.frasm), [`tcp_firewall_acl_blocked_port_scan.frasm`](tcp/tcp_firewall_acl_blocked_port_scan.frasm) | 34 |
| **UDP** | [`udp/`](udp/) | `17` | `udp` | [`udp_default_frame.frasm`](udp/udp_default_frame.frasm) | [`udp_dns_ntp_syslog_soc_baseline.frasm`](udp/udp_dns_ntp_syslog_soc_baseline.frasm), [`udp_dhcp_discover_offer_request_ack.frasm`](udp/udp_dhcp_discover_offer_request_ack.frasm) | 34 |
| **SCTP** | [`sctp/`](sctp/) | `132` | `sctp` | [`sctp_default_frame.frasm`](sctp/sctp_default_frame.frasm) | [`sctp_association_and_chunks.frasm`](sctp/sctp_association_and_chunks.frasm), [`sctp_5g_ngap_n2_interface_ipv6.frasm`](sctp/sctp_5g_ngap_n2_interface_ipv6.frasm) | 32 |

## Scenario Highlights by Use Case

### Firewall, Scan & Flag Verification (`tcp/`)

- [`tcp_default_frame.frasm`](tcp/tcp_default_frame.frasm) — Two-block TCP SYN starter (`12345 -> 80`) with automatic checksums.
- [`tcp_3_way_handshake.frasm`](tcp/tcp_3_way_handshake.frasm) — Complete `SYN -> SYN ACK -> ACK` session on HTTPS port 443.
- [`tcp_firewall_acl_blocked_port_scan.frasm`](tcp/tcp_firewall_acl_blocked_port_scan.frasm) — Mixed ACL test: permitted HTTPS handshake, Telnet `RST ACK`, dropped SSH probe, and ICMP code 13 reject on RDP.
- [`tcp_closed_port_rst_ack_rejection.frasm`](tcp/tcp_closed_port_rst_ack_rejection.frasm) — Closed service port returning immediate `RST ACK`.
- [`tcp_ack_firewall_rule_probe.frasm`](tcp/tcp_ack_firewall_rule_probe.frasm) — Unsolicited ACK sweep to separate stateful vs. stateless packet filters.
- [`tcp_fin_stealth_scan.frasm`](tcp/tcp_fin_stealth_scan.frasm) and [`tcp_all_eight_flags_kamikaze.frasm`](tcp/tcp_all_eight_flags_kamikaze.frasm) — Suricata/Zeek anomaly signatures and scan-detection test vectors.
- [`tcp_3_way_handshake_ipv6.frasm`](tcp/tcp_3_way_handshake_ipv6.frasm) and [`tcp_bidirectional_asymmetric_port_routing.frasm`](tcp/tcp_bidirectional_asymmetric_port_routing.frasm) — IPv6 handshakes and automatic reply-port swap behavior.

### Core Infrastructure, Control & Telemetry (`udp/`)

- [`udp_default_frame.frasm`](udp/udp_default_frame.frasm) — Two-block UDP datagram starter targeting port 80.
- [`udp_dns_ntp_syslog_soc_baseline.frasm`](udp/udp_dns_ntp_syslog_soc_baseline.frasm) — Compact SOC baseline combining DNS (`53`), NTP (`123`), and RFC 5424 Syslog (`514`).
- [`udp_dhcp_discover_offer_request_ack.frasm`](udp/udp_dhcp_discover_offer_request_ack.frasm) — Full DHCPv4 DORA sequence across ports `68/67`.
- [`udp_bfd_single_hop_and_echo.frasm`](udp/udp_bfd_single_hop_and_echo.frasm) — RFC 5881 BFD control (`3784`) and echo (`3785`) with TTL 255 GTSM checks.
- [`udp_capwap_wireless_ap_tunnel.frasm`](udp/udp_capwap_wireless_ap_tunnel.frasm) and [`udp_polymorphic_dual_stack_echo_loop.frasm`](udp/udp_polymorphic_dual_stack_echo_loop.frasm) — Wireless controller tunnels and shared IPv4/IPv6 echo pacing.

### Telecom & Multi-Stream Associations (`sctp/`)

- [`sctp_default_frame.frasm`](sctp/sctp_default_frame.frasm) — Two-block SCTP `INIT` starter with CRC32c checksum.
- [`sctp_association_and_chunks.frasm`](sctp/sctp_association_and_chunks.frasm) and [`sctp_abort_and_shutdown.frasm`](sctp/sctp_abort_and_shutdown.frasm) — 4-way `INIT`/`COOKIEECHO` setup, `DATA`/`SACK` exchange, and clean teardown.
- [`sctp_3gpp_s1ap_ue_context_release_command.frasm`](sctp/sctp_3gpp_s1ap_ue_context_release_command.frasm) — 4G LTE S1AP MME/eNodeB signaling (PPID `18`).
- [`sctp_5g_ngap_n2_interface_ipv6.frasm`](sctp/sctp_5g_ngap_n2_interface_ipv6.frasm), [`sctp_5g_n2_handover_preparation_multi_stream.frasm`](sctp/sctp_5g_n2_handover_preparation_multi_stream.frasm), and [`sctp_5g_xn_interface_direct_gnb_handover.frasm`](sctp/sctp_5g_xn_interface_direct_gnb_handover.frasm) — 5G NGAP (port `38412`, PPID `60`) and XnAP (port `38422`, PPID `61`) over IPv6.

## Notes on Automatic Sequence Numbers, Ports, and Timing

- **Automatic TCP tracking:** Sequence numbers advance automatically by TCP payload length across `->` and `<-`, and reply statements (`<-`) swap `srcport`/`dstport` automatically unless overridden. Raw `tcp` statements share connection state with TCP-based Layer 7 protocols (`http`, `tls`, `ssh`, `bgp`, `modbus`, etc.).
- **Checksums:** IPv4 header, TCP/UDP pseudo-header, and SCTP CRC32c checksums are computed automatically on every emitted frame.
- **Post-packet `wait`:** `wait 2ms` on a statement pauses 2ms *after* that frame before emitting the next frame (default gap is `10ms`).
