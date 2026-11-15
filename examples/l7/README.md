# Layer 7 Protocol Examples (All 50 Application Protocols)

[<- Main Examples Index](../README.md) • [Docs Index](../../docs/README.md) • [Use-Case Cookbook](../../docs/02_use_cases.md)

Every folder below contains a minimal 2-block `<proto>_default_frame.frasm` starter plus around 30 real-world `.frasm` scenarios (1,500+ Layer 7 files total). Preview any scenario with `frameassembly show <file.frasm>` or compile directly into a Wireshark-ready `.pcap`:

```console
$ frameassembly show examples/l7/snmp/snmpv3/snmp3_default_frame.frasm
$ frameassembly examples/l7/tls/tls_sni_inspection_check.frasm temp/tls_sni.pcap
```

## 1. SNMP Monitoring & Traps (`snmp1`, `snmp2`, `snmp3`)

Guide: [SNMPv1, v2c & Encrypted SNMPv3](../../docs/06_l7_snmp.md)

| Protocol | Starter File | Highlight Scenario | Default Port |
| :--- | :--- | :--- | :--- |
| **`snmp1`** | [`snmp1_default_frame.frasm`](snmp/snmpv1/snmp1_default_frame.frasm) | [`snmpv1_all_supported_v1_varbind_types.frasm`](snmp/snmpv1/snmpv1_all_supported_v1_varbind_types.frasm) | UDP `161` / `162` |
| **`snmp2`** | [`snmp2_default_frame.frasm`](snmp/snmpv2c/snmp2_default_frame.frasm) | [`snmp2_checkmk_zabbix_linkdown_trap.frasm`](snmp/snmpv2c/snmp2_checkmk_zabbix_linkdown_trap.frasm) | UDP `161` / `162` |
| **`snmp3`** | [`snmp3_default_frame.frasm`](snmp/snmpv3/snmp3_default_frame.frasm) | [`snmp3_authpriv_sha256_aes128_poll.frasm`](snmp/snmpv3/snmp3_authpriv_sha256_aes128_poll.frasm) | UDP `161` / `162` |

## 2. Infrastructure, Time, AAA & Flow Telemetry (11 Protocols)

Guide: [Infrastructure, Time, AAA & Telemetry](../../docs/07_l7_infra_and_telemetry.md)

| Protocol | Starter File | Highlight Scenario | Default Port |
| :--- | :--- | :--- | :--- |
| **`dhcp`** | [`dhcp_default_frame.frasm`](dhcp/dhcp_default_frame.frasm) | [`dhcp_branch_wan_mpls_relay_lease.frasm`](dhcp/dhcp_branch_wan_mpls_relay_lease.frasm) | UDP `68/67` (`546/547` v6) |
| **`dns`** | [`dns_default_frame.frasm`](dns/dns_default_frame.frasm) | [`dns_a_record_query_response.frasm`](dns/dns_a_record_query_response.frasm) | UDP / TCP `53` |
| **`ipfix`** | [`ipfix_default_frame.frasm`](ipfix/ipfix_default_frame.frasm) | [`ipfix_bgp_next_hop_peering_accounting.frasm`](ipfix/ipfix_bgp_next_hop_peering_accounting.frasm) | UDP `4739` |
| **`mdns`** | [`mdns_default_frame.frasm`](mdns/mdns_default_frame.frasm) | [`mdns_airplay_multicast_beacon.frasm`](mdns/mdns_airplay_multicast_beacon.frasm) | UDP `5353` |
| **`netflow`** | [`netflow_default_frame.frasm`](netflow/netflow_default_frame.frasm) | [`netflow_bgp_peering_transit_accounting.frasm`](netflow/netflow_bgp_peering_transit_accounting.frasm) | UDP `2055` |
| **`ntp`** | [`ntp_default_frame.frasm`](ntp/ntp_default_frame.frasm) | [`ntp_chrony_iburst_four_packet_startup.frasm`](ntp/ntp_chrony_iburst_four_packet_startup.frasm) | UDP `123` |
| **`ptp`** | [`ptp_default_frame.frasm`](ptp/ptp_default_frame.frasm) | [`ptp_complete_two_step_e2e_sync.frasm`](ptp/ptp_complete_two_step_e2e_sync.frasm) | UDP `319` / `320` |
| **`radius`** | [`radius_default_frame.frasm`](radius/radius_default_frame.frasm) | [`radius_access_challenge_mfa_otp.frasm`](radius/radius_access_challenge_mfa_otp.frasm) | UDP `1812` / `1813` |
| **`sflow`** | [`sflow_default_frame.frasm`](sflow/sflow_default_frame.frasm) | [`sflow_5g_upf_gtpu_user_plane_samples.frasm`](sflow/sflow_5g_upf_gtpu_user_plane_samples.frasm) | UDP `6343` |
| **`syslog`** | [`syslog_default_frame.frasm`](syslog/syslog_default_frame.frasm) | [`syslog_firewall_acl_deny_burst.frasm`](syslog/syslog_firewall_acl_deny_burst.frasm) | UDP / TCP `514` |
| **`tacacs`** | [`tacacs_default_frame.frasm`](tacacs/tacacs_default_frame.frasm) | [`tacacs_acct_rollback_config_change.frasm`](tacacs/tacacs_acct_rollback_config_change.frasm) | TCP `49` |

## 3. Web, Cloud, Transport Security, VoIP & Remote Access (16 Protocols)

Guide: [Web, Cloud, TLS, VoIP & Remote Access](../../docs/08_l7_web_and_cloud.md)

| Protocol | Starter File | Highlight Scenario | Default Port |
| :--- | :--- | :--- | :--- |
| **`ftp`** | [`ftp_default_frame.frasm`](ftp/ftp_default_frame.frasm) | [`ftp_auth_tls_explicit_upgrade.frasm`](ftp/ftp_auth_tls_explicit_upgrade.frasm) | TCP `21` |
| **`grpc`** | [`grpc_default_frame.frasm`](grpc/grpc_default_frame.frasm) | [`grpc_containerd_cri_runtime_pod_sandbox.frasm`](grpc/grpc_containerd_cri_runtime_pod_sandbox.frasm) | TCP `50051` |
| **`http`** | [`http_default_frame.frasm`](http/http_default_frame.frasm) | [`http_auth_401_unauthorized_bearer.frasm`](http/http_auth_401_unauthorized_bearer.frasm) | TCP `80` |
| **`http2`** | [`http2_default_frame.frasm`](http2/http2_default_frame.frasm) | [`http2_5g_n12_ausf_authentication_sba.frasm`](http2/http2_5g_n12_ausf_authentication_sba.frasm) | TCP `443` |
| **`quic`** | [`quic_default_frame.frasm`](quic/quic_default_frame.frasm) | [`quic_version_2_rfc9369_handshake.frasm`](quic/quic_version_2_rfc9369_handshake.frasm) | UDP `443` |
| **`rtp`** | [`rtp_default_frame.frasm`](rtp/rtp_default_frame.frasm) | [`rtp_opus_dynamic_payload_type_111.frasm`](rtp/rtp_opus_dynamic_payload_type_111.frasm) | UDP `5004` |
| **`rtsp`** | [`rtsp_default_frame.frasm`](rtsp/rtsp_default_frame.frasm) | [`rtsp_cctv_vlan_custom_port_8554.frasm`](rtsp/rtsp_cctv_vlan_custom_port_8554.frasm) | TCP `554` |
| **`sip`** | [`sip_default_frame.frasm`](sip/sip_default_frame.frasm) | [`sip_200_ok_sdp_answer.frasm`](sip/sip_200_ok_sdp_answer.frasm) | UDP / TCP `5060` |
| **`ssdp`** | [`ssdp_default_frame.frasm`](ssdp/ssdp_default_frame.frasm) | [`ssdp_msearch_discover_devices.frasm`](ssdp/ssdp_msearch_discover_devices.frasm) | UDP `1900` |
| **`ssh`** | [`ssh_default_frame.frasm`](ssh/ssh_default_frame.frasm) | [`ssh_ansible_automation_bastion_jump.frasm`](ssh/ssh_ansible_automation_bastion_jump.frasm) | TCP `22` |
| **`stun`** | [`stun_default_frame.frasm`](stun/stun_default_frame.frasm) | [`stun_udp_rto_retransmission_recovery.frasm`](stun/stun_udp_rto_retransmission_recovery.frasm) | UDP `3478` |
| **`telnet`** | [`telnet_default_frame.frasm`](telnet/telnet_default_frame.frasm) | [`telnet_login_failure_lockout_loop.frasm`](telnet/telnet_login_failure_lockout_loop.frasm) | TCP `23` |
| **`tftp`** | [`tftp_default_frame.frasm`](tftp/tftp_default_frame.frasm) | [`tftp_bios_spi_flash_recovery_loop.frasm`](tftp/tftp_bios_spi_flash_recovery_loop.frasm) | UDP `69` |
| **`tls`** | [`tls_default_frame.frasm`](tls/tls_default_frame.frasm) | [`tls_client_hello_sni_alpn.frasm`](tls/tls_client_hello_sni_alpn.frasm) | TCP `443` |
| **`websocket`** | [`websocket_default_frame.frasm`](websocket/websocket_default_frame.frasm) | [`websocket_bidirectional_close_handshake.frasm`](websocket/websocket_bidirectional_close_handshake.frasm) | TCP `80` |
| **`whois`** | [`whois_default_frame.frasm`](whois/whois_default_frame.frasm) | [`whois_afnic_fr_domain_security_audit.frasm`](whois/whois_afnic_fr_domain_security_audit.frasm) | TCP `43` |

## 4. Mail, Identity, Storage, Databases & Message Brokers (14 Protocols)

Guide: [Mail, Identity, Storage, Databases & Brokers](../../docs/09_l7_mail_auth_storage_db.md)

| Protocol | Starter File | Highlight Scenario | Default Port |
| :--- | :--- | :--- | :--- |
| **`amqp`** | [`amqp_default_frame.frasm`](amqp/amqp_default_frame.frasm) | [`amqp_basic_deliver_consumer.frasm`](amqp/amqp_basic_deliver_consumer.frasm) | TCP `5672` |
| **`coap`** | [`coap_default_frame.frasm`](coap/coap_default_frame.frasm) | [`coap_blockwise_firmware_chunk_transfer.frasm`](coap/coap_blockwise_firmware_chunk_transfer.frasm) | UDP `5683` |
| **`imap`** | [`imap_default_frame.frasm`](imap/imap_default_frame.frasm) | [`imap_append_draft_and_copy.frasm`](imap/imap_append_draft_and_copy.frasm) | TCP `143` |
| **`kerberos`** | [`kerberos_default_frame.frasm`](kerberos/kerberos_default_frame.frasm) | [`kerberos_aes256_strong_crypto_exchange.frasm`](kerberos/kerberos_aes256_strong_crypto_exchange.frasm) | UDP / TCP `88` |
| **`ldap`** | [`ldap_default_frame.frasm`](ldap/ldap_default_frame.frasm) | [`ldap_ad_netlogon_rootdse_ping.frasm`](ldap/ldap_ad_netlogon_rootdse_ping.frasm) | TCP `389` |
| **`memcached`** | [`memcached_default_frame.frasm`](memcached/memcached_default_frame.frasm) | [`memcached_admin_version_and_flush_all.frasm`](memcached/memcached_admin_version_and_flush_all.frasm) | TCP / UDP `11211` |
| **`mqtt`** | [`mqtt_default_frame.frasm`](mqtt/mqtt_default_frame.frasm) | [`mqtt_broker_bridge_qinq_mpls.frasm`](mqtt/mqtt_broker_bridge_qinq_mpls.frasm) | TCP `1883` |
| **`mysql`** | [`mysql_default_frame.frasm`](mysql/mysql_default_frame.frasm) | [`mysql_connection_pool_keepalive.frasm`](mysql/mysql_connection_pool_keepalive.frasm) | TCP `3306` |
| **`nfs`** | [`nfs_default_frame.frasm`](nfs/nfs_default_frame.frasm) | [`nfs_compound_getattr.frasm`](nfs/nfs_compound_getattr.frasm) | TCP / UDP `2049` |
| **`pop3`** | [`pop3_default_frame.frasm`](pop3/pop3_default_frame.frasm) | [`pop3_apop_challenge_authentication.frasm`](pop3/pop3_apop_challenge_authentication.frasm) | TCP `110` |
| **`postgres`** | [`postgres_default_frame.frasm`](postgres/postgres_default_frame.frasm) | [`postgres_acid_transaction_commit.frasm`](postgres/postgres_acid_transaction_commit.frasm) | TCP `5432` |
| **`redis`** | [`redis_default_frame.frasm`](redis/redis_default_frame.frasm) | [`redis_bgsave_info_persistence_check.frasm`](redis/redis_bgsave_info_persistence_check.frasm) | TCP `6379` |
| **`smb`** | [`smb_default_frame.frasm`](smb/smb_default_frame.frasm) | [`smb2_file_sharing.frasm`](smb/smb2_file_sharing.frasm) | TCP `445` |
| **`smtp`** | [`smtp_default_frame.frasm`](smtp/smtp_default_frame.frasm) | [`smtp_mail_transaction_rfc5321.frasm`](smtp/smtp_mail_transaction_rfc5321.frasm) | TCP `25` |

## 5. Industrial Control Systems & SCADA/OT (6 Protocols)

Guide: [Industrial Control Systems & SCADA/OT](../../docs/10_l7_industrial_ot.md)

| Protocol | Starter File | Highlight Scenario | Default Port |
| :--- | :--- | :--- | :--- |
| **`bacnet`** | [`bacnet_default_frame.frasm`](bacnet/bacnet_default_frame.frasm) | [`bacnet_accumulator_pulse_water_meter.frasm`](bacnet/bacnet_accumulator_pulse_water_meter.frasm) | UDP `47808` |
| **`dnp3`** | [`dnp3_default_frame.frasm`](dnp3/dnp3_default_frame.frasm) | [`dnp3_analog_output_select_before_operate_group41.frasm`](dnp3/dnp3_analog_output_select_before_operate_group41.frasm) | TCP / UDP `20000` |
| **`ethernetip`** | [`ethernetip_default_frame.frasm`](ethernetip/ethernetip_default_frame.frasm) | [`ethernetip_cip_connection_manager.frasm`](ethernetip/ethernetip_cip_connection_manager.frasm) | TCP / UDP `44818` |
| **`modbus`** | [`modbus_default_frame.frasm`](modbus/modbus_default_frame.frasm) | [`industrial_modbus_tcp_udp.frasm`](modbus/industrial_modbus_tcp_udp.frasm) | TCP / UDP `502` |
| **`opcua`** | [`opcua_default_frame.frasm`](opcua/opcua_default_frame.frasm) | [`industrial_opcua_binary_protocol.frasm`](opcua/industrial_opcua_binary_protocol.frasm) | TCP `4840` |
| **`s7comm`** | [`s7comm_default_frame.frasm`](s7comm/s7comm_default_frame.frasm) | [`industrial_s7comm_plc_read_write.frasm`](s7comm/industrial_s7comm_plc_read_write.frasm) | TCP `102` |
