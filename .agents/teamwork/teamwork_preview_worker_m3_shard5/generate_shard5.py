#!/usr/bin/env python3
"""
Corpus expansion generator for Shard 5:
IPFIX, Kerberos, LDAP, mDNS, Memcached, Modbus, MQTT, MySQL, NetFlow, NFS, NTP (12 files each = 132 files).
"""

import os
import subprocess
import sys

FILES = {}

# ==============================================================================
# 1. IPFIX (12 files)
# ==============================================================================
FILES["examples/l7/ipfix/ipfix_bidirectional_biflow_telemetry.fasm"] = """// PROMPT: IPFIX bidirectional biflow telemetry reporting TCP payload metrics between core routers.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, WAIT, ms, COMPILE

// INSTRUCTION: Define core router ingress interface.
HOST core_ingress { IP 10.150.1.1 }

// INSTRUCTION: Define centralized IPFIX collector node.
HOST ipfix_collector { IP 10.150.10.50 }

// INSTRUCTION: Define bidirectional flow export metrics.
FLOW biflow_telemetry(ing, col) {
    ing -> col IPFIX DOMAIN_ID 501 SRCIP 172.20.10.14 DSTIP 172.20.20.88 SRCPORT 443 DSTPORT 51234 PROTO 6 PACKETS 320 OCTETS 450200 WAIT 10ms
    ing -> col IPFIX DOMAIN_ID 501 SRCIP 172.20.20.88 DSTIP 172.20.10.14 SRCPORT 51234 DSTPORT 443 PROTO 6 PACKETS 410 OCTETS 52400
}

// INSTRUCTION: Compile biflow telemetry export scenario.
COMPILE {
    biflow_telemetry(core_ingress, ipfix_collector)
}
"""

FILES["examples/l7/ipfix/ipfix_mpls_vpn_pe_exporter.fasm"] = """// PROMPT: IPFIX flow exporter running on MPLS PE router with traffic class marking.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, MPLS, COMPILE

// INSTRUCTION: Define MPLS provider edge router exporter.
HOST pe_exporter { IP 192.168.210.1 }

// INSTRUCTION: Define carrier analytics collector.
HOST carrier_collector { IP 192.168.210.254 }

// INSTRUCTION: Define MPLS encapsulated IPFIX export flow.
FLOW pe_ipfix_flow(pe, col) {
    pe -> col IPFIX DOMAIN_ID 1002 SRCIP 10.80.4.1 DSTIP 10.80.5.2 PROTO 6 PACKETS 1420 OCTETS 1845000 MPLS 2048
}

// INSTRUCTION: Compile MPLS PE exporter scenario.
COMPILE {
    pe_ipfix_flow(pe_exporter, carrier_collector)
}
"""

FILES["examples/l7/ipfix/ipfix_vlan_datacenter_collector.fasm"] = """// PROMPT: IPFIX telemetry collection over 802.1Q tagged datacenter monitoring VLAN.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define datacenter spine switch exporter.
HOST spine_switch { IP 10.240.0.1 }

// INSTRUCTION: Define network operations collector on monitoring VLAN 400.
HOST noc_collector { IP 10.240.0.100 }

// INSTRUCTION: Define tagged VLAN telemetry export flow.
FLOW vlan_ipfix_flow(sw, noc) {
    sw -> noc IPFIX DOMAIN_ID 4001 SRCIP 10.100.1.50 DSTIP 10.200.2.60 PROTO 17 PACKETS 85 OCTETS 12400 VLAN 400 PCP 4 DEI 0
}

// INSTRUCTION: Compile VLAN telemetry scenario.
COMPILE {
    vlan_ipfix_flow(spine_switch, noc_collector)
}
"""

FILES["examples/l7/ipfix/ipfix_observation_domain_aggregation.fasm"] = """// PROMPT: Multi-domain IPFIX aggregation exporting telemetry from access and aggregation domains.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, WAIT, ms, COMPILE

// INSTRUCTION: Define multi-tenant border router.
HOST border_router { IP 172.31.1.1 }

// INSTRUCTION: Define corporate flow collector.
HOST corp_collector { IP 172.31.2.20 }

// INSTRUCTION: Define multi-domain telemetry export flow.
FLOW domain_aggregation_flow(rtr, col) {
    rtr -> col IPFIX DOMAIN_ID 10 SRCIP 192.168.1.10 DSTIP 198.51.100.5 PROTO 6 PACKETS 50 OCTETS 64000 WAIT 5ms
    rtr -> col IPFIX DOMAIN_ID 20 SRCIP 192.168.2.20 DSTIP 203.0.113.8 PROTO 17 PACKETS 12 OCTETS 1440
}

// INSTRUCTION: Compile domain aggregation export scenario.
COMPILE {
    domain_aggregation_flow(border_router, corp_collector)
}
"""

FILES["examples/l7/ipfix/ipfix_periodic_export_burst_loop.fasm"] = """// PROMPT: Periodic IPFIX flow export burst executed in compile loop simulating telemetry timer.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define edge telemetry probe.
HOST edge_probe { IP 192.168.75.10 }

// INSTRUCTION: Define central flow listener.
HOST flow_listener { IP 192.168.75.1 }

// INSTRUCTION: Define periodic IPFIX export burst flow.
FLOW ipfix_burst_flow(probe, srv) {
    probe -> srv IPFIX DOMAIN_ID 99 SRCIP 10.0.12.3 DSTIP 10.0.14.5 SRCPORT 80 DSTPORT 49152 PROTO 6 PACKETS 15 OCTETS 2140 WAIT 25ms
}

// INSTRUCTION: Compile periodic IPFIX export burst in loop.
COMPILE {
    LOOP 3 {
        ipfix_burst_flow(edge_probe, flow_listener)
    }
}
"""

FILES["examples/l7/ipfix/ipfix_ipv6_underlay_multicast_metrics.fasm"] = """// PROMPT: IPFIX flow records exported over IPv6 transport reporting streaming multicast metrics.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define IPv6 streaming video distribution router.
HOST video_headend { IP 2001:db8:feed::1 }

// INSTRUCTION: Define IPv6 telemetry collector node.
HOST v6_collector { IP 2001:db8:feed::250 }

// INSTRUCTION: Define IPv6 IPFIX export flow.
FLOW ipfix_multicast_metrics(vhead, col) {
    vhead -> col IPFIX DOMAIN_ID 601 SRCIP 198.51.100.10 DSTIP 233.252.0.1 PROTO 17 PACKETS 98500 OCTETS 128400000
}

// INSTRUCTION: Compile IPv6 multicast telemetry scenario.
COMPILE {
    ipfix_multicast_metrics(video_headend, v6_collector)
}
"""

FILES["examples/l7/ipfix/ipfix_dscp_marked_voice_telemetry.fasm"] = """// PROMPT: Expedited forwarding DSCP marked IPFIX export packets for VoIP telemetry.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, DSCP, ECN, COMPILE

// INSTRUCTION: Define VoIP gateway exporter.
HOST voip_gw { IP 10.45.1.1 }

// INSTRUCTION: Define QoS monitoring collector.
HOST qos_analyzer { IP 10.45.1.100 }

// INSTRUCTION: Define DSCP prioritized IPFIX export flow.
FLOW voip_ipfix_export(gw, col) {
    gw -> col IPFIX DOMAIN_ID 333 SRCIP 10.45.10.15 DSTIP 10.45.20.25 SRCPORT 5060 DSTPORT 5060 PROTO 17 PACKETS 120 OCTETS 24000 DSCP 46 ECN 1
}

// INSTRUCTION: Compile DSCP voice telemetry scenario.
COMPILE {
    voip_ipfix_export(voip_gw, qos_analyzer)
}
"""

FILES["examples/l7/ipfix/ipfix_custom_udp_collector_port.fasm"] = """// PROMPT: IPFIX telemetry flow targeted at custom UDP collector port 4739 with source port specification.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define campus aggregation router.
HOST campus_agg { IP 172.18.0.1 }

// INSTRUCTION: Define custom port telemetry server.
HOST custom_collector { IP 172.18.0.250 }

// INSTRUCTION: Define IPFIX export with port details.
FLOW custom_port_ipfix(agg, col) {
    agg -> col IPFIX DOMAIN_ID 7701 SRCIP 10.10.1.1 DSTIP 10.20.1.1 SRCPORT 8080 DSTPORT 58200 PROTO 6 PACKETS 64 OCTETS 8192
}

// INSTRUCTION: Compile custom port IPFIX scenario.
COMPILE {
    custom_port_ipfix(campus_agg, custom_collector)
}
"""

FILES["examples/l7/ipfix/ipfix_sampled_enterprise_gateway.fasm"] = """// PROMPT: 1-in-1000 sampled IPFIX export from enterprise edge gateway reporting egress stats.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define enterprise Internet edge firewall.
HOST edge_firewall { IP 198.51.100.1 }

// INSTRUCTION: Define security information and event collector.
HOST siem_collector { IP 198.51.100.50 }

// INSTRUCTION: Define sampled egress IPFIX export flow.
FLOW sampled_egress_flow(fw, siem) {
    fw -> siem IPFIX DOMAIN_ID 1000 SRCIP 10.1.50.120 DSTIP 198.51.100.254 PROTO 6 PACKETS 1000 OCTETS 1420000
}

// INSTRUCTION: Compile enterprise sampled export scenario.
COMPILE {
    sampled_egress_flow(edge_firewall, siem_collector)
}
"""

FILES["examples/l7/ipfix/ipfix_carrier_qinq_flow_reporting.fasm"] = """// PROMPT: Carrier Ethernet QinQ stacked VLAN underlay transporting IPFIX flow datagrams.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, VLAN, COMPILE

// INSTRUCTION: Define broadband network gateway exporter.
HOST bng_router { IP 100.64.1.1 }

// INSTRUCTION: Define carrier wholesale telemetry collector.
HOST carrier_noc { IP 100.64.1.200 }

// INSTRUCTION: Define QinQ encapsulated IPFIX export flow.
FLOW qinq_ipfix_stream(bng, noc) {
    bng -> noc IPFIX DOMAIN_ID 8000 SRCIP 100.64.10.5 DSTIP 100.64.20.9 PROTO 17 PACKETS 450 OCTETS 57600 VLAN 100
}

// INSTRUCTION: Compile carrier QinQ flow export scenario.
COMPILE {
    qinq_ipfix_stream(bng_router, carrier_noc)
}
"""

FILES["examples/l7/ipfix/ipfix_dns_resolver_traffic_export.fasm"] = """// PROMPT: IPFIX export datagram capturing recursive DNS resolver UDP port 53 traffic volumes.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define caching DNS resolver exporter.
HOST dns_cache_rtr { IP 192.0.2.53 }

// INSTRUCTION: Define DNS security telemetry analytics engine.
HOST dns_analytics { IP 192.0.2.200 }

// INSTRUCTION: Define DNS volume export flow.
FLOW dns_ipfix_flow(rtr, ana) {
    rtr -> ana IPFIX DOMAIN_ID 5353 SRCIP 10.2.1.15 DSTIP 192.0.2.53 SRCPORT 61240 DSTPORT 53 PROTO 17 PACKETS 24 OCTETS 1920
}

// INSTRUCTION: Compile DNS telemetry export scenario.
COMPILE {
    dns_ipfix_flow(dns_cache_rtr, dns_analytics)
}
"""

FILES["examples/l7/ipfix/ipfix_syn_flood_security_monitoring.fasm"] = """// PROMPT: High packet volume IPFIX security export recording detected TCP SYN flood anomaly.
// TOKENS: HOST, IP, FLOW, ->, IPFIX, DOMAIN_ID, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define DDoS mitigation appliance.
HOST ddos_scrubber { IP 198.18.0.1 }

// INSTRUCTION: Define central security operations center.
HOST soc_collector { IP 198.18.0.254 }

// INSTRUCTION: Define SYN flood anomaly IPFIX report flow.
FLOW syn_flood_report(scrub, soc) {
    scrub -> soc IPFIX DOMAIN_ID 9999 SRCIP 203.0.113.77 DSTIP 198.18.10.1 SRCPORT 45123 DSTPORT 80 PROTO 6 PACKETS 50000 OCTETS 2000000
}

// INSTRUCTION: Compile SYN flood security export scenario.
COMPILE {
    syn_flood_report(ddos_scrubber, soc_collector)
}
"""


# ==============================================================================
# 2. Kerberos (12 files)
# ==============================================================================
FILES["examples/l7/kerberos/kerberos_as_rep_ticket_granting_ticket.fasm"] = """// PROMPT: Kerberos AS-REP reply from KDC returning encrypted Ticket Granting Ticket to client.
// TOKENS: HOST, IP, FLOW, <-, KERBEROS, AS_REP, REALM, CNAME, ETYPE, COMPILE

// INSTRUCTION: Define authenticating enterprise workstation.
HOST corp_workstation { IP 10.20.1.80 }

// INSTRUCTION: Define primary Key Distribution Center (KDC).
HOST central_kdc { IP 10.20.1.5 }

// INSTRUCTION: Define AS-REP ticket issuance flow.
FLOW krb_as_rep_flow(w, kdc) {
    w <- kdc KERBEROS AS_REP REALM "ENTERPRISE.CORP" CNAME "jdoe" ETYPE 18
}

// INSTRUCTION: Compile Kerberos AS-REP scenario.
COMPILE {
    krb_as_rep_flow(corp_workstation, central_kdc)
}
"""

FILES["examples/l7/kerberos/kerberos_tgs_rep_service_ticket_grant.fasm"] = """// PROMPT: Kerberos TGS-REP response from KDC delivering service ticket for application server.
// TOKENS: HOST, IP, FLOW, <-, KERBEROS, TGS_REP, REALM, SNAME, ETYPE, COMPILE

// INSTRUCTION: Define application client workstation.
HOST app_client { IP 172.16.8.50 }

// INSTRUCTION: Define Key Distribution Center server.
HOST kdc_server { IP 172.16.8.1 }

// INSTRUCTION: Define TGS-REP service ticket delivery flow.
FLOW krb_tgs_rep_flow(c, kdc) {
    c <- kdc KERBEROS TGS_REP REALM "SERVICES.LOCAL" SNAME "http/portal.services.local" ETYPE 18
}

// INSTRUCTION: Compile Kerberos TGS-REP scenario.
COMPILE {
    krb_tgs_rep_flow(app_client, kdc_server)
}
"""

FILES["examples/l7/kerberos/kerberos_error_preauth_required.fasm"] = """// PROMPT: Kerberos KRB-ERROR response signaling pre-authentication required before ticket issuance.
// TOKENS: HOST, IP, FLOW, <-, KERBEROS, KRB_ERROR, REALM, SNAME, COMPILE

// INSTRUCTION: Define unauthenticated client host.
HOST unauth_client { IP 192.168.100.12 }

// INSTRUCTION: Define enterprise KDC authenticator.
HOST auth_kdc { IP 192.168.100.1 }

// INSTRUCTION: Define KRB-ERROR preauth notification flow.
FLOW krb_error_preauth(c, kdc) {
    c <- kdc KERBEROS KRB_ERROR REALM "ACME.ORG" SNAME "krbtgt/ACME.ORG"
}

// INSTRUCTION: Compile KRB-ERROR scenario.
COMPILE {
    krb_error_preauth(unauth_client, auth_kdc)
}
"""

FILES["examples/l7/kerberos/kerberos_aes256_strong_crypto_exchange.fasm"] = """// PROMPT: Kerberos AS-REQ ticket request negotiating AES256-CTS-HMAC-SHA1-96 encryption type 18.
// TOKENS: HOST, IP, FLOW, ->, KERBEROS, AS_REQ, REALM, CNAME, ETYPE, COMPILE

// INSTRUCTION: Define secure banking workstation.
HOST finance_pc { IP 10.88.2.14 }

// INSTRUCTION: Define security hardened domain controller.
HOST secure_dc { IP 10.88.2.1 }

// INSTRUCTION: Define AES256 ticket request flow.
FLOW krb_aes_req_flow(pc, dc) {
    pc -> dc KERBEROS AS_REQ REALM "BANKING.INTERNAL" CNAME "auditor" ETYPE 18
}

// INSTRUCTION: Compile AES256 crypto exchange scenario.
COMPILE {
    krb_aes_req_flow(finance_pc, secure_dc)
}
"""

FILES["examples/l7/kerberos/kerberos_legacy_rc4_compatibility.fasm"] = """// PROMPT: Kerberos AS-REQ ticket request with legacy RC4-HMAC encryption type 23 for backward compatibility.
// TOKENS: HOST, IP, FLOW, ->, KERBEROS, AS_REQ, REALM, CNAME, ETYPE, COMPILE

// INSTRUCTION: Define legacy terminal client.
HOST legacy_terminal { IP 192.168.4.99 }

// INSTRUCTION: Define Active Directory domain controller.
HOST ad_controller { IP 192.168.4.10 }

// INSTRUCTION: Define RC4-HMAC legacy ticket request flow.
FLOW krb_rc4_req_flow(term, dc) {
    term -> dc KERBEROS AS_REQ REALM "LEGACY.CORP" CNAME "scanner_svc" ETYPE 23
}

// INSTRUCTION: Compile legacy RC4 compatibility scenario.
COMPILE {
    krb_rc4_req_flow(legacy_terminal, ad_controller)
}
"""

FILES["examples/l7/kerberos/kerberos_ipv6_kdc_authentication_stream.fasm"] = """// PROMPT: Full Kerberos authentication exchange AS-REQ and AS-REP across IPv6 domain controller underlay.
// TOKENS: HOST, IP, FLOW, ->, <-, KERBEROS, AS_REQ, AS_REP, REALM, CNAME, ETYPE, WAIT, ms, COMPILE

// INSTRUCTION: Define IPv6 enterprise client workstation.
HOST v6_client { IP 2001:db8:acad::15 }

// INSTRUCTION: Define IPv6 Key Distribution Center server.
HOST v6_kdc { IP 2001:db8:acad::1 }

// INSTRUCTION: Define full IPv6 Kerberos AS exchange flow.
FLOW krb_v6_exchange(c, kdc) {
    c -> kdc KERBEROS AS_REQ REALM "IPV6.ACADEMY" CNAME "student_lab" ETYPE 18 WAIT 15ms
    c <- kdc KERBEROS AS_REP REALM "IPV6.ACADEMY" CNAME "student_lab" ETYPE 18
}

// INSTRUCTION: Compile IPv6 Kerberos exchange scenario.
COMPILE {
    krb_v6_exchange(v6_client, v6_kdc)
}
"""

FILES["examples/l7/kerberos/kerberos_vlan_segmented_identity_realm.fasm"] = """// PROMPT: Kerberos authentication traffic isolated on 802.1Q tagged security management VLAN.
// TOKENS: HOST, IP, FLOW, ->, KERBEROS, AS_REQ, REALM, CNAME, ETYPE, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define identity management bastion host.
HOST bastion_host { IP 10.99.1.5 }

// INSTRUCTION: Define authentication realm controller.
HOST realm_controller { IP 10.99.1.20 }

// INSTRUCTION: Define VLAN tagged authentication flow.
FLOW krb_vlan_auth(bas, ctl) {
    bas -> ctl KERBEROS AS_REQ REALM "MGMT.ZONE" CNAME "admin_sec" ETYPE 18 VLAN 99 PCP 6 DEI 0
}

// INSTRUCTION: Compile VLAN segmented identity scenario.
COMPILE {
    krb_vlan_auth(bastion_host, realm_controller)
}
"""

FILES["examples/l7/kerberos/kerberos_cross_realm_trust_referral.fasm"] = """// PROMPT: Kerberos TGS-REQ cross-realm trust referral requesting ticket from foreign partner realm.
// TOKENS: HOST, IP, FLOW, ->, KERBEROS, TGS_REQ, REALM, SNAME, ETYPE, COMPILE

// INSTRUCTION: Define local domain member server.
HOST member_server { IP 172.24.1.10 }

// INSTRUCTION: Define local Kerberos KDC proxy.
HOST local_kdc { IP 172.24.1.1 }

// INSTRUCTION: Define cross-realm trust ticket request flow.
FLOW cross_realm_flow(srv, kdc) {
    srv -> kdc KERBEROS TGS_REQ REALM "PARTNER.EXT" SNAME "krbtgt/PARTNER.EXT" ETYPE 18
}

// INSTRUCTION: Compile cross-realm trust scenario.
COMPILE {
    cross_realm_flow(member_server, local_kdc)
}
"""

FILES["examples/l7/kerberos/kerberos_cifs_file_service_ticket.fasm"] = """// PROMPT: Kerberos TGS-REQ service ticket request for enterprise CIFS/SMB storage cluster.
// TOKENS: HOST, IP, FLOW, ->, KERBEROS, TGS_REQ, REALM, SNAME, ETYPE, COMPILE

// INSTRUCTION: Define file transfer client workstation.
HOST storage_client { IP 10.50.2.100 }

// INSTRUCTION: Define enterprise KDC server.
HOST file_kdc { IP 10.50.2.1 }

// INSTRUCTION: Define CIFS ticket acquisition flow.
FLOW cifs_ticket_flow(cli, kdc) {
    cli -> kdc KERBEROS TGS_REQ REALM "STORAGE.CORP" SNAME "cifs/nas01.storage.corp" ETYPE 18
}

// INSTRUCTION: Compile CIFS file service ticket scenario.
COMPILE {
    cifs_ticket_flow(storage_client, file_kdc)
}
"""

FILES["examples/l7/kerberos/kerberos_http_spnego_web_service.fasm"] = """// PROMPT: Kerberos SPNEGO ticket request for intranet web application single sign-on.
// TOKENS: HOST, IP, FLOW, ->, KERBEROS, TGS_REQ, REALM, SNAME, ETYPE, COMPILE

// INSTRUCTION: Define web browser workstation.
HOST web_workstation { IP 192.168.12.45 }

// INSTRUCTION: Define corporate authentication server.
HOST auth_server { IP 192.168.12.1 }

// INSTRUCTION: Define SPNEGO HTTP service ticket request flow.
FLOW spnego_req_flow(w, a) {
    w -> a KERBEROS TGS_REQ REALM "INTRANET.NET" SNAME "HTTP/wiki.intranet.net" ETYPE 18
}

// INSTRUCTION: Compile SPNEGO web service ticket scenario.
COMPILE {
    spnego_req_flow(web_workstation, auth_server)
}
"""

FILES["examples/l7/kerberos/kerberos_tcp_stream_authentication.fasm"] = """// PROMPT: Kerberos authentication over TCP port 88 handling large ticket structures.
// TOKENS: HOST, IP, FLOW, ->, <-, TCP, SYN, ACK, DSTPORT, KERBEROS, AS_REQ, AS_REP, REALM, CNAME, ETYPE, WAIT, ms, COMPILE

// INSTRUCTION: Define directory client machine.
HOST dir_client { IP 10.10.5.25 }

// INSTRUCTION: Define domain controller port 88 listener.
HOST kdc_tcp_node { IP 10.10.5.1 }

// INSTRUCTION: Define TCP handshake and Kerberos AS exchange flow.
FLOW krb_tcp_stream(c, s) {
    c -> s TCP SYN DSTPORT 88
    c <- s TCP SYN ACK
    c -> s TCP ACK WAIT 2ms
    c -> s KERBEROS AS_REQ REALM "GLOBAL.CORP" CNAME "service_admin" ETYPE 18 WAIT 10ms
    c <- s KERBEROS AS_REP REALM "GLOBAL.CORP" CNAME "service_admin" ETYPE 18
}

// INSTRUCTION: Compile TCP Kerberos authentication scenario.
COMPILE {
    krb_tcp_stream(dir_client, kdc_tcp_node)
}
"""

FILES["examples/l7/kerberos/kerberos_redundant_kdc_failover.fasm"] = """// PROMPT: Kerberos ticket request failover sequence querying primary and secondary KDC nodes.
// TOKENS: HOST, IP, FLOW, ->, KERBEROS, AS_REQ, REALM, CNAME, ETYPE, WAIT, ms, COMPILE

// INSTRUCTION: Define redundant client station.
HOST branch_client { IP 172.22.1.80 }

// INSTRUCTION: Define primary site KDC.
HOST primary_kdc { IP 172.22.1.10 }

// INSTRUCTION: Define secondary site backup KDC.
HOST backup_kdc { IP 172.22.2.10 }

// INSTRUCTION: Define failover ticket request flow.
FLOW kdc_failover_flow(c, k1, k2) {
    c -> k1 KERBEROS AS_REQ REALM "BRANCH.INTERNAL" CNAME "teller01" ETYPE 18 WAIT 50ms
    c -> k2 KERBEROS AS_REQ REALM "BRANCH.INTERNAL" CNAME "teller01" ETYPE 18
}

// INSTRUCTION: Compile redundant KDC failover scenario.
COMPILE {
    kdc_failover_flow(branch_client, primary_kdc, backup_kdc)
}
"""


# ==============================================================================
# 3. LDAP (12 files)
# ==============================================================================
FILES["examples/l7/ldap/ldap_bind_response_success.fasm"] = """// PROMPT: LDAP directory BindResponse confirming successful administrative authentication.
// TOKENS: HOST, IP, FLOW, <-, LDAP, BIND_RES, MSGID, RESULT_CODE, COMPILE

// INSTRUCTION: Define administrative management console.
HOST admin_console { IP 10.0.15.50 }

// INSTRUCTION: Define directory service LDAP server.
HOST ldap_server { IP 10.0.15.1 }

// INSTRUCTION: Define BindResponse success flow.
FLOW bind_response_flow(c, s) {
    c <- s LDAP BIND_RES MSGID 1 RESULT_CODE 0
}

// INSTRUCTION: Compile LDAP BindResponse success scenario.
COMPILE {
    bind_response_flow(admin_console, ldap_server)
}
"""

FILES["examples/l7/ldap/ldap_user_search_subtree_scope.fasm"] = """// PROMPT: LDAP subtree SearchRequest querying active user accounts matching filter criteria.
// TOKENS: HOST, IP, FLOW, ->, LDAP, SEARCH_REQ, MSGID, BASE_DN, FILTER, COMPILE

// INSTRUCTION: Define web application user authenticator.
HOST app_auth_worker { IP 172.16.20.10 }

// INSTRUCTION: Define central LDAP directory directory.
HOST corporate_ldap { IP 172.16.20.2 }

// INSTRUCTION: Define user search query flow.
FLOW user_search_flow(app, dir) {
    app -> dir LDAP SEARCH_REQ MSGID 10 BASE_DN "ou=users,dc=enterprise,dc=com" FILTER "(mail=user@enterprise.com)"
}

// INSTRUCTION: Compile LDAP user search scenario.
COMPILE {
    user_search_flow(app_auth_worker, corporate_ldap)
}
"""

FILES["examples/l7/ldap/ldap_group_membership_filter.fasm"] = """// PROMPT: LDAP directory SearchRequest looking up security group memberships for authorization.
// TOKENS: HOST, IP, FLOW, ->, LDAP, SEARCH_REQ, MSGID, BASE_DN, FILTER, COMPILE

// INSTRUCTION: Define VPN gateway authorization module.
HOST vpn_gateway { IP 192.168.88.1 }

// INSTRUCTION: Define corporate directory replica.
HOST directory_replica { IP 192.168.88.10 }

// INSTRUCTION: Define security group membership query flow.
FLOW group_search_flow(vpn, dir) {
    vpn -> dir LDAP SEARCH_REQ MSGID 42 BASE_DN "ou=groups,dc=corp,dc=org" FILTER "(member=cn=eng_lead)"
}

// INSTRUCTION: Compile group membership search scenario.
COMPILE {
    group_search_flow(vpn_gateway, directory_replica)
}
"""

FILES["examples/l7/ldap/ldap_anonymous_bind_probe.fasm"] = """// PROMPT: Anonymous LDAP bind probe checking public directory schema accessibility.
// TOKENS: HOST, IP, FLOW, ->, LDAP, BIND_REQ, MSGID, BASE_DN, COMPILE

// INSTRUCTION: Define security audit scanner.
HOST audit_scanner { IP 10.30.1.200 }

// INSTRUCTION: Define public LDAP directory endpoint.
HOST public_directory { IP 10.30.1.5 }

// INSTRUCTION: Define anonymous bind request flow.
FLOW anon_bind_flow(scan, dir) {
    scan -> dir LDAP BIND_REQ MSGID 1 BASE_DN ""
}

// INSTRUCTION: Compile anonymous bind probe scenario.
COMPILE {
    anon_bind_flow(audit_scanner, public_directory)
}
"""

FILES["examples/l7/ldap/ldap_directory_entry_and_done.fasm"] = """// PROMPT: LDAP SearchResponse returning matched SearchResultEntry followed by SearchResultDone.
// TOKENS: HOST, IP, FLOW, <-, LDAP, SEARCH_ENTRY, SEARCH_DONE, MSGID, RESULT_CODE, WAIT, ms, COMPILE

// INSTRUCTION: Define searching client workstation.
HOST search_client { IP 192.168.1.150 }

// INSTRUCTION: Define directory search responder.
HOST ldap_responder { IP 192.168.1.10 }

// INSTRUCTION: Define search response sequence flow.
FLOW search_response_stream(c, s) {
    c <- s LDAP SEARCH_ENTRY MSGID 7 WAIT 3ms
    c <- s LDAP SEARCH_DONE MSGID 7 RESULT_CODE 0
}

// INSTRUCTION: Compile LDAP search response scenario.
COMPILE {
    search_response_stream(search_client, ldap_responder)
}
"""

FILES["examples/l7/ldap/ldap_vlan_tagged_enterprise_directory.fasm"] = """// PROMPT: Enterprise LDAP directory authentication on 802.1Q tagged management VLAN.
// TOKENS: HOST, IP, FLOW, ->, LDAP, BIND_REQ, MSGID, BASE_DN, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define server rack management controller.
HOST bmc_controller { IP 10.110.5.8 }

// INSTRUCTION: Define identity directory server on VLAN 310.
HOST vlan_ldap_server { IP 10.110.5.1 }

// INSTRUCTION: Define tagged VLAN LDAP bind flow.
FLOW vlan_ldap_bind(bmc, srv) {
    bmc -> srv LDAP BIND_REQ MSGID 2 BASE_DN "cn=admin,ou=systems,dc=local" VLAN 310 PCP 5 DEI 0
}

// INSTRUCTION: Compile VLAN tagged directory scenario.
COMPILE {
    vlan_ldap_bind(bmc_controller, vlan_ldap_server)
}
"""

FILES["examples/l7/ldap/ldap_ipv6_directory_search_loop.fasm"] = """// PROMPT: Periodic LDAP directory sync queries executed over IPv6 in a compile loop.
// TOKENS: HOST, IP, FLOW, ->, LDAP, SEARCH_REQ, MSGID, BASE_DN, FILTER, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define IPv6 directory synchronization daemon.
HOST sync_daemon { IP 2001:db8:dc::50 }

// INSTRUCTION: Define primary IPv6 directory controller.
HOST v6_ldap_master { IP 2001:db8:dc::1 }

// INSTRUCTION: Define periodic LDAP search poll flow.
FLOW v6_sync_poll(c, s) {
    c -> s LDAP SEARCH_REQ MSGID 101 BASE_DN "ou=inventory,dc=corp6,dc=net" FILTER "(objectClass=device)" WAIT 20ms
}

// INSTRUCTION: Compile IPv6 directory poll in loop.
COMPILE {
    LOOP 3 {
        v6_sync_poll(sync_daemon, v6_ldap_master)
    }
}
"""

FILES["examples/l7/ldap/ldap_computer_account_lookup.fasm"] = """// PROMPT: Domain workstation computer account lookup via LDAP SearchRequest.
// TOKENS: HOST, IP, FLOW, ->, LDAP, SEARCH_REQ, MSGID, BASE_DN, FILTER, COMPILE

// INSTRUCTION: Define domain join provisioning agent.
HOST provisioning_agent { IP 10.25.1.40 }

// INSTRUCTION: Define Active Directory domain service node.
HOST domain_service_node { IP 10.25.1.1 }

// INSTRUCTION: Define computer object lookup flow.
FLOW computer_lookup_flow(agent, dc) {
    agent -> dc LDAP SEARCH_REQ MSGID 15 BASE_DN "ou=computers,dc=domain,dc=local" FILTER "(sAMAccountName=ws-desk-404$)"
}

// INSTRUCTION: Compile computer account lookup scenario.
COMPILE {
    computer_lookup_flow(provisioning_agent, domain_service_node)
}
"""

FILES["examples/l7/ldap/ldap_ou_structural_query.fasm"] = """// PROMPT: LDAP query navigating organizational unit hierarchy using base DN scoping.
// TOKENS: HOST, IP, FLOW, ->, LDAP, SEARCH_REQ, MSGID, BASE_DN, FILTER, COMPILE

// INSTRUCTION: Define HR portal directory service.
HOST hr_portal { IP 172.28.1.10 }

// INSTRUCTION: Define corporate LDAP directory host.
HOST hr_ldap_host { IP 172.28.1.2 }

// INSTRUCTION: Define organizational hierarchy query flow.
FLOW ou_hierarchy_query(app, dir) {
    app -> dir LDAP SEARCH_REQ MSGID 33 BASE_DN "ou=departments,ou=emea,dc=global,dc=com" FILTER "(objectClass=organizationalUnit)"
}

// INSTRUCTION: Compile OU structural query scenario.
COMPILE {
    ou_hierarchy_query(hr_portal, hr_ldap_host)
}
"""

FILES["examples/l7/ldap/ldap_unbind_graceful_close_session.fasm"] = """// PROMPT: LDAP graceful session termination with UnbindRequest after operations.
// TOKENS: HOST, IP, FLOW, ->, LDAP, UNBIND_REQ, MSGID, COMPILE

// INSTRUCTION: Define directory client application.
HOST app_session_client { IP 192.168.200.75 }

// INSTRUCTION: Define LDAP directory service server.
HOST directory_service { IP 192.168.200.1 }

// INSTRUCTION: Define graceful unbind termination flow.
FLOW unbind_close_flow(c, s) {
    c -> s LDAP UNBIND_REQ MSGID 99
}

// INSTRUCTION: Compile LDAP unbind session close scenario.
COMPILE {
    unbind_close_flow(app_session_client, directory_service)
}
"""

FILES["examples/l7/ldap/ldap_dscp_priority_directory_sync.fasm"] = """// PROMPT: LDAP directory synchronization with DSCP expedited forwarding priority marking.
// TOKENS: HOST, IP, FLOW, ->, LDAP, SEARCH_REQ, MSGID, BASE_DN, FILTER, DSCP, COMPILE

// INSTRUCTION: Define high-priority identity sync service.
HOST identity_sync_svc { IP 10.70.1.15 }

// INSTRUCTION: Define identity master LDAP server.
HOST identity_master { IP 10.70.1.2 }

// INSTRUCTION: Define DSCP prioritized search flow.
FLOW priority_ldap_search(sync, mstr) {
    sync -> mstr LDAP SEARCH_REQ MSGID 501 BASE_DN "ou=executives,dc=identity,dc=net" FILTER "(status=active)" DSCP 46
}

// INSTRUCTION: Compile DSCP priority directory scenario.
COMPILE {
    priority_ldap_search(identity_sync_svc, identity_master)
}
"""

FILES["examples/l7/ldap/ldap_mpls_intersite_directory_replication.fasm"] = """// PROMPT: Inter-site LDAP replication across MPLS VPN backbone connecting enterprise datacenters.
// TOKENS: HOST, IP, FLOW, ->, LDAP, BIND_REQ, SEARCH_REQ, MSGID, BASE_DN, FILTER, COMPILE

// INSTRUCTION: Define branch office directory replica.
HOST branch_replica { IP 10.180.1.5 }

// INSTRUCTION: Define headquarters primary directory server.
HOST hq_master_ldap { IP 10.180.2.5 }

// INSTRUCTION: Define inter-site directory replication flow.
FLOW intersite_replication(br, hq) {
    br -> hq LDAP BIND_REQ MSGID 1 BASE_DN "cn=repl_agent,dc=enterprise,dc=net"
    br -> hq LDAP SEARCH_REQ MSGID 2 BASE_DN "ou=global,dc=enterprise,dc=net" FILTER "(modifyTimestamp>=20261024000000Z)"
}

// INSTRUCTION: Compile inter-site replication scenario.
COMPILE {
    intersite_replication(branch_replica, hq_master_ldap)
}
"""


# ==============================================================================
# 4. mDNS (12 files)
# ==============================================================================
FILES["examples/l7/mdns/mdns_printer_ipp_service_discovery.fasm"] = """// PROMPT: Multicast DNS discovery querying Internet Printing Protocol (IPP) services on local link.
// TOKENS: HOST, IP, FLOW, ->, MDNS, QUERY, TXID, QNAME, QTYPE, COMPILE

// INSTRUCTION: Define office desktop client.
HOST office_desktop { IP 192.168.1.105 }

// INSTRUCTION: Define standard mDNS multicast group.
HOST mdns_multicast { IP 224.0.0.251 }

// INSTRUCTION: Define IPP print service query flow.
FLOW ipp_discovery_flow(cli, grp) {
    cli -> grp MDNS QUERY TXID 1001 QNAME "_ipp._tcp.local" QTYPE "PTR"
}

// INSTRUCTION: Compile mDNS IPP discovery scenario.
COMPILE {
    ipp_discovery_flow(office_desktop, mdns_multicast)
}
"""

FILES["examples/l7/mdns/mdns_workstation_ptr_enumeration.fasm"] = """// PROMPT: mDNS PTR record query enumerating local workstation hostnames on 224.0.0.251:5353.
// TOKENS: HOST, IP, FLOW, ->, MDNS, QUERY, TXID, QNAME, QTYPE, COMPILE

// INSTRUCTION: Define network auditing probe.
HOST audit_probe { IP 10.0.8.55 }

// INSTRUCTION: Define local link multicast endpoint.
HOST link_multicast { IP 224.0.0.251 }

// INSTRUCTION: Define workstation enumeration flow.
FLOW workstation_enum_flow(prb, grp) {
    prb -> grp MDNS QUERY TXID 2002 QNAME "_workstation._tcp.local" QTYPE "PTR"
}

// INSTRUCTION: Compile workstation enumeration scenario.
COMPILE {
    workstation_enum_flow(audit_probe, link_multicast)
}
"""

FILES["examples/l7/mdns/mdns_ssh_service_announcement.fasm"] = """// PROMPT: mDNS unsolicited response announcing available SSH remote terminal service on local subnet.
// TOKENS: HOST, IP, FLOW, ->, MDNS, RESPONSE, TXID, QNAME, QTYPE, RDATA, ANS_TTL, COMPILE

// INSTRUCTION: Define headless Linux server.
HOST headless_server { IP 192.168.10.8 }

// INSTRUCTION: Define local mDNS multicast address.
HOST mcast_group { IP 224.0.0.251 }

// INSTRUCTION: Define SSH service announcement flow.
FLOW ssh_announce_flow(srv, grp) {
    srv -> grp MDNS RESPONSE TXID 0 QNAME "srv-box._ssh._tcp.local" QTYPE "SRV" RDATA "srv-box.local:22" ANS_TTL 120
}

// INSTRUCTION: Compile SSH service announcement scenario.
COMPILE {
    ssh_announce_flow(headless_server, mcast_group)
}
"""

FILES["examples/l7/mdns/mdns_ipv6_link_local_smb_discovery.fasm"] = """// PROMPT: mDNS discovery for SMB file shares over IPv6 link-local multicast ff02::fb.
// TOKENS: HOST, IP, FLOW, ->, MDNS, QUERY, TXID, QNAME, QTYPE, COMPILE

// INSTRUCTION: Define IPv6 client workstation.
HOST v6_workstation { IP fe80::20c:29ff:fe4a:1234 }

// INSTRUCTION: Define IPv6 mDNS link-local multicast group.
HOST v6_mdns_group { IP ff02::fb }

// INSTRUCTION: Define SMB file share query flow.
FLOW smb_query_flow(w, g) {
    w -> g MDNS QUERY TXID 3003 QNAME "_smb._tcp.local" QTYPE "PTR"
}

// INSTRUCTION: Compile IPv6 SMB discovery scenario.
COMPILE {
    smb_query_flow(v6_workstation, v6_mdns_group)
}
"""

FILES["examples/l7/mdns/mdns_airplay_multicast_beacon.fasm"] = """// PROMPT: Apple AirPlay media streaming device announcement using mDNS TXT and SRV records.
// TOKENS: HOST, IP, FLOW, ->, MDNS, RESPONSE, TXID, QNAME, QTYPE, RDATA, ANS_TTL, COMPILE

// INSTRUCTION: Define media receiver device.
HOST apple_tv_device { IP 192.168.2.40 }

// INSTRUCTION: Define mDNS multicast group.
HOST lan_multicast { IP 224.0.0.251 }

// INSTRUCTION: Define AirPlay beacon announcement flow.
FLOW airplay_beacon_flow(dev, grp) {
    dev -> grp MDNS RESPONSE TXID 0 QNAME "LivingRoom._airplay._tcp.local" QTYPE "SRV" RDATA "LivingRoom.local:7000" ANS_TTL 4500
}

// INSTRUCTION: Compile AirPlay beacon scenario.
COMPILE {
    airplay_beacon_flow(apple_tv_device, lan_multicast)
}
"""

FILES["examples/l7/mdns/mdns_vlan_tagged_iot_discovery.fasm"] = """// PROMPT: Zero-configuration IoT smart sensor discovery isolated on tagged home automation VLAN.
// TOKENS: HOST, IP, FLOW, ->, MDNS, QUERY, TXID, QNAME, QTYPE, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define smart home hub controller.
HOST home_hub { IP 10.80.20.5 }

// INSTRUCTION: Define IoT multicast endpoint.
HOST iot_mcast { IP 224.0.0.251 }

// INSTRUCTION: Define VLAN tagged IoT service query flow.
FLOW iot_discovery_vlan(hub, grp) {
    hub -> grp MDNS QUERY TXID 4004 QNAME "_iot-sensor._sub._http._tcp.local" QTYPE "PTR" VLAN 80 PCP 3 DEI 0
}

// INSTRUCTION: Compile VLAN tagged IoT discovery scenario.
COMPILE {
    iot_discovery_vlan(home_hub, iot_mcast)
}
"""

FILES["examples/l7/mdns/mdns_periodic_service_query_loop.fasm"] = """// PROMPT: Continuous mDNS background service poll loop discovering dynamic network endpoints.
// TOKENS: HOST, IP, FLOW, ->, MDNS, QUERY, TXID, QNAME, QTYPE, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define discovery agent scanner.
HOST scanner_host { IP 192.168.5.25 }

// INSTRUCTION: Define local multicast address.
HOST local_mcast { IP 224.0.0.251 }

// INSTRUCTION: Define periodic discovery query flow.
FLOW mcast_poll_flow(s, g) {
    s -> g MDNS QUERY TXID 5005 QNAME "_services._dns-sd._udp.local" QTYPE "PTR" WAIT 30ms
}

// INSTRUCTION: Compile periodic mDNS poll in loop.
COMPILE {
    LOOP 3 {
        mcast_poll_flow(scanner_host, local_mcast)
    }
}
"""

FILES["examples/l7/mdns/mdns_custom_ttl_cache_announcement.fasm"] = """// PROMPT: mDNS service announcement with custom 4500-second cache time-to-live parameter.
// TOKENS: HOST, IP, FLOW, ->, MDNS, RESPONSE, TXID, QNAME, QTYPE, RDATA, ANS_TTL, COMPILE

// INSTRUCTION: Define network attached storage device.
HOST nas_device { IP 192.168.1.200 }

// INSTRUCTION: Define multicast broadcast receiver.
HOST mdns_addr { IP 224.0.0.251 }

// INSTRUCTION: Define long TTL announcement flow.
FLOW long_ttl_announce(nas, grp) {
    nas -> grp MDNS RESPONSE TXID 0 QNAME "storage-vault.local" QTYPE "A" RDATA "192.168.1.200" ANS_TTL 4500
}

// INSTRUCTION: Compile custom TTL announcement scenario.
COMPILE {
    long_ttl_announce(nas_device, mdns_addr)
}
"""

FILES["examples/l7/mdns/mdns_homekit_accessory_resolver.fasm"] = """// PROMPT: Apple HomeKit smart home accessory resolver query over local multicast.
// TOKENS: HOST, IP, FLOW, ->, MDNS, QUERY, TXID, QNAME, QTYPE, COMPILE

// INSTRUCTION: Define smart home mobile controller.
HOST mobile_device { IP 192.168.100.88 }

// INSTRUCTION: Define local link multicast receiver.
HOST mcast_listener { IP 224.0.0.251 }

// INSTRUCTION: Define HomeKit accessory query flow.
FLOW homekit_query_flow(mob, grp) {
    mob -> grp MDNS QUERY TXID 6006 QNAME "_hap._tcp.local" QTYPE "PTR"
}

// INSTRUCTION: Compile HomeKit accessory resolver scenario.
COMPILE {
    homekit_query_flow(mobile_device, mcast_listener)
}
"""

FILES["examples/l7/mdns/mdns_chromecast_cast_discovery.fasm"] = """// PROMPT: Google Cast device discovery query matching _googlecast._tcp.local service pointers.
// TOKENS: HOST, IP, FLOW, ->, MDNS, QUERY, TXID, QNAME, QTYPE, COMPILE

// INSTRUCTION: Define streaming media application client.
HOST media_client { IP 10.0.50.40 }

// INSTRUCTION: Define local subnet multicast endpoint.
HOST mcast_dest { IP 224.0.0.251 }

// INSTRUCTION: Define Google Cast query flow.
FLOW cast_query_flow(app, dst) {
    app -> dst MDNS QUERY TXID 7007 QNAME "_googlecast._tcp.local" QTYPE "PTR"
}

// INSTRUCTION: Compile Chromecast discovery scenario.
COMPILE {
    cast_query_flow(media_client, mcast_dest)
}
"""

FILES["examples/l7/mdns/mdns_http_web_server_advertisement.fasm"] = """// PROMPT: Embedded device advertising internal HTTP web management server via mDNS response.
// TOKENS: HOST, IP, FLOW, ->, MDNS, RESPONSE, TXID, QNAME, QTYPE, RDATA, ANS_TTL, COMPILE

// INSTRUCTION: Define smart router embedded device.
HOST embedded_router { IP 192.168.1.1 }

// INSTRUCTION: Define local link multicast target.
HOST mcast_target { IP 224.0.0.251 }

// INSTRUCTION: Define HTTP web server advertisement flow.
FLOW http_advertisement(rtr, tgt) {
    rtr -> tgt MDNS RESPONSE TXID 0 QNAME "router-ui._http._tcp.local" QTYPE "SRV" RDATA "router.local:80" ANS_TTL 300
}

// INSTRUCTION: Compile web server advertisement scenario.
COMPILE {
    http_advertisement(embedded_router, mcast_target)
}
"""

FILES["examples/l7/mdns/mdns_dual_stack_hostname_resolution.fasm"] = """// PROMPT: Dual-stack mDNS queries resolving both IPv4 A and IPv6 AAAA records for local host.
// TOKENS: HOST, IP, FLOW, ->, MDNS, QUERY, TXID, QNAME, QTYPE, WAIT, ms, COMPILE

// INSTRUCTION: Define dual-stack workstation.
HOST dual_workstation { IP 192.168.10.15 }

// INSTRUCTION: Define multicast group endpoint.
HOST mcast_endpoint { IP 224.0.0.251 }

// INSTRUCTION: Define dual-stack address queries flow.
FLOW dual_query_flow(w, g) {
    w -> g MDNS QUERY TXID 8008 QNAME "fileserver.local" QTYPE "A" WAIT 10ms
    w -> g MDNS QUERY TXID 8009 QNAME "fileserver.local" QTYPE "AAAA"
}

// INSTRUCTION: Compile dual-stack hostname resolution scenario.
COMPILE {
    dual_query_flow(dual_workstation, mcast_endpoint)
}
"""


# ==============================================================================
# 5. Memcached (12 files)
# ==============================================================================
FILES["examples/l7/memcached/memcached_text_set_and_replace.fasm"] = """// PROMPT: Memcached text protocol storing key value pair with set and updating via replace.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, EXPTIME, WAIT, ms, COMPILE

// INSTRUCTION: Define web backend service.
HOST web_service { IP 10.0.30.12 }

// INSTRUCTION: Define Memcached cache cluster node.
HOST memcache_node { IP 10.0.30.5 }

// INSTRUCTION: Define set and replace caching flow.
FLOW set_replace_flow(c, s) {
    c -> s MEMCACHED CMD "set" KEY "config_flags" EXPTIME 1800 WAIT 5ms
    c -> s MEMCACHED CMD "replace" KEY "config_flags" EXPTIME 1800
}

// INSTRUCTION: Compile Memcached set and replace scenario.
COMPILE {
    set_replace_flow(web_service, memcache_node)
}
"""

FILES["examples/l7/memcached/memcached_binary_set_with_opaque.fasm"] = """// PROMPT: Memcached binary protocol Set operation carrying opaque request transaction identifier.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, OPAQUE, COMPILE

// INSTRUCTION: Define microservice caching client.
HOST microservice_client { IP 172.19.4.50 }

// INSTRUCTION: Define Memcached binary server.
HOST binary_memcached { IP 172.19.4.1 }

// INSTRUCTION: Define binary set command flow with opaque ID.
FLOW binary_set_flow(cli, srv) {
    cli -> srv MEMCACHED CMD "Set" KEY "user:session:99" OPAQUE 887766
}

// INSTRUCTION: Compile binary set scenario.
COMPILE {
    binary_set_flow(microservice_client, binary_memcached)
}
"""

FILES["examples/l7/memcached/memcached_atomic_cas_optimistic_update.fasm"] = """// PROMPT: Memcached Compare-And-Swap atomic update with CAS token validation.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, CAS, COMPILE

// INSTRUCTION: Define inventory transaction worker.
HOST inventory_worker { IP 192.168.15.22 }

// INSTRUCTION: Define centralized Memcached host.
HOST central_memcached { IP 192.168.15.10 }

// INSTRUCTION: Define atomic CAS update flow.
FLOW atomic_cas_flow(wrk, srv) {
    wrk -> srv MEMCACHED CMD "cas" KEY "item:stock:4002" CAS 1234567890
}

// INSTRUCTION: Compile atomic CAS update scenario.
COMPILE {
    atomic_cas_flow(inventory_worker, central_memcached)
}
"""

FILES["examples/l7/memcached/memcached_cache_eviction_flush_all.fasm"] = """// PROMPT: Administrative cache invalidation purging all cached entries via flush_all command.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, COMPILE

// INSTRUCTION: Define cache maintenance orchestrator.
HOST devops_admin { IP 10.10.10.99 }

// INSTRUCTION: Define target Memcached instance.
HOST target_cache { IP 10.10.10.2 }

// INSTRUCTION: Define cache flush command flow.
FLOW flush_cache_flow(adm, srv) {
    adm -> srv MEMCACHED CMD "flush_all"
}

// INSTRUCTION: Compile cache eviction flush scenario.
COMPILE {
    flush_cache_flow(devops_admin, target_cache)
}
"""

FILES["examples/l7/memcached/memcached_stats_telemetry_polling.fasm"] = """// PROMPT: Monitoring agent querying Memcached runtime statistics and memory metrics.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, COMPILE

// INSTRUCTION: Define Prometheus monitoring exporter.
HOST prometheus_exporter { IP 192.168.70.15 }

// INSTRUCTION: Define production Memcached node.
HOST prod_memcached { IP 192.168.70.2 }

// INSTRUCTION: Define stats query command flow.
FLOW stats_query_flow(exp, node) {
    exp -> node MEMCACHED CMD "stats"
}

// INSTRUCTION: Compile stats telemetry polling scenario.
COMPILE {
    stats_query_flow(prometheus_exporter, prod_memcached)
}
"""

FILES["examples/l7/memcached/memcached_vlan_sharded_cache_cluster.fasm"] = """// PROMPT: Distributed Memcached cache node query partitioned across tagged datacenter VLAN.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define application tier worker node.
HOST app_worker_node { IP 10.60.10.14 }

// INSTRUCTION: Define Memcached cache shard on VLAN 250.
HOST cache_shard_250 { IP 10.60.10.2 }

// INSTRUCTION: Define tagged VLAN cache lookup flow.
FLOW vlan_cache_lookup(app, shd) {
    app -> shd MEMCACHED CMD "get" KEY "tenant:cfg:101" VLAN 250 PCP 4 DEI 0
}

// INSTRUCTION: Compile VLAN sharded cache scenario.
COMPILE {
    vlan_cache_lookup(app_worker_node, cache_shard_250)
}
"""

FILES["examples/l7/memcached/memcached_ipv6_session_store_get.fasm"] = """// PROMPT: Web frontend retrieving user session data from Memcached cluster over IPv6.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, COMPILE

// INSTRUCTION: Define IPv6 edge web gateway.
HOST v6_web_gateway { IP 2001:db8:ca5e::20 }

// INSTRUCTION: Define IPv6 Memcached server.
HOST v6_memcached_srv { IP 2001:db8:ca5e::1 }

// INSTRUCTION: Define IPv6 session lookup flow.
FLOW v6_session_get(gw, srv) {
    gw -> srv MEMCACHED CMD "get" KEY "sess:v6:982341"
}

// INSTRUCTION: Compile IPv6 session store scenario.
COMPILE {
    v6_session_get(v6_web_gateway, v6_memcached_srv)
}
"""

FILES["examples/l7/memcached/memcached_high_rate_get_burst_loop.fasm"] = """// PROMPT: High-throughput Memcached cache read benchmark executed inside compile loop.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define performance benchmark runner.
HOST benchmark_runner { IP 172.30.1.100 }

// INSTRUCTION: Define high-concurrency Memcached target.
HOST cache_target { IP 172.30.1.1 }

// INSTRUCTION: Define rapid get request burst flow.
FLOW burst_get_flow(cli, srv) {
    cli -> srv MEMCACHED CMD "get" KEY "hot:item:key" WAIT 5ms
}

// INSTRUCTION: Compile high rate get burst in loop.
COMPILE {
    LOOP 4 {
        burst_get_flow(benchmark_runner, cache_target)
    }
}
"""

FILES["examples/l7/memcached/memcached_item_expiry_ttl_caching.fasm"] = """// PROMPT: Memcached storage command configuring short 300-second time-to-live expiration.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, EXPTIME, COMPILE

// INSTRUCTION: Define OTP verification service.
HOST otp_service { IP 192.168.120.45 }

// INSTRUCTION: Define volatile memory cache store.
HOST volatile_cache { IP 192.168.120.2 }

// INSTRUCTION: Define short TTL storage flow.
FLOW short_ttl_store(svc, store) {
    svc -> store MEMCACHED CMD "set" KEY "otp:user:552" EXPTIME 300
}

// INSTRUCTION: Compile item expiry TTL caching scenario.
COMPILE {
    short_ttl_store(otp_service, volatile_cache)
}
"""

FILES["examples/l7/memcached/memcached_delete_key_invalidation.fasm"] = """// PROMPT: Explicit cache invalidation executing Memcached delete command for stale data.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, COMPILE

// INSTRUCTION: Define user profile updater service.
HOST profile_updater { IP 10.40.2.18 }

// INSTRUCTION: Define primary Memcached server.
HOST profile_cache { IP 10.40.2.2 }

// INSTRUCTION: Define cache key deletion flow.
FLOW delete_cache_key(app, c) {
    app -> c MEMCACHED CMD "delete" KEY "profile:uid:88192"
}

// INSTRUCTION: Compile delete key invalidation scenario.
COMPILE {
    delete_cache_key(profile_updater, profile_cache)
}
"""

FILES["examples/l7/memcached/memcached_tcp_handshake_session_get.fasm"] = """// PROMPT: TCP 3-way handshake on port 11211 followed by Memcached session key lookup.
// TOKENS: HOST, IP, FLOW, ->, <-, TCP, SYN, ACK, DSTPORT, MEMCACHED, CMD, KEY, WAIT, ms, COMPILE

// INSTRUCTION: Define web backend application client.
HOST web_app_client { IP 172.16.55.80 }

// INSTRUCTION: Define Memcached port 11211 daemon.
HOST memcached_daemon { IP 172.16.55.10 }

// INSTRUCTION: Define TCP handshake and get query flow.
FLOW tcp_memcached_session(c, s) {
    c -> s TCP SYN DSTPORT 11211
    c <- s TCP SYN ACK
    c -> s TCP ACK WAIT 1ms
    c -> s MEMCACHED CMD "get" KEY "app:session:55"
}

// INSTRUCTION: Compile TCP handshake session get scenario.
COMPILE {
    tcp_memcached_session(web_app_client, memcached_daemon)
}
"""

FILES["examples/l7/memcached/memcached_dscp_marked_read_replica.fasm"] = """// PROMPT: Low-latency DSCP marked Memcached lookup from application microservice.
// TOKENS: HOST, IP, FLOW, ->, MEMCACHED, CMD, KEY, DSCP, COMPILE

// INSTRUCTION: Define latency-sensitive trading client.
HOST trading_engine { IP 10.200.1.5 }

// INSTRUCTION: Define in-memory cache replica.
HOST memory_replica { IP 10.200.1.2 }

// INSTRUCTION: Define DSCP expedited forwarding lookup flow.
FLOW low_latency_lookup(trd, rep) {
    trd -> rep MEMCACHED CMD "get" KEY "ticker:quote:GOOG" DSCP 46
}

// INSTRUCTION: Compile DSCP marked read replica scenario.
COMPILE {
    low_latency_lookup(trading_engine, memory_replica)
}
"""


# ==============================================================================
# 6. Modbus (12 files)
# ==============================================================================
FILES["examples/l7/modbus/modbus_read_coils_digital_inputs.fasm"] = """// PROMPT: Modbus TCP function code 1 reading digital output coil statuses from remote PLC.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, COMPILE

// INSTRUCTION: Define industrial SCADA supervisory station.
HOST scada_station { IP 192.168.10.10 }

// INSTRUCTION: Define programmable logic controller (PLC).
HOST field_plc { IP 192.168.10.200 }

// INSTRUCTION: Define read coils operation flow.
FLOW read_coils_flow(scada, plc) {
    scada -> plc MODBUS FUNC "READ_COILS" ADDR 0 COUNT 16 UNITID 1
}

// INSTRUCTION: Compile Modbus read coils scenario.
COMPILE {
    read_coils_flow(scada_station, field_plc)
}
"""

FILES["examples/l7/modbus/modbus_read_discrete_inputs_telemetry.fasm"] = """// PROMPT: Modbus TCP function code 2 reading discrete input binary telemetry from RTU.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, COMPILE

// INSTRUCTION: Define water treatment plant master controller.
HOST water_plant_hmi { IP 10.100.1.15 }

// INSTRUCTION: Define remote telemetry unit pump controller.
HOST pump_station_rtu { IP 10.100.1.50 }

// INSTRUCTION: Define read discrete inputs flow.
FLOW read_inputs_flow(hmi, rtu) {
    hmi -> rtu MODBUS FUNC "READ_DISCRETE_INPUTS" ADDR 10001 COUNT 8 UNITID 2
}

// INSTRUCTION: Compile read discrete inputs scenario.
COMPILE {
    read_inputs_flow(water_plant_hmi, pump_station_rtu)
}
"""

FILES["examples/l7/modbus/modbus_read_input_registers_analog.fasm"] = """// PROMPT: Modbus TCP function code 4 reading analog sensor measurements from input registers.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, COMPILE

// INSTRUCTION: Define environmental telemetry monitor.
HOST env_monitor { IP 172.25.1.20 }

// INSTRUCTION: Define analog weather station sensor RTU.
HOST weather_rtu { IP 172.25.1.100 }

// INSTRUCTION: Define read input registers flow.
FLOW read_analog_flow(mon, rtu) {
    mon -> rtu MODBUS FUNC "READ_INPUT_REGISTERS" ADDR 30001 COUNT 4 UNITID 1
}

// INSTRUCTION: Compile read input registers scenario.
COMPILE {
    read_analog_flow(env_monitor, weather_rtu)
}
"""

FILES["examples/l7/modbus/modbus_write_multiple_registers_batch.fasm"] = """// PROMPT: Modbus TCP function code 16 writing batch parameter configuration to PLC registers.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, COMPILE

// INSTRUCTION: Define assembly line engineering workstation.
HOST eng_workstation { IP 192.168.2.10 }

// INSTRUCTION: Define manufacturing cell PLC controller.
HOST robot_cell_plc { IP 192.168.2.88 }

// INSTRUCTION: Define write multiple registers configuration flow.
FLOW write_batch_config(eng, plc) {
    eng -> plc MODBUS FUNC "WRITE_MULTIPLE_REGISTERS" ADDR 40100 COUNT 5 UNITID 3
}

// INSTRUCTION: Compile write multiple registers scenario.
COMPILE {
    write_batch_config(eng_workstation, robot_cell_plc)
}
"""

FILES["examples/l7/modbus/modbus_response_holding_register_values.fasm"] = """// PROMPT: Modbus TCP response frame returning holding register integer values to SCADA master.
// TOKENS: HOST, IP, FLOW, <-, MODBUS, IS_RESPONSE, TXID, PROTO_ID, UNITID, COUNT, VALUE, COMPILE

// INSTRUCTION: Define SCADA master client.
HOST scada_client { IP 10.50.1.10 }

// INSTRUCTION: Define responding field RTU node.
HOST field_rtu_node { IP 10.50.1.25 }

// INSTRUCTION: Define Modbus response packet flow.
FLOW modbus_response_flow(mst, rtu) {
    mst <- rtu MODBUS IS_RESPONSE TXID 101 PROTO_ID 0 UNITID 1 COUNT 2 VALUE 1234
}

// INSTRUCTION: Compile Modbus register response scenario.
COMPILE {
    modbus_response_flow(scada_client, field_rtu_node)
}
"""

FILES["examples/l7/modbus/modbus_plc_polling_loop_cycle.fasm"] = """// PROMPT: Cyclic industrial control polling loop querying RTU register status every 25ms.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define factory DCS central controller.
HOST factory_dcs { IP 192.168.40.1 }

// INSTRUCTION: Define conveyor belt slave drive.
HOST conveyor_drive { IP 192.168.40.50 }

// INSTRUCTION: Define periodic register polling flow.
FLOW cyclic_poll_flow(dcs, drv) {
    dcs -> drv MODBUS FUNC "READ_HOLDING_REGISTERS" ADDR 500 COUNT 2 UNITID 1 WAIT 25ms
}

// INSTRUCTION: Compile cyclic PLC polling in loop.
COMPILE {
    LOOP 3 {
        cyclic_poll_flow(factory_dcs, conveyor_drive)
    }
}
"""

FILES["examples/l7/modbus/modbus_ipv6_substation_rtu_telemetry.fasm"] = """// PROMPT: Modern electrical substation RTU communication running Modbus TCP over IPv6.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, COMPILE

// INSTRUCTION: Define electrical grid control center.
HOST grid_control { IP 2001:db8:5ca0::10 }

// INSTRUCTION: Define smart grid feeder RTU.
HOST feeder_rtu { IP 2001:db8:5ca0::200 }

// INSTRUCTION: Define IPv6 Modbus telemetry flow.
FLOW v6_substation_poll(ctrl, rtu) {
    ctrl -> rtu MODBUS FUNC "READ_HOLDING_REGISTERS" ADDR 1000 COUNT 8 UNITID 5
}

// INSTRUCTION: Compile IPv6 substation telemetry scenario.
COMPILE {
    v6_substation_poll(grid_control, feeder_rtu)
}
"""

FILES["examples/l7/modbus/modbus_vlan_tagged_industrial_scada.fasm"] = """// PROMPT: Critical infrastructure Modbus control traffic isolated on 802.1Q SCADA VLAN.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define operations control center HMI.
HOST occ_hmi { IP 10.200.5.12 }

// INSTRUCTION: Define generator protection relay PLC.
HOST generator_relay { IP 10.200.5.80 }

// INSTRUCTION: Define tagged VLAN Modbus interrogation flow.
FLOW vlan_modbus_flow(hmi, rly) {
    hmi -> rly MODBUS FUNC "READ_HOLDING_REGISTERS" ADDR 200 COUNT 6 UNITID 1 VLAN 502 PCP 6 DEI 0
}

// INSTRUCTION: Compile VLAN tagged industrial SCADA scenario.
COMPILE {
    vlan_modbus_flow(occ_hmi, generator_relay)
}
"""

FILES["examples/l7/modbus/modbus_dscp_marked_process_automation.fasm"] = """// PROMPT: Modbus industrial automation command with DSCP expedited forwarding priority marking.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, VALUE, UNITID, DSCP, COMPILE

// INSTRUCTION: Define emergency shutdown safety system.
HOST safety_system { IP 192.168.1.99 }

// INSTRUCTION: Define emergency relief valve actuator.
HOST valve_actuator { IP 192.168.1.150 }

// INSTRUCTION: Define DSCP prioritized emergency coil write flow.
FLOW emergency_valve_trip(sys, act) {
    sys -> act MODBUS FUNC "WRITE_SINGLE_COIL" ADDR 10 VALUE 65280 UNITID 1 DSCP 46
}

// INSTRUCTION: Compile DSCP marked process automation scenario.
COMPILE {
    emergency_valve_trip(safety_system, valve_actuator)
}
"""

FILES["examples/l7/modbus/modbus_custom_unit_id_gateway.fasm"] = """// PROMPT: Modbus TCP to RTU serial bridge routing command to slave device unit ID 15.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, TXID, COMPILE

// INSTRUCTION: Define multi-drop master poller.
HOST master_poller { IP 10.10.8.5 }

// INSTRUCTION: Define RS485 serial gateway bridge.
HOST rs485_gateway { IP 10.10.8.20 }

// INSTRUCTION: Define bridged serial command flow.
FLOW bridged_unit_flow(mst, gw) {
    mst -> gw MODBUS FUNC "READ_HOLDING_REGISTERS" ADDR 50 COUNT 10 UNITID 15 TXID 7788
}

// INSTRUCTION: Compile custom unit ID gateway scenario.
COMPILE {
    bridged_unit_flow(master_poller, rs485_gateway)
}
"""

FILES["examples/l7/modbus/modbus_write_single_register_setpoint.fasm"] = """// PROMPT: Modbus TCP function code 6 updating industrial PID temperature controller setpoint.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, VALUE, UNITID, COMPILE

// INSTRUCTION: Define furnace supervisory station.
HOST furnace_hmi { IP 172.16.80.14 }

// INSTRUCTION: Define temperature controller device.
HOST temp_controller { IP 172.16.80.200 }

// INSTRUCTION: Define setpoint write flow.
FLOW write_setpoint_flow(hmi, ctrl) {
    hmi -> ctrl MODBUS FUNC "WRITE_SINGLE_REGISTER" ADDR 40050 VALUE 750 UNITID 1
}

// INSTRUCTION: Compile write single register setpoint scenario.
COMPILE {
    write_setpoint_flow(furnace_hmi, temp_controller)
}
"""

FILES["examples/l7/modbus/modbus_mpls_remote_substation_poll.fasm"] = """// PROMPT: Wide-area power grid monitoring polling remote Modbus RTU across MPLS core network.
// TOKENS: HOST, IP, FLOW, ->, MODBUS, FUNC, ADDR, COUNT, UNITID, MPLS, COMPILE

// INSTRUCTION: Define regional power dispatcher node.
HOST dispatcher_node { IP 10.250.1.1 }

// INSTRUCTION: Define remote wind farm substation RTU.
HOST wind_farm_rtu { IP 10.250.100.5 }

// INSTRUCTION: Define MPLS transported Modbus polling flow.
FLOW mpls_modbus_poll(disp, rtu) {
    disp -> rtu MODBUS FUNC "READ_HOLDING_REGISTERS" ADDR 100 COUNT 12 UNITID 2 MPLS 3001
}

// INSTRUCTION: Compile MPLS remote substation scenario.
COMPILE {
    mpls_modbus_poll(dispatcher_node, wind_farm_rtu)
}
"""


# ==============================================================================
# 7. MQTT (12 files)
# ==============================================================================
FILES["examples/l7/mqtt/mqtt_qos_zero_sensor_telemetry.fasm"] = """// PROMPT: MQTT QoS 0 telemetry publishing fire-and-forget temperature sensor updates.
// TOKENS: HOST, IP, FLOW, ->, MQTT, PUBLISH, TOPIC, QOS, COMPILE

// INSTRUCTION: Define edge temperature sensor node.
HOST edge_temp_sensor { IP 192.168.1.80 }

// INSTRUCTION: Define central MQTT message broker.
HOST central_broker { IP 192.168.1.10 }

// INSTRUCTION: Define QoS 0 telemetry publish flow.
FLOW qos0_publish_flow(sensor, broker) {
    sensor -> broker MQTT PUBLISH TOPIC "factory/zone1/temperature" QOS 0
}

// INSTRUCTION: Compile QoS 0 sensor telemetry scenario.
COMPILE {
    qos0_publish_flow(edge_temp_sensor, central_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_qos_one_publish_and_puback.fasm"] = """// PROMPT: MQTT QoS 1 reliable publishing with broker PUBACK acknowledgment packet.
// TOKENS: HOST, IP, FLOW, ->, <-, MQTT, PUBLISH, PUBACK, TOPIC, QOS, PKT_ID, WAIT, ms, COMPILE

// INSTRUCTION: Define smart power meter device.
HOST smart_meter { IP 10.0.12.50 }

// INSTRUCTION: Define utility telemetry broker.
HOST utility_broker { IP 10.0.12.1 }

// INSTRUCTION: Define QoS 1 publish and PUBACK flow.
FLOW qos1_publish_ack_flow(dev, brk) {
    dev -> brk MQTT PUBLISH TOPIC "grid/meter/power_kw" QOS 1 PKT_ID 401 WAIT 5ms
    dev <- brk MQTT PUBACK PKT_ID 401
}

// INSTRUCTION: Compile QoS 1 publish and PUBACK scenario.
COMPILE {
    qos1_publish_ack_flow(smart_meter, utility_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_retained_status_broadcast.fasm"] = """// PROMPT: MQTT retained message broadcast preserving latest device online status for new subscribers.
// TOKENS: HOST, IP, FLOW, ->, MQTT, PUBLISH, TOPIC, RETAIN, COMPILE

// INSTRUCTION: Define industrial IoT gateway.
HOST industrial_gw { IP 172.16.4.15 }

// INSTRUCTION: Define IoT management broker.
HOST iot_broker { IP 172.16.4.1 }

// INSTRUCTION: Define retained status broadcast flow.
FLOW retained_status_flow(gw, brk) {
    gw -> brk MQTT PUBLISH TOPIC "devices/gateway01/status" RETAIN
}

// INSTRUCTION: Compile retained status broadcast scenario.
COMPILE {
    retained_status_flow(industrial_gw, iot_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_client_pingreq_heartbeat_loop.fasm"] = """// PROMPT: MQTT keepalive heartbeat loop periodically transmitting PINGREQ to maintain session.
// TOKENS: HOST, IP, FLOW, ->, MQTT, PINGREQ, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define battery operated sensor client.
HOST lowpower_client { IP 192.168.20.99 }

// INSTRUCTION: Define cloud MQTT gateway.
HOST cloud_gateway { IP 192.168.20.1 }

// INSTRUCTION: Define heartbeat PINGREQ transmission flow.
FLOW heartbeat_ping_flow(cli, gw) {
    cli -> gw MQTT PINGREQ WAIT 50ms
}

// INSTRUCTION: Compile client heartbeat loop scenario.
COMPILE {
    LOOP 3 {
        heartbeat_ping_flow(lowpower_client, cloud_gateway)
    }
}
"""

FILES["examples/l7/mqtt/mqtt_vlan_tagged_industrial_broker.fasm"] = """// PROMPT: Manufacturing shop floor IoT gateway communicating with broker over tagged VLAN.
// TOKENS: HOST, IP, FLOW, ->, MQTT, CONNECT, CLIENT_ID, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define shop floor telemetry gateway.
HOST shopfloor_gw { IP 10.90.1.25 }

// INSTRUCTION: Define factory MQTT cluster broker on VLAN 90.
HOST plant_broker { IP 10.90.1.5 }

// INSTRUCTION: Define tagged VLAN CONNECT session initiation.
FLOW vlan_mqtt_connect(gw, brk) {
    gw -> brk MQTT CONNECT CLIENT_ID "shopfloor-gw-01" VLAN 90 PCP 5 DEI 0
}

// INSTRUCTION: Compile VLAN tagged industrial broker scenario.
COMPILE {
    vlan_mqtt_connect(shopfloor_gw, plant_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_ipv6_smart_meter_ingest.fasm"] = """// PROMPT: Smart utility meter publishing electrical telemetry to cloud MQTT broker over IPv6.
// TOKENS: HOST, IP, FLOW, ->, MQTT, PUBLISH, TOPIC, CLIENT_ID, COMPILE

// INSTRUCTION: Define IPv6 smart electric meter.
HOST v6_smart_meter { IP 2001:db8:beef::45 }

// INSTRUCTION: Define utility IPv6 MQTT broker.
HOST v6_utility_broker { IP 2001:db8:beef::1 }

// INSTRUCTION: Define IPv6 telemetry publishing flow.
FLOW v6_meter_publish(meter, brk) {
    meter -> brk MQTT PUBLISH TOPIC "smartgrid/v6/meter45/voltage" CLIENT_ID "meter-v6-45"
}

// INSTRUCTION: Compile IPv6 smart meter ingest scenario.
COMPILE {
    v6_meter_publish(v6_smart_meter, v6_utility_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_custom_keepalive_connection.fasm"] = """// PROMPT: MQTT client session connection specifying client ID and clean session initiation.
// TOKENS: HOST, IP, FLOW, ->, MQTT, CONNECT, CLIENT_ID, COMPILE

// INSTRUCTION: Define offshore oil rig telemetry node.
HOST offshore_telemetry { IP 198.51.100.14 }

// INSTRUCTION: Define onshore central MQTT broker.
HOST onshore_broker { IP 198.51.100.1 }

// INSTRUCTION: Define extended keepalive connection flow.
FLOW extended_keepalive_conn(node, brk) {
    node -> brk MQTT CONNECT CLIENT_ID "offshore-rig-alpha"
}

// INSTRUCTION: Compile custom keepalive connection scenario.
COMPILE {
    extended_keepalive_conn(offshore_telemetry, onshore_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_connack_session_present_response.fasm"] = """// PROMPT: MQTT broker CONNACK packet confirming successful connection and session acknowledgment.
// TOKENS: HOST, IP, FLOW, <-, MQTT, CONNACK, RETURN_CODE, COMPILE

// INSTRUCTION: Define connecting IoT edge client.
HOST edge_client_device { IP 10.12.0.40 }

// INSTRUCTION: Define enterprise message broker.
HOST enterprise_broker { IP 10.12.0.1 }

// INSTRUCTION: Define CONNACK acknowledgment response flow.
FLOW connack_response_flow(dev, brk) {
    dev <- brk MQTT CONNACK RETURN_CODE 0
}

// INSTRUCTION: Compile MQTT CONNACK response scenario.
COMPILE {
    connack_response_flow(edge_client_device, enterprise_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_environmental_multi_topic_pub.fasm"] = """// PROMPT: Environmental monitoring station publishing sequential humidity and air quality telemetry.
// TOKENS: HOST, IP, FLOW, ->, MQTT, PUBLISH, TOPIC, WAIT, ms, COMPILE

// INSTRUCTION: Define environmental sensor station.
HOST weather_station { IP 192.168.33.10 }

// INSTRUCTION: Define environmental data broker.
HOST env_data_broker { IP 192.168.33.1 }

// INSTRUCTION: Define multi-topic sequential publishing flow.
FLOW env_multi_publish(ws, brk) {
    ws -> brk MQTT PUBLISH TOPIC "env/sensors/humidity" WAIT 10ms
    ws -> brk MQTT PUBLISH TOPIC "env/sensors/co2_ppm"
}

// INSTRUCTION: Compile multi-topic publishing scenario.
COMPILE {
    env_multi_publish(weather_station, env_data_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_fleet_telematics_publish_stream.fasm"] = """// PROMPT: Connected vehicle telematics gateway streaming GPS location coordinates via MQTT.
// TOKENS: HOST, IP, FLOW, ->, MQTT, PUBLISH, TOPIC, CLIENT_ID, COMPILE

// INSTRUCTION: Define vehicle telematics unit.
HOST vehicle_telematics { IP 10.220.1.88 }

// INSTRUCTION: Define fleet operations broker.
HOST fleet_broker { IP 10.220.1.10 }

// INSTRUCTION: Define vehicle GPS telemetry publishing flow.
FLOW vehicle_gps_publish(veh, brk) {
    veh -> brk MQTT PUBLISH TOPIC "fleet/truck402/location" CLIENT_ID "truck-obd-402"
}

// INSTRUCTION: Compile fleet telematics scenario.
COMPILE {
    vehicle_gps_publish(vehicle_telematics, fleet_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_dscp_marked_high_priority_alarm.fasm"] = """// PROMPT: Critical industrial safety alarm published over MQTT with DSCP expedited forwarding.
// TOKENS: HOST, IP, FLOW, ->, MQTT, PUBLISH, TOPIC, QOS, DSCP, COMPILE

// INSTRUCTION: Define hazardous gas detector.
HOST gas_detector { IP 172.20.10.5 }

// INSTRUCTION: Define safety monitoring broker.
HOST safety_broker { IP 172.20.10.1 }

// INSTRUCTION: Define DSCP marked emergency alert flow.
FLOW safety_alarm_publish(det, brk) {
    det -> brk MQTT PUBLISH TOPIC "alarms/safety/methane_leak" QOS 1 DSCP 46
}

// INSTRUCTION: Compile DSCP priority safety alarm scenario.
COMPILE {
    safety_alarm_publish(gas_detector, safety_broker)
}
"""

FILES["examples/l7/mqtt/mqtt_edge_gateway_cluster_pubsub.fasm"] = """// PROMPT: Edge gateway connecting to broker, subscribing to command topic, and publishing telemetry.
// TOKENS: HOST, IP, FLOW, ->, MQTT, CONNECT, CLIENT_ID, PUBLISH, TOPIC, WAIT, ms, COMPILE

// INSTRUCTION: Define edge computing gateway.
HOST edge_compute_node { IP 10.15.2.50 }

// INSTRUCTION: Define centralized edge cluster broker.
HOST edge_cluster_broker { IP 10.15.2.1 }

// INSTRUCTION: Define connection followed by telemetry publishing.
FLOW edge_cluster_lifecycle(node, brk) {
    node -> brk MQTT CONNECT CLIENT_ID "edge-node-50" WAIT 15ms
    node -> brk MQTT PUBLISH TOPIC "edge/compute/load_avg"
}

// INSTRUCTION: Compile edge gateway pubsub scenario.
COMPILE {
    edge_cluster_lifecycle(edge_compute_node, edge_cluster_broker)
}
"""


# ==============================================================================
# 8. MySQL (12 files)
# ==============================================================================
FILES["examples/l7/mysql/mysql_tcp_handshake_com_query.fasm"] = """// PROMPT: TCP 3-way handshake on port 3306 followed by MySQL COM_QUERY database statement.
// TOKENS: HOST, IP, FLOW, ->, <-, TCP, SYN, ACK, DSTPORT, MYSQL, SQL, WAIT, ms, COMPILE

// INSTRUCTION: Define microservice API database client.
HOST microservice_db_client { IP 10.0.100.15 }

// INSTRUCTION: Define MySQL database instance listening on 3306.
HOST mysql_db_instance { IP 10.0.100.2 }

// INSTRUCTION: Define TCP handshake and COM_QUERY sequence flow.
FLOW mysql_tcp_query_flow(c, s) {
    c -> s TCP SYN DSTPORT 3306
    c <- s TCP SYN ACK
    c -> s TCP ACK WAIT 1ms
    c -> s MYSQL SQL "SELECT COUNT(*) FROM orders WHERE status = 'pending'"
}

// INSTRUCTION: Compile TCP handshake and query scenario.
COMPILE {
    mysql_tcp_query_flow(microservice_db_client, mysql_db_instance)
}
"""

FILES["examples/l7/mysql/mysql_greeting_server_capabilities.fasm"] = """// PROMPT: MySQL server initial greeting packet announcing version 8.0.36 protocol capabilities.
// TOKENS: HOST, IP, FLOW, <-, MYSQL, GREETING, SERVER_VERSION, COMPILE

// INSTRUCTION: Define connecting application client.
HOST connecting_app_client { IP 192.168.1.50 }

// INSTRUCTION: Define MySQL relational database server.
HOST enterprise_mysql { IP 192.168.1.10 }

// INSTRUCTION: Define server greeting response flow.
FLOW mysql_greeting_flow(app, db) {
    app <- db MYSQL GREETING SERVER_VERSION "8.0.36"
}

// INSTRUCTION: Compile MySQL greeting capabilities scenario.
COMPILE {
    mysql_greeting_flow(connecting_app_client, enterprise_mysql)
}
"""

FILES["examples/l7/mysql/mysql_table_schema_describe_query.fasm"] = """// PROMPT: MySQL client querying table column definitions using DESCRIBE schema statement.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, COMPILE

// INSTRUCTION: Define database management console.
HOST db_console { IP 172.16.1.14 }

// INSTRUCTION: Define MySQL schema repository.
HOST schema_repo { IP 172.16.1.2 }

// INSTRUCTION: Define schema inspection query flow.
FLOW describe_table_flow(con, db) {
    con -> db MYSQL SQL "DESCRIBE user_credentials"
}

// INSTRUCTION: Compile table schema describe scenario.
COMPILE {
    describe_table_flow(db_console, schema_repo)
}
"""

FILES["examples/l7/mysql/mysql_insert_transaction_commit.fasm"] = """// PROMPT: MySQL transactional write inserting customer order record followed by COMMIT.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, WAIT, ms, COMPILE

// INSTRUCTION: Define ecommerce checkout service.
HOST checkout_service { IP 10.8.0.22 }

// INSTRUCTION: Define primary transactional database node.
HOST oltp_mysql_primary { IP 10.8.0.1 }

// INSTRUCTION: Define multi-statement transaction flow.
FLOW insert_commit_flow(app, db) {
    app -> db MYSQL SQL "INSERT INTO orders (id, amount) VALUES (998, 149.99)" WAIT 5ms
    app -> db MYSQL SQL "COMMIT"
}

// INSTRUCTION: Compile transactional insert commit scenario.
COMPILE {
    insert_commit_flow(checkout_service, oltp_mysql_primary)
}
"""

FILES["examples/l7/mysql/mysql_select_indexed_record_lookup.fasm"] = """// PROMPT: High-speed primary key SELECT query retrieving user profile record from MySQL.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, COMPILE

// INSTRUCTION: Define user session authentication provider.
HOST auth_provider { IP 192.168.10.40 }

// INSTRUCTION: Define user database replica node.
HOST user_db_replica { IP 192.168.10.2 }

// INSTRUCTION: Define indexed record retrieval flow.
FLOW select_user_flow(auth, db) {
    auth -> db MYSQL SQL "SELECT id, email, role FROM accounts WHERE id = 4210"
}

// INSTRUCTION: Compile indexed record lookup scenario.
COMPILE {
    select_user_flow(auth_provider, user_db_replica)
}
"""

FILES["examples/l7/mysql/mysql_vlan_tagged_database_cluster.fasm"] = """// PROMPT: Backend application querying MySQL cluster on 802.1Q tagged database storage VLAN.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define application cluster pod node.
HOST app_pod_node { IP 10.50.4.15 }

// INSTRUCTION: Define clustered database service on VLAN 405.
HOST db_cluster_service { IP 10.50.4.2 }

// INSTRUCTION: Define tagged VLAN database query flow.
FLOW vlan_db_query(pod, srv) {
    pod -> srv MYSQL SQL "SELECT status FROM cluster_nodes WHERE healthy = 1" VLAN 405 PCP 5 DEI 0
}

// INSTRUCTION: Compile VLAN tagged database cluster scenario.
COMPILE {
    vlan_db_query(app_pod_node, db_cluster_service)
}
"""

FILES["examples/l7/mysql/mysql_ipv6_analytics_read_query.fasm"] = """// PROMPT: Business intelligence reporting service executing aggregation query across IPv6 underlay.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, COMPILE

// INSTRUCTION: Define IPv6 analytics reporting engine.
HOST analytics_engine { IP 2001:db8:501::55 }

// INSTRUCTION: Define IPv6 MySQL reporting warehouse.
HOST v6_warehouse_db { IP 2001:db8:501::1 }

// INSTRUCTION: Define aggregation report query flow.
FLOW analytics_query_flow(eng, db) {
    eng -> db MYSQL SQL "SELECT region, SUM(revenue) FROM sales_archive GROUP BY region"
}

// INSTRUCTION: Compile IPv6 analytics query scenario.
COMPILE {
    analytics_query_flow(analytics_engine, v6_warehouse_db)
}
"""

FILES["examples/l7/mysql/mysql_periodic_health_probe_loop.fasm"] = """// PROMPT: Load balancer health check loop executing periodic ping queries against MySQL server.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define HAProxy load balancer probe.
HOST haproxy_probe { IP 172.20.1.10 }

// INSTRUCTION: Define backend MySQL cluster member.
HOST backend_mysql_node { IP 172.20.1.2 }

// INSTRUCTION: Define periodic health probe query flow.
FLOW health_probe_flow(prb, db) {
    prb -> db MYSQL SQL "/* ping */ SELECT 1" WAIT 20ms
}

// INSTRUCTION: Compile periodic health check loop.
COMPILE {
    LOOP 3 {
        health_probe_flow(haproxy_probe, backend_mysql_node)
    }
}
"""

FILES["examples/l7/mysql/mysql_dscp_marked_oltp_traffic.fasm"] = """// PROMPT: Online transaction processing database query prioritized with DSCP AF31 traffic marking.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, DSCP, COMPILE

// INSTRUCTION: Define trading platform order router.
HOST order_router { IP 10.90.1.18 }

// INSTRUCTION: Define low-latency MySQL transaction store.
HOST low_latency_db { IP 10.90.1.2 }

// INSTRUCTION: Define DSCP marked payment query flow.
FLOW dscp_payment_query(rtr, db) {
    rtr -> db MYSQL SQL "UPDATE balances SET amount = amount - 50.00 WHERE account_id = 918" DSCP 26
}

// INSTRUCTION: Compile DSCP marked OLTP scenario.
COMPILE {
    dscp_payment_query(order_router, low_latency_db)
}
"""

FILES["examples/l7/mysql/mysql_connection_pool_keepalive.fasm"] = """// PROMPT: Application connection pool executing lightweight SELECT 1 keepalive query on MySQL.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, COMPILE

// INSTRUCTION: Define HikariCP connection pool host.
HOST connection_pool_mgr { IP 192.168.4.88 }

// INSTRUCTION: Define pooled MySQL database server.
HOST pooled_mysql_server { IP 192.168.4.1 }

// INSTRUCTION: Define pool validation keepalive flow.
FLOW pool_keepalive_flow(mgr, srv) {
    mgr -> srv MYSQL SQL "SELECT 1"
}

// INSTRUCTION: Compile connection pool keepalive scenario.
COMPILE {
    pool_keepalive_flow(connection_pool_mgr, pooled_mysql_server)
}
"""

FILES["examples/l7/mysql/mysql_database_use_statement.fasm"] = """// PROMPT: MySQL client setting active database schema context with USE statement.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, DB, COMPILE

// INSTRUCTION: Define database migration runner.
HOST migration_runner { IP 10.35.2.14 }

// INSTRUCTION: Define target corporate MySQL instance.
HOST corp_mysql_db { IP 10.35.2.1 }

// INSTRUCTION: Define database context switch flow.
FLOW switch_db_context_flow(mig, db) {
    mig -> db MYSQL SQL "USE production_sales" DB "production_sales"
}

// INSTRUCTION: Compile database USE statement scenario.
COMPILE {
    switch_db_context_flow(migration_runner, corp_mysql_db)
}
"""

FILES["examples/l7/mysql/mysql_read_replica_status_check.fasm"] = """// PROMPT: MySQL replication monitor querying SHOW REPLICA STATUS on secondary database node.
// TOKENS: HOST, IP, FLOW, ->, MYSQL, SQL, COMPILE

// INSTRUCTION: Define database replication monitor.
HOST repl_monitor { IP 172.24.0.15 }

// INSTRUCTION: Define secondary MySQL replica node.
HOST secondary_replica { IP 172.24.0.2 }

// INSTRUCTION: Define replica status check flow.
FLOW check_replica_flow(mon, rep) {
    mon -> rep MYSQL SQL "SHOW REPLICA STATUS"
}

// INSTRUCTION: Compile read replica status check scenario.
COMPILE {
    check_replica_flow(repl_monitor, secondary_replica)
}
"""


# ==============================================================================
# 9. NetFlow (12 files)
# ==============================================================================
FILES["examples/l7/netflow/netflow_enterprise_edge_exporter.fasm"] = """// PROMPT: Cisco NetFlow v5 export datagram reporting enterprise edge gateway traffic metrics.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define enterprise edge router exporter.
HOST edge_router_exp { IP 10.10.1.1 }

// INSTRUCTION: Define central NetFlow monitoring collector.
HOST central_collector { IP 10.10.1.250 }

// INSTRUCTION: Define edge traffic export flow.
FLOW edge_export_flow(rtr, col) {
    rtr -> col NETFLOW SRCIP 192.168.10.101 DSTIP 172.217.16.206 SRCPORT 54321 DSTPORT 443 PROTO 6 PACKETS 85 OCTETS 114200
}

// INSTRUCTION: Compile enterprise edge NetFlow scenario.
COMPILE {
    edge_export_flow(edge_router_exp, central_collector)
}
"""

FILES["examples/l7/netflow/netflow_mpls_core_transit_metrics.fasm"] = """// PROMPT: NetFlow telemetry exported across MPLS carrier backbone with label tagging.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, MPLS, COMPILE

// INSTRUCTION: Define carrier core router exporter.
HOST core_transit_rtr { IP 192.168.220.1 }

// INSTRUCTION: Define carrier operations flow collector.
HOST carrier_flow_col { IP 192.168.220.254 }

// INSTRUCTION: Define MPLS tagged NetFlow export flow.
FLOW mpls_netflow_export(rtr, col) {
    rtr -> col NETFLOW SRCIP 10.40.1.10 DSTIP 10.50.2.20 PROTO 6 PACKETS 2400 OCTETS 3120000 MPLS 1024
}

// INSTRUCTION: Compile MPLS core transit NetFlow scenario.
COMPILE {
    mpls_netflow_export(core_transit_rtr, carrier_flow_col)
}
"""

FILES["examples/l7/netflow/netflow_vlan_tagged_traffic_analyzer.fasm"] = """// PROMPT: NetFlow telemetry collection over 802.1Q tagged network management VLAN.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define campus distribution switch.
HOST campus_dist_sw { IP 10.15.0.1 }

// INSTRUCTION: Define management VLAN collector on VLAN 105.
HOST mgmt_flow_analyzer { IP 10.15.0.105 }

// INSTRUCTION: Define tagged VLAN NetFlow export flow.
FLOW vlan_netflow_flow(sw, ana) {
    sw -> ana NETFLOW SRCIP 10.10.5.15 DSTIP 10.20.5.25 PROTO 17 PACKETS 42 OCTETS 5376 VLAN 105 PCP 4 DEI 0
}

// INSTRUCTION: Compile VLAN tagged NetFlow scenario.
COMPILE {
    vlan_netflow_flow(campus_dist_sw, mgmt_flow_analyzer)
}
"""

FILES["examples/l7/netflow/netflow_periodic_sampling_loop.fasm"] = """// PROMPT: Periodic NetFlow export timer loop streaming accounting records to collector.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define edge sampling router.
HOST sampling_router { IP 192.168.60.1 }

// INSTRUCTION: Define telemetry server listener.
HOST telemetry_listener { IP 192.168.60.200 }

// INSTRUCTION: Define periodic accounting record flow.
FLOW periodic_accounting_flow(rtr, col) {
    rtr -> col NETFLOW SRCIP 172.16.8.12 DSTIP 198.51.100.44 SRCPORT 80 DSTPORT 41200 PROTO 6 PACKETS 20 OCTETS 28000 WAIT 15ms
}

// INSTRUCTION: Compile periodic NetFlow sampling in loop.
COMPILE {
    LOOP 3 {
        periodic_accounting_flow(sampling_router, telemetry_listener)
    }
}
"""

FILES["examples/l7/netflow/netflow_ipv6_underlay_collector_export.fasm"] = """// PROMPT: Cisco NetFlow telemetry exported over IPv6 transport to centralized monitoring station.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define IPv6 enterprise border router.
HOST v6_border_router { IP 2001:db8:f100::1 }

// INSTRUCTION: Define IPv6 NetFlow monitoring station.
HOST v6_monitoring_station { IP 2001:db8:f100::254 }

// INSTRUCTION: Define IPv6 NetFlow telemetry flow.
FLOW v6_netflow_export(rtr, mon) {
    rtr -> mon NETFLOW SRCIP 10.100.1.1 DSTIP 10.200.1.1 PROTO 6 PACKETS 620 OCTETS 780000
}

// INSTRUCTION: Compile IPv6 underlay NetFlow scenario.
COMPILE {
    v6_netflow_export(v6_border_router, v6_monitoring_station)
}
"""

FILES["examples/l7/netflow/netflow_dscp_marked_telemetry_flow.fasm"] = """// PROMPT: Expedited forwarding DSCP marked NetFlow export packet for high-priority telemetry.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, DSCP, COMPILE

// INSTRUCTION: Define financial exchange gateway router.
HOST exchange_gateway { IP 10.77.1.1 }

// INSTRUCTION: Define high-priority market audit collector.
HOST audit_collector { IP 10.77.1.100 }

// INSTRUCTION: Define DSCP marked telemetry export flow.
FLOW dscp_netflow_export(gw, col) {
    gw -> col NETFLOW SRCIP 10.77.10.5 DSTIP 10.77.20.9 SRCPORT 443 DSTPORT 59123 PROTO 6 PACKETS 500 OCTETS 650000 DSCP 46
}

// INSTRUCTION: Compile DSCP marked NetFlow scenario.
COMPILE {
    dscp_netflow_export(exchange_gateway, audit_collector)
}
"""

FILES["examples/l7/netflow/netflow_udp_custom_collector_port.fasm"] = """// PROMPT: NetFlow export datagram directed to custom UDP collector port 2055 with source port.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define branch office VPN gateway router.
HOST branch_vpn_rtr { IP 172.30.0.1 }

// INSTRUCTION: Define corporate collector on custom port 2055.
HOST custom_netflow_srv { IP 172.30.0.250 }

// INSTRUCTION: Define custom port NetFlow export flow.
FLOW custom_netflow_port_flow(rtr, srv) {
    rtr -> srv NETFLOW SRCIP 10.0.2.14 DSTIP 10.0.4.88 SRCPORT 8080 DSTPORT 49822 PROTO 6 PACKETS 95 OCTETS 124500
}

// INSTRUCTION: Compile custom UDP port NetFlow scenario.
COMPILE {
    custom_netflow_port_flow(branch_vpn_rtr, custom_netflow_srv)
}
"""

FILES["examples/l7/netflow/netflow_web_server_traffic_accounting.fasm"] = """// PROMPT: NetFlow record capturing high-volume HTTP/HTTPS web server client flow accounting.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define web tier load balancer switch.
HOST web_tier_switch { IP 192.168.180.1 }

// INSTRUCTION: Define datacenter traffic accounting collector.
HOST traffic_accounting { IP 192.168.180.200 }

// INSTRUCTION: Define web traffic flow export.
FLOW web_accounting_flow(sw, acc) {
    sw -> acc NETFLOW SRCIP 198.51.100.15 DSTIP 192.168.180.10 SRCPORT 443 DSTPORT 52100 PROTO 6 PACKETS 1800 OCTETS 2450000
}

// INSTRUCTION: Compile web server traffic accounting scenario.
COMPILE {
    web_accounting_flow(web_tier_switch, traffic_accounting)
}
"""

FILES["examples/l7/netflow/netflow_dns_query_volume_telemetry.fasm"] = """// PROMPT: NetFlow record summarizing DNS UDP port 53 query metrics and octet consumption.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define internal DNS resolver router.
HOST dns_router_node { IP 10.128.0.1 }

// INSTRUCTION: Define network analytics flow receiver.
HOST analytics_receiver { IP 10.128.0.254 }

// INSTRUCTION: Define DNS volume NetFlow report flow.
FLOW dns_volume_flow(rtr, rec) {
    rtr -> rec NETFLOW SRCIP 10.128.1.50 DSTIP 8.8.8.8 SRCPORT 53 DSTPORT 60124 PROTO 17 PACKETS 35 OCTETS 2800
}

// INSTRUCTION: Compile DNS query volume scenario.
COMPILE {
    dns_volume_flow(dns_router_node, analytics_receiver)
}
"""

FILES["examples/l7/netflow/netflow_qinq_service_provider_export.fasm"] = """// PROMPT: Metro Ethernet QinQ double-tagged underlay transporting NetFlow accounting packets.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, PROTO, PACKETS, OCTETS, VLAN, COMPILE

// INSTRUCTION: Define service provider aggregation switch.
HOST metro_agg_switch { IP 100.64.50.1 }

// INSTRUCTION: Define carrier billing flow collector.
HOST billing_collector { IP 100.64.50.250 }

// INSTRUCTION: Define QinQ encapsulated NetFlow flow.
FLOW qinq_netflow_export(sw, col) {
    sw -> col NETFLOW SRCIP 100.64.10.1 DSTIP 100.64.20.2 PROTO 6 PACKETS 750 OCTETS 950000 VLAN 200
}

// INSTRUCTION: Compile QinQ service provider NetFlow scenario.
COMPILE {
    qinq_netflow_export(metro_agg_switch, billing_collector)
}
"""

FILES["examples/l7/netflow/netflow_high_packet_volume_audit.fasm"] = """// PROMPT: NetFlow accounting record reporting sustained high packet rate across datacenter spine.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define datacenter spine router exporter.
HOST dc_spine_exporter { IP 10.255.0.1 }

// INSTRUCTION: Define network telemetry storage node.
HOST telemetry_storage { IP 10.255.0.100 }

// INSTRUCTION: Define high packet volume audit flow.
FLOW spine_audit_flow(rtr, stor) {
    rtr -> stor NETFLOW SRCIP 10.1.1.100 DSTIP 10.2.2.200 SRCPORT 9000 DSTPORT 9000 PROTO 6 PACKETS 250000 OCTETS 350000000
}

// INSTRUCTION: Compile high packet volume audit scenario.
COMPILE {
    spine_audit_flow(dc_spine_exporter, telemetry_storage)
}
"""

FILES["examples/l7/netflow/netflow_bgp_peering_transit_accounting.fasm"] = """// PROMPT: Border router NetFlow record tracking inter-domain BGP transit link bandwidth utilization.
// TOKENS: HOST, IP, FLOW, ->, NETFLOW, SRCIP, DSTIP, SRCPORT, DSTPORT, PROTO, PACKETS, OCTETS, COMPILE

// INSTRUCTION: Define Internet exchange peering router.
HOST ix_peering_rtr { IP 203.0.113.1 }

// INSTRUCTION: Define capacity planning flow collector.
HOST capacity_planner { IP 203.0.113.250 }

// INSTRUCTION: Define BGP transit link accounting flow.
FLOW bgp_transit_accounting(ix, col) {
    ix -> col NETFLOW SRCIP 203.0.113.10 DSTIP 198.51.100.88 SRCPORT 179 DSTPORT 179 PROTO 6 PACKETS 1200 OCTETS 1560000
}

// INSTRUCTION: Compile BGP peering transit accounting scenario.
COMPILE {
    bgp_transit_accounting(ix_peering_rtr, capacity_planner)
}
"""


# ==============================================================================
# 10. NFS (12 files)
# ==============================================================================
FILES["examples/l7/nfs/nfs_read_file_block_procedure.fasm"] = """// PROMPT: NFS RPC READ procedure request retrieving 64KB data block from network storage.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, COMPILE

// INSTRUCTION: Define compute cluster node client.
HOST compute_node { IP 10.0.4.15 }

// INSTRUCTION: Define high-performance NFS storage server.
HOST nfs_storage_node { IP 10.0.4.1 }

// INSTRUCTION: Define NFS READ procedure request flow.
FLOW nfs_read_data_flow(cli, srv) {
    cli -> srv NFS VERS 4 PROC "READ" PATH "/data/simulations/run_01.dat"
}

// INSTRUCTION: Compile NFS READ procedure scenario.
COMPILE {
    nfs_read_data_flow(compute_node, nfs_storage_node)
}
"""

FILES["examples/l7/nfs/nfs_write_file_data_procedure.fasm"] = """// PROMPT: NFS RPC WRITE procedure request appending log entries to remote filestore.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, COMPILE

// INSTRUCTION: Define central logging daemon.
HOST logging_daemon { IP 192.168.10.88 }

// INSTRUCTION: Define archive NFS file server.
HOST nfs_archive_srv { IP 192.168.10.2 }

// INSTRUCTION: Define NFS WRITE procedure flow.
FLOW nfs_write_log_flow(log, srv) {
    log -> srv NFS VERS 4 PROC "WRITE" PATH "/exports/logs/system.log"
}

// INSTRUCTION: Compile NFS WRITE procedure scenario.
COMPILE {
    nfs_write_log_flow(logging_daemon, nfs_archive_srv)
}
"""

FILES["examples/l7/nfs/nfs_lookup_directory_hierarchy.fasm"] = """// PROMPT: NFS RPC LOOKUP procedure navigating deep enterprise storage directory paths.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, COMPILE

// INSTRUCTION: Define file browser workstation.
HOST workstation_user { IP 172.16.8.40 }

// INSTRUCTION: Define departmental NFS file server.
HOST nfs_dept_server { IP 172.16.8.1 }

// INSTRUCTION: Define directory lookup request flow.
FLOW nfs_lookup_dir_flow(ws, srv) {
    ws -> srv NFS VERS 4 PROC "LOOKUP" PATH "/shared/engineering/projects/firmware"
}

// INSTRUCTION: Compile NFS LOOKUP hierarchy scenario.
COMPILE {
    nfs_lookup_dir_flow(workstation_user, nfs_dept_server)
}
"""

FILES["examples/l7/nfs/nfs_getattr_metadata_caching.fasm"] = """// PROMPT: NFSv3 GETATTR procedure polling file modification timestamps and POSIX permissions.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, COMPILE

// INSTRUCTION: Define file synchronization worker.
HOST sync_worker { IP 10.20.1.14 }

// INSTRUCTION: Define legacy NFSv3 storage server.
HOST nfs_v3_server { IP 10.20.1.5 }

// INSTRUCTION: Define file attributes lookup flow.
FLOW nfs_getattr_flow(wrk, srv) {
    wrk -> srv NFS VERS 3 PROC "GETATTR" PATH "/vol/shared/docs/spec.pdf"
}

// INSTRUCTION: Compile NFS GETATTR metadata scenario.
COMPILE {
    nfs_getattr_flow(sync_worker, nfs_v3_server)
}
"""

FILES["examples/l7/nfs/nfs_null_procedure_heartbeat_loop.fasm"] = """// PROMPT: NFS NULL procedure RPC ping loop verifying remote storage cluster server availability.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define storage health monitor.
HOST storage_monitor { IP 192.168.50.25 }

// INSTRUCTION: Define enterprise NFS cluster head.
HOST nfs_cluster_head { IP 192.168.50.1 }

// INSTRUCTION: Define periodic NULL RPC ping flow.
FLOW nfs_null_ping_flow(mon, srv) {
    mon -> srv NFS VERS 4 PROC "NULL" WAIT 20ms
}

// INSTRUCTION: Compile NFS heartbeat loop scenario.
COMPILE {
    LOOP 3 {
        nfs_null_ping_flow(storage_monitor, nfs_cluster_head)
    }
}
"""

FILES["examples/l7/nfs/nfs_vlan_tagged_nas_storage.fasm"] = """// PROMPT: Storage area network NFS traffic isolated on dedicated 802.1Q tagged NAS VLAN.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define virtualization hypervisor host.
HOST esxi_hypervisor { IP 10.150.10.20 }

// INSTRUCTION: Define enterprise NAS storage array on VLAN 150.
HOST enterprise_nas { IP 10.150.10.2 }

// INSTRUCTION: Define tagged VLAN storage lookup flow.
FLOW vlan_nfs_lookup(hyp, nas) {
    hyp -> nas NFS VERS 4 PROC "LOOKUP" PATH "/datastores/vm_gold_01" VLAN 150 PCP 6 DEI 0
}

// INSTRUCTION: Compile VLAN tagged NAS storage scenario.
COMPILE {
    vlan_nfs_lookup(esxi_hypervisor, enterprise_nas)
}
"""

FILES["examples/l7/nfs/nfs_ipv6_storage_mount_compound.fasm"] = """// PROMPT: NFSv4 compound RPC procedure mounting remote export root over IPv6 network fabric.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, COMPILE

// INSTRUCTION: Define IPv6 database backup server.
HOST v6_backup_server { IP 2001:db8:ba5e::90 }

// INSTRUCTION: Define IPv6 storage vault server.
HOST v6_storage_vault { IP 2001:db8:ba5e::1 }

// INSTRUCTION: Define IPv6 NFS compound mount flow.
FLOW v6_nfs_mount_flow(bck, srv) {
    bck -> srv NFS VERS 4 PROC "COMPOUND" PATH "/exports/backup/weekly"
}

// INSTRUCTION: Compile IPv6 storage mount scenario.
COMPILE {
    v6_nfs_mount_flow(v6_backup_server, v6_storage_vault)
}
"""

FILES["examples/l7/nfs/nfs_custom_xid_transaction_tracking.fasm"] = """// PROMPT: NFS RPC request specifying unique transaction identifier for asynchronous tracking.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, COMPILE

// INSTRUCTION: Define async file processing worker.
HOST async_worker { IP 172.22.4.15 }

// INSTRUCTION: Define NFS backend server.
HOST nfs_backend { IP 172.22.4.1 }

// INSTRUCTION: Define tracked RPC procedure call flow.
FLOW tracked_rpc_flow(wrk, srv) {
    wrk -> srv NFS VERS 4 PROC "READ" PATH "/processing/queue/job_992"
}

// INSTRUCTION: Compile transaction tracking scenario.
COMPILE {
    tracked_rpc_flow(async_worker, nfs_backend)
}
"""

FILES["examples/l7/nfs/nfs_dscp_prioritized_backup_stream.fasm"] = """// PROMPT: NFS backup stream marked with DSCP lower-effort scavenger priority marking.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, DSCP, COMPILE

// INSTRUCTION: Define secondary backup replication client.
HOST repl_backup_client { IP 10.80.1.18 }

// INSTRUCTION: Define remote DR site NFS server.
HOST dr_nfs_target { IP 10.80.1.2 }

// INSTRUCTION: Define DSCP marked backup write flow.
FLOW dscp_backup_write(cli, tgt) {
    cli -> tgt NFS VERS 4 PROC "WRITE" PATH "/dr/backups/daily_snapshot.tar" DSCP 8
}

// INSTRUCTION: Compile DSCP prioritized backup scenario.
COMPILE {
    dscp_backup_write(repl_backup_client, dr_nfs_target)
}
"""

FILES["examples/l7/nfs/nfs_compound_root_export_traverse.fasm"] = """// PROMPT: NFSv4 compound traverse inspecting export root and mounting user home directory.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, WAIT, ms, COMPILE

// INSTRUCTION: Define login desktop client.
HOST desktop_login_pc { IP 192.168.100.45 }

// INSTRUCTION: Define corporate user fileserver.
HOST user_fileserver { IP 192.168.100.1 }

// INSTRUCTION: Define compound root traversal flow.
FLOW traverse_export_flow(pc, srv) {
    pc -> srv NFS VERS 4 PROC "LOOKUP" PATH "/" WAIT 5ms
    pc -> srv NFS VERS 4 PROC "LOOKUP" PATH "/home/developers"
}

// INSTRUCTION: Compile compound export traverse scenario.
COMPILE {
    traverse_export_flow(desktop_login_pc, user_fileserver)
}
"""

FILES["examples/l7/nfs/nfs_tcp_session_file_attributes.fasm"] = """// PROMPT: TCP 3-way handshake on port 2049 followed by NFS GETATTR metadata procedure call.
// TOKENS: HOST, IP, FLOW, ->, <-, TCP, SYN, ACK, DSTPORT, NFS, VERS, PROC, PATH, WAIT, ms, COMPILE

// INSTRUCTION: Define storage management client.
HOST storage_mgr_client { IP 10.10.80.12 }

// INSTRUCTION: Define NFS daemon listening on port 2049.
HOST nfs_daemon_node { IP 10.10.80.1 }

// INSTRUCTION: Define TCP handshake and NFS getattr flow.
FLOW nfs_tcp_handshake_flow(c, s) {
    c -> s TCP SYN DSTPORT 2049
    c <- s TCP SYN ACK
    c -> s TCP ACK WAIT 1ms
    c -> s NFS VERS 4 PROC "GETATTR" PATH "/exports/production"
}

// INSTRUCTION: Compile TCP session NFS scenario.
COMPILE {
    nfs_tcp_handshake_flow(storage_mgr_client, nfs_daemon_node)
}
"""

FILES["examples/l7/nfs/nfs_storage_cluster_failover_probe.fasm"] = """// PROMPT: High-availability storage client querying primary and backup NFS file controllers.
// TOKENS: HOST, IP, FLOW, ->, NFS, VERS, PROC, PATH, WAIT, ms, COMPILE

// INSTRUCTION: Define HA application client.
HOST ha_app_client { IP 172.28.2.50 }

// INSTRUCTION: Define primary NFS storage controller.
HOST primary_nfs_controller { IP 172.28.2.1 }

// INSTRUCTION: Define secondary backup NFS controller.
HOST secondary_nfs_controller { IP 172.28.2.2 }

// INSTRUCTION: Define failover storage query flow.
FLOW ha_nfs_failover(app, p1, p2) {
    app -> p1 NFS VERS 4 PROC "LOOKUP" PATH "/ha/storage" WAIT 25ms
    app -> p2 NFS VERS 4 PROC "LOOKUP" PATH "/ha/storage"
}

// INSTRUCTION: Compile storage failover probe scenario.
COMPILE {
    ha_nfs_failover(ha_app_client, primary_nfs_controller, secondary_nfs_controller)
}
"""


# ==============================================================================
# 11. NTP (12 files)
# ==============================================================================
FILES["examples/l7/ntp/ntp_stratum2_regional_time_sync.fasm"] = """// PROMPT: NTP client synchronization with regional Stratum 2 time server over UDP 123.
// TOKENS: HOST, IP, FLOW, ->, <-, NTP, MODE, VN, STRATUM, POLL, WAIT, ms, COMPILE

// INSTRUCTION: Define campus time client workstation.
HOST campus_client { IP 192.168.1.150 }

// INSTRUCTION: Define regional Stratum 2 time server.
HOST regional_stratum2 { IP 192.168.1.1 }

// INSTRUCTION: Define NTP client request and server response flow.
FLOW stratum2_sync_flow(c, s) {
    c -> s NTP MODE 3 VN 4 STRATUM 0 POLL 6 WAIT 10ms
    c <- s NTP MODE 4 VN 4 STRATUM 2 POLL 6
}

// INSTRUCTION: Compile Stratum 2 time sync scenario.
COMPILE {
    stratum2_sync_flow(campus_client, regional_stratum2)
}
"""

FILES["examples/l7/ntp/ntp_broadcast_mode_local_subnet.fasm"] = """// PROMPT: NTP server broadcast mode 5 distributing periodic clock beacons to local subnet.
// TOKENS: HOST, IP, FLOW, ->, NTP, MODE, VN, STRATUM, POLL, COMPILE

// INSTRUCTION: Define local subnet master clock server.
HOST subnet_clock_server { IP 10.0.10.1 }

// INSTRUCTION: Define local subnet broadcast address.
HOST subnet_broadcast { IP 10.0.10.255 }

// INSTRUCTION: Define NTP broadcast mode transmission flow.
FLOW ntp_broadcast_flow(srv, bcast) {
    srv -> bcast NTP MODE 5 VN 4 STRATUM 1 POLL 6
}

// INSTRUCTION: Compile NTP broadcast mode scenario.
COMPILE {
    ntp_broadcast_flow(subnet_clock_server, subnet_broadcast)
}
"""

FILES["examples/l7/ntp/ntp_symmetric_active_peer_exchange.fasm"] = """// PROMPT: NTP symmetric active mode 1 peer clock coordination between core routers.
// TOKENS: HOST, IP, FLOW, ->, <-, NTP, MODE, VN, STRATUM, POLL, PRECISION, WAIT, ms, COMPILE

// INSTRUCTION: Define core router time peer Alpha.
HOST router_peer_alpha { IP 172.16.0.1 }

// INSTRUCTION: Define core router time peer Beta.
HOST router_peer_beta { IP 172.16.0.2 }

// INSTRUCTION: Define symmetric active peer exchange flow.
FLOW symmetric_peer_flow(a, b) {
    a -> b NTP MODE 1 VN 4 STRATUM 2 POLL 6 PRECISION -20 WAIT 15ms
    a <- b NTP MODE 2 VN 4 STRATUM 2 POLL 6 PRECISION -20
}

// INSTRUCTION: Compile symmetric peer exchange scenario.
COMPILE {
    symmetric_peer_flow(router_peer_alpha, router_peer_beta)
}
"""

FILES["examples/l7/ntp/ntp_high_precision_pps_atomic_clock.fasm"] = """// PROMPT: Stratum 1 atomic time reference server response with pulse-per-second precision.
// TOKENS: HOST, IP, FLOW, <-, NTP, MODE, VN, STRATUM, PRECISION, REFID, COMPILE

// INSTRUCTION: Define enterprise time synchronization client.
HOST enterprise_sync_client { IP 10.20.1.88 }

// INSTRUCTION: Define Stratum 1 atomic clock reference node.
HOST atomic_pps_server { IP 10.20.1.1 }

// INSTRUCTION: Define PPS atomic reference response flow.
FLOW pps_atomic_response(cli, srv) {
    cli <- srv NTP MODE 4 VN 4 STRATUM 1 PRECISION -24 REFID "PPS"
}

// INSTRUCTION: Compile PPS atomic clock response scenario.
COMPILE {
    pps_atomic_response(enterprise_sync_client, atomic_pps_server)
}
"""

FILES["examples/l7/ntp/ntp_periodic_clock_poll_loop.fasm"] = """// PROMPT: Continuous NTP time client synchronization poll loop executed in compile block.
// TOKENS: HOST, IP, FLOW, ->, <-, NTP, MODE, VN, STRATUM, POLL, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define network time sync daemon.
HOST timed_daemon { IP 192.168.100.50 }

// INSTRUCTION: Define enterprise NTP server node.
HOST ntp_server_node { IP 192.168.100.1 }

// INSTRUCTION: Define periodic poll cycle flow.
FLOW periodic_ntp_poll(c, s) {
    c -> s NTP MODE 3 VN 4 STRATUM 0 POLL 4 WAIT 5ms
    c <- s NTP MODE 4 VN 4 STRATUM 2 POLL 4 WAIT 15ms
}

// INSTRUCTION: Compile periodic clock poll in loop.
COMPILE {
    LOOP 3 {
        periodic_ntp_poll(timed_daemon, ntp_server_node)
    }
}
"""

FILES["examples/l7/ntp/ntp_vlan_tagged_infrastructure_sync.fasm"] = """// PROMPT: Network infrastructure clock synchronization isolated on dedicated 802.1Q management VLAN.
// TOKENS: HOST, IP, FLOW, ->, NTP, MODE, VN, STRATUM, POLL, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define top of rack management switch.
HOST tor_mgmt_switch { IP 10.88.10.15 }

// INSTRUCTION: Define datacenter grandmaster clock on VLAN 200.
HOST grandmaster_clock { IP 10.88.10.1 }

// INSTRUCTION: Define tagged VLAN NTP client request flow.
FLOW vlan_ntp_sync(sw, gm) {
    sw -> gm NTP MODE 3 VN 4 STRATUM 0 POLL 6 VLAN 200 PCP 6 DEI 0
}

// INSTRUCTION: Compile VLAN infrastructure sync scenario.
COMPILE {
    vlan_ntp_sync(tor_mgmt_switch, grandmaster_clock)
}
"""

FILES["examples/l7/ntp/ntp_ipv6_enterprise_stratum_sync.fasm"] = """// PROMPT: Enterprise workstation synchronizing time with internal Stratum 1 server across IPv6.
// TOKENS: HOST, IP, FLOW, ->, <-, NTP, MODE, VN, STRATUM, REFID, WAIT, ms, COMPILE

// INSTRUCTION: Define IPv6 enterprise workstation.
HOST v6_client_node { IP 2001:db8:710e::88 }

// INSTRUCTION: Define IPv6 Stratum 1 atomic time server.
HOST v6_atomic_server { IP 2001:db8:710e::1 }

// INSTRUCTION: Define IPv6 NTP exchange flow.
FLOW v6_ntp_exchange(c, s) {
    c -> s NTP MODE 3 VN 4 STRATUM 0 WAIT 8ms
    c <- s NTP MODE 4 VN 4 STRATUM 1 REFID "GPS"
}

// INSTRUCTION: Compile IPv6 enterprise sync scenario.
COMPILE {
    v6_ntp_exchange(v6_client_node, v6_atomic_server)
}
"""

FILES["examples/l7/ntp/ntp_leap_indicator_warning_state.fasm"] = """// PROMPT: NTP server response signaling upcoming leap second insertion with leap indicator 1.
// TOKENS: HOST, IP, FLOW, <-, NTP, LI, VN, MODE, STRATUM, REFID, COMPILE

// INSTRUCTION: Define reference clock client listener.
HOST clock_listener { IP 172.24.1.45 }

// INSTRUCTION: Define national time laboratory server.
HOST nist_time_server { IP 172.24.1.1 }

// INSTRUCTION: Define leap second warning response flow.
FLOW leap_warning_response(cli, srv) {
    cli <- srv NTP LI 1 VN 4 MODE 4 STRATUM 1 REFID "ACTS"
}

// INSTRUCTION: Compile leap indicator warning scenario.
COMPILE {
    leap_warning_response(clock_listener, nist_time_server)
}
"""

FILES["examples/l7/ntp/ntp_custom_poll_interval_negotiation.fasm"] = """// PROMPT: NTP client requesting fine-grained 16-second poll interval log2 4 for clock convergence.
// TOKENS: HOST, IP, FLOW, ->, NTP, MODE, VN, STRATUM, POLL, PRECISION, COMPILE

// INSTRUCTION: Define precision financial trading host.
HOST trading_server { IP 10.60.1.20 }

// INSTRUCTION: Define low-latency local time source.
HOST local_time_source { IP 10.60.1.1 }

// INSTRUCTION: Define short poll interval request flow.
FLOW short_poll_req_flow(trd, srv) {
    trd -> srv NTP MODE 3 VN 4 STRATUM 0 POLL 4 PRECISION -20
}

// INSTRUCTION: Compile custom poll interval scenario.
COMPILE {
    short_poll_req_flow(trading_server, local_time_source)
}
"""

FILES["examples/l7/ntp/ntp_dscp_expedited_forwarding_sync.fasm"] = """// PROMPT: High-precision NTP clock sync packets prioritized with DSCP Expedited Forwarding.
// TOKENS: HOST, IP, FLOW, ->, NTP, MODE, VN, STRATUM, POLL, DSCP, COMPILE

// INSTRUCTION: Define telecommunications base station clock.
HOST bts_clock_client { IP 192.168.250.10 }

// INSTRUCTION: Define carrier primary reference clock.
HOST carrier_prc_server { IP 192.168.250.1 }

// INSTRUCTION: Define DSCP marked NTP request flow.
FLOW dscp_ntp_request(bts, prc) {
    bts -> prc NTP MODE 3 VN 4 STRATUM 0 POLL 5 DSCP 46
}

// INSTRUCTION: Compile DSCP expedited forwarding sync scenario.
COMPILE {
    dscp_ntp_request(bts_clock_client, carrier_prc_server)
}
"""

FILES["examples/l7/ntp/ntp_client_request_precision_time.fasm"] = """// PROMPT: NTP client request transmitting 64-bit transmit timestamp to NTP time server.
// TOKENS: HOST, IP, FLOW, ->, NTP, MODE, VN, STRATUM, TX_TIMESTAMP, COMPILE

// INSTRUCTION: Define timestamping client device.
HOST timestamp_client { IP 10.10.10.55 }

// INSTRUCTION: Define network time protocol server.
HOST ntp_clock_server { IP 10.10.10.1 }

// INSTRUCTION: Define timestamped request flow.
FLOW timestamped_ntp_req(cli, srv) {
    cli -> srv NTP MODE 3 VN 4 STRATUM 0 TX_TIMESTAMP 16500000000000000000
}

// INSTRUCTION: Compile client request precision time scenario.
COMPILE {
    timestamped_ntp_req(timestamp_client, ntp_clock_server)
}
"""

FILES["examples/l7/ntp/ntp_stratum1_rubidium_clock_source.fasm"] = """// PROMPT: Stratum 1 server response referencing synchronized Rubidium atomic frequency standard.
// TOKENS: HOST, IP, FLOW, <-, NTP, MODE, VN, STRATUM, REFID, PRECISION, COMPILE

// INSTRUCTION: Define mission control time receiver.
HOST mission_control { IP 192.168.0.50 }

// INSTRUCTION: Define rubidium atomic frequency reference.
HOST rubidium_server { IP 192.168.0.1 }

// INSTRUCTION: Define rubidium reference response flow.
FLOW rubidium_response_flow(mc, srv) {
    mc <- srv NTP MODE 4 VN 4 STRATUM 1 REFID "ATOM" PRECISION -22
}

// INSTRUCTION: Compile Rubidium clock source scenario.
COMPILE {
    rubidium_response_flow(mission_control, rubidium_server)
}
"""


def main():
    print(f"Total files to generate: {len(FILES)}")
    assert len(FILES) == 132, f"Expected 132 files, got {len(FILES)}"

    # Check that each file satisfies line length requirements and formatting
    for path, content in sorted(FILES.items()):
        # Write file
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        lines = content.splitlines()
        assert len(lines) >= 3, f"{path}: file too short"
        assert lines[0].startswith("// PROMPT: "), f"{path}: line 1 missing PROMPT"
        assert lines[1].startswith("// TOKENS: "), f"{path}: line 2 missing TOKENS"
        assert "// INSTRUCTION:" in content, f"{path}: missing INSTRUCTION comments"

        filename = os.path.basename(path)
        assert not filename[0].isdigit(), f"{path}: filename starts with digit"

        lengths = [len(l) for l in lines]
        avg_l = sum(lengths) / len(lengths)
        max_l = max(lengths)
        if avg_l > 85:
            print(f"ERROR: {path} avg_line_length = {avg_l:.2f} > 85")
            sys.exit(1)
        if max_l > 200:
            print(f"ERROR: {path} max_line_length = {max_l} > 200")
            sys.exit(1)

    print("All 132 files written and verified for headers and line length constraints.")

    # Now verify compilation with target/debug/frameassembly
    bin_path = "target/debug/frameassembly"
    temp_pcap = "/tmp/shard5_test.pcap"
    failed = []

    for path in sorted(FILES.keys()):
        cmd = [bin_path, path, "-o", temp_pcap]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            failed.append((path, res.stderr or res.stdout))
        else:
            if not os.path.exists(temp_pcap) or os.path.getsize(temp_pcap) == 0:
                failed.append((path, "PCAP file 0 bytes"))
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)

    if failed:
        print(f"FAILED: {len(failed)} files failed compilation:")
        for path, err in failed:
            print(f"  {path}: {err}")
        sys.exit(1)
    else:
        print(f"SUCCESS: All {len(FILES)} files successfully compiled into non-empty PCAP files!")


if __name__ == "__main__":
    main()
