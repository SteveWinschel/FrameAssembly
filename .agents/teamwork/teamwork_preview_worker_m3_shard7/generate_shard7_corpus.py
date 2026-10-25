#!/usr/bin/env python3
import os
import subprocess
import sys

def verify_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    lines = content.splitlines()
    if len(lines) < 3:
        return False, "File too short"
    if not lines[0].startswith("// PROMPT: "):
        return False, "Line 1 does not start with // PROMPT: "
    if not lines[1].startswith("// TOKENS: "):
        return False, "Line 2 does not start with // TOKENS: "
    if "// INSTRUCTION:" not in content:
        return False, "Missing // INSTRUCTION: comments"
    
    lengths = [len(l) for l in lines]
    max_l = max(lengths) if lengths else 0
    avg_l = sum(lengths) / len(lengths) if lengths else 0
    if max_l > 200:
        return False, f"max_line_length ({max_l}) > 200"
    if avg_l > 85:
        return False, f"avg_line_length ({avg_l:.1f}) > 85"
    
    # Test compilation
    res = subprocess.run(["./target/debug/frameassembly", filepath, "-o", "/tmp/shard7_verify.pcap"], capture_output=True, text=True)
    if res.returncode != 0:
        return False, f"Compilation error: {res.stderr or res.stdout}"
    
    if not os.path.exists("/tmp/shard7_verify.pcap") or os.path.getsize("/tmp/shard7_verify.pcap") == 0:
        return False, "Generated PCAP is 0 bytes"
    
    return True, "OK"

# We will populate scenarios in a structured way
files_data = {}

# ==========================================
# 1. SMTP (12 new files)
# ==========================================
files_data["examples/l7/smtp/smtp_auth_login_credentials.fasm"] = """// PROMPT: SMTP client authenticating via AUTH LOGIN mechanism with Base64 credentials.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, CMD, PARAM, CODE, REPLY, COMPILE

// INSTRUCTION: Define email client workstation.
HOST mail_client { IP 10.10.10.25 }

// INSTRUCTION: Define corporate mail relay server.
HOST mail_relay { IP 10.10.10.1 }

// INSTRUCTION: Define SMTP authentication handshake flow.
FLOW smtp_auth_flow(c, s) {
    c -> s SMTP CMD "AUTH" PARAM "LOGIN"
    c <- s SMTP CODE 334 REPLY "VXNlcm5hbWU6"
    c -> s SMTP CMD "dGVzdHVzZXI="
    c <- s SMTP CODE 334 REPLY "UGFzc3dvcmQ6"
    c -> s SMTP CMD "U2VjcmV0MTIz"
    c <- s SMTP CODE 235 REPLY "2.7.0 Authentication successful"
}

// INSTRUCTION: Compile block executing authentication session.
COMPILE {
    smtp_auth_flow(mail_client, mail_relay)
}
"""

files_data["examples/l7/smtp/smtp_starttls_encryption_upgrade.fasm"] = """// PROMPT: Opportunistic TLS upgrade using STARTTLS command and 220 server confirmation.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, CMD, CODE, REPLY, COMPILE

// INSTRUCTION: Define sending MTA node.
HOST sending_mta { IP 192.168.12.10 }

// INSTRUCTION: Define receiving MTA node.
HOST receiving_mta { IP 192.168.12.1 }

// INSTRUCTION: Define STARTTLS protocol negotiation flow.
FLOW smtp_starttls_flow(c, s) {
    c -> s SMTP EHLO "mta1.internal.net"
    c <- s SMTP CODE 250 REPLY "mta2.internal.net Hello, STARTTLS supported"
    c -> s SMTP CMD "STARTTLS"
    c <- s SMTP CODE 220 REPLY "2.0.0 Ready to start TLS"
}

// INSTRUCTION: Compile block executing STARTTLS upgrade.
COMPILE {
    smtp_starttls_flow(sending_mta, receiving_mta)
}
"""

files_data["examples/l7/smtp/smtp_recipient_rejected_relay_denied.fasm"] = """// PROMPT: Outbound mail relay rejection with 550 Relaying Denied error reply.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, MAIL_FROM, RCPT_TO, PARAM, CODE, REPLY, QUIT, COMPILE

// INSTRUCTION: Define untrusted external client.
HOST untrusted_client { IP 203.0.113.88 }

// INSTRUCTION: Define border mail gateway.
HOST border_gateway { IP 198.51.100.25 }

// INSTRUCTION: Define unauthorized relay rejection flow.
FLOW smtp_relay_denied_flow(c, s) {
    c -> s SMTP MAIL_FROM PARAM "spammer@external.org"
    c <- s SMTP CODE 250 REPLY "2.1.0 Sender ok"
    c -> s SMTP RCPT_TO PARAM "victim@remote-domain.com"
    c <- s SMTP CODE 550 REPLY "5.7.1 Relaying denied: authentication required"
    c -> s SMTP QUIT
}

// INSTRUCTION: Compile block executing relay rejection flow.
COMPILE {
    smtp_relay_denied_flow(untrusted_client, border_gateway)
}
"""

files_data["examples/l7/smtp/smtp_mailbox_unavailable_soft_bounce.fasm"] = """// PROMPT: Mail delivery temporary delay with 450 Mailbox Busy try again later response.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, MAIL_FROM, RCPT_TO, PARAM, CODE, REPLY, COMPILE

// INSTRUCTION: Define delivery dispatch MTA.
HOST dispatch_mta { IP 172.24.0.15 }

// INSTRUCTION: Define mailbox destination server.
HOST mailbox_server { IP 172.24.0.2 }

// INSTRUCTION: Define temporary soft bounce delivery delay flow.
FLOW smtp_soft_bounce_flow(c, s) {
    c -> s SMTP MAIL_FROM PARAM "billing@service.com"
    c <- s SMTP CODE 250 REPLY "2.1.0 Sender ok"
    c -> s SMTP RCPT_TO PARAM "accounting@corp.local"
    c <- s SMTP CODE 450 REPLY "4.2.1 Mailbox busy, recipient concurrency exceeded"
}

// INSTRUCTION: Compile block executing soft bounce flow.
COMPILE {
    smtp_soft_bounce_flow(dispatch_mta, mailbox_server)
}
"""

files_data["examples/l7/smtp/smtp_vrfy_user_query.fasm"] = """// PROMPT: Address verification query using VRFY and 250 verified user mailbox response.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, CMD, PARAM, CODE, REPLY, COMPILE

// INSTRUCTION: Define auditing host endpoint.
HOST auditor_host { IP 10.45.1.9 }

// INSTRUCTION: Define directory mail agent.
HOST directory_mta { IP 10.45.1.2 }

// INSTRUCTION: Define user verification query flow.
FLOW smtp_vrfy_flow(c, s) {
    c -> s SMTP CMD "VRFY" PARAM "postmaster"
    c <- s SMTP CODE 250 REPLY "Postmaster <postmaster@directory.internal>"
    c -> s SMTP CMD "VRFY" PARAM "unknown_user_99"
    c <- s SMTP CODE 550 REPLY "5.1.1 User not found in directory"
}

// INSTRUCTION: Compile block executing VRFY verification.
COMPILE {
    smtp_vrfy_flow(auditor_host, directory_mta)
}
"""

files_data["examples/l7/smtp/smtp_expn_distribution_list.fasm"] = """// PROMPT: Mailing list membership expansion query using EXPN command.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, CMD, PARAM, CODE, REPLY, COMPILE

// INSTRUCTION: Define admin management workstation.
HOST admin_station { IP 172.19.4.12 }

// INSTRUCTION: Define campus listserv server.
HOST campus_listserv { IP 172.19.4.1 }

// INSTRUCTION: Define list expansion command flow.
FLOW smtp_expn_flow(c, s) {
    c -> s SMTP CMD "EXPN" PARAM "sysadmins"
    c <- s SMTP CODE 250 REPLY "lead-admin@campus.edu"
    c -> s SMTP CMD "EXPN" PARAM "secops"
    c <- s SMTP CODE 250 REPLY "soc-oncall@campus.edu"
}

// INSTRUCTION: Compile block executing EXPN query.
COMPILE {
    smtp_expn_flow(admin_station, campus_listserv)
}
"""

files_data["examples/l7/smtp/smtp_pipelining_reset_transaction.fasm"] = """// PROMPT: Pipelined transaction abort and reset using RSET command followed by new envelope.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, CMD, MAIL_FROM, RCPT_TO, PARAM, CODE, REPLY, COMPILE

// INSTRUCTION: Define newsletter dispatch MTA.
HOST dispatch_node { IP 192.168.105.10 }

// INSTRUCTION: Define enterprise MX receiver.
HOST mx_receiver { IP 192.168.105.1 }

// INSTRUCTION: Define RSET abort and retry flow.
FLOW smtp_reset_flow(c, s) {
    c -> s SMTP MAIL_FROM PARAM "wrong-sender@newsletter.com"
    c <- s SMTP CODE 250 REPLY "2.1.0 Sender ok"
    c -> s SMTP CMD "RSET"
    c <- s SMTP CODE 250 REPLY "2.0.0 Reset state OK"
    c -> s SMTP MAIL_FROM PARAM "correct-sender@newsletter.com"
    c <- s SMTP CODE 250 REPLY "2.1.0 Sender ok"
}

// INSTRUCTION: Compile block executing transaction reset.
COMPILE {
    smtp_reset_flow(dispatch_node, mx_receiver)
}
"""

files_data["examples/l7/smtp/smtp_service_ready_initial_banner.fasm"] = """// PROMPT: Mail transfer agent greeting client with 220 ESMTP service ready banner.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, CODE, REPLY, EHLO, COMPILE

// INSTRUCTION: Define client connection node.
HOST mta_client { IP 10.60.2.14 }

// INSTRUCTION: Define authoritative inbound mail server.
HOST inbound_mx { IP 10.60.2.25 }

// INSTRUCTION: Define initial SMTP greeting and EHLO handshake flow.
FLOW smtp_greeting_flow(c, s) {
    c <- s SMTP CODE 220 REPLY "mx1.enterprise.net ESMTP ready at Wed, 24 Oct 2026"
    c -> s SMTP EHLO "mta-client.network.org"
    c <- s SMTP CODE 250 REPLY "mx1.enterprise.net greets mta-client.network.org"
}

// INSTRUCTION: Compile block executing banner exchange.
COMPILE {
    smtp_greeting_flow(mta_client, inbound_mx)
}
"""

files_data["examples/l7/smtp/smtp_size_limit_exceeded_error.fasm"] = """// PROMPT: Mail transaction aborted due to 552 Message size exceeds administrative limit.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, MAIL_FROM, RCPT_TO, PARAM, CODE, REPLY, BODY, COMPILE

// INSTRUCTION: Define branch office mail client.
HOST branch_client { IP 172.30.15.4 }

// INSTRUCTION: Define regional hub mail server.
HOST regional_hub { IP 172.30.15.1 }

// INSTRUCTION: Define oversized message rejection flow.
FLOW smtp_size_limit_flow(c, s) {
    c -> s SMTP MAIL_FROM PARAM "reporter@branch.net"
    c <- s SMTP CODE 250 REPLY "2.1.0 Sender accepted"
    c -> s SMTP RCPT_TO PARAM "archive@regional.net"
    c <- s SMTP CODE 250 REPLY "2.1.5 Recipient accepted"
    c -> s SMTP BODY "Oversized attachment payload data..."
    c <- s SMTP CODE 552 REPLY "5.3.4 Error: message file too big (max 10MB)"
}

// INSTRUCTION: Compile block executing size limit rejection.
COMPILE {
    smtp_size_limit_flow(branch_client, regional_hub)
}
"""

files_data["examples/l7/smtp/smtp_service_closing_transmission_channel.fasm"] = """// PROMPT: Clean session termination using QUIT and 221 Service closing channel reply.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, QUIT, CODE, REPLY, COMPILE

// INSTRUCTION: Define monitoring poller agent.
HOST poller_agent { IP 192.168.80.70 }

// INSTRUCTION: Define production SMTP daemon.
HOST smtp_daemon { IP 192.168.80.25 }

// INSTRUCTION: Define clean QUIT termination flow.
FLOW smtp_quit_flow(c, s) {
    c -> s SMTP EHLO "poller.healthcheck.local"
    c <- s SMTP CODE 250 REPLY "smtp.daemon.local Hello"
    c -> s SMTP QUIT
    c <- s SMTP CODE 221 REPLY "2.0.0 smtp.daemon.local closing transmission channel"
}

// INSTRUCTION: Compile block executing clean QUIT flow.
COMPILE {
    smtp_quit_flow(poller_agent, smtp_daemon)
}
"""

files_data["examples/l7/smtp/smtp_help_command_supported_extensions.fasm"] = """// PROMPT: Administrative HELP query receiving 214 list of supported ESMTP extensions.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, CMD, CODE, REPLY, COMPILE

// INSTRUCTION: Define diagnosis probe client.
HOST probe_client { IP 10.99.1.55 }

// INSTRUCTION: Define standard compliance server.
HOST compliance_mta { IP 10.99.1.1 }

// INSTRUCTION: Define SMTP HELP command flow.
FLOW smtp_help_flow(c, s) {
    c -> s SMTP CMD "HELP"
    c <- s SMTP CODE 214 REPLY "2.1.4 Supported: 8BITMIME SIZE PIPELINING STARTTLS"
    c -> s SMTP CMD "NOOP"
    c <- s SMTP CODE 250 REPLY "2.0.0 OK"
}

// INSTRUCTION: Compile block executing HELP query.
COMPILE {
    smtp_help_flow(probe_client, compliance_mta)
}
"""

files_data["examples/l7/smtp/smtp_ipv6_mx_notification_delivery.fasm"] = """// PROMPT: Automated IPv6 system status alert delivery over ESMTP port 25.
// TOKENS: HOST, IP, FLOW, ->, <-, SMTP, MAIL_FROM, RCPT_TO, PARAM, CODE, REPLY, BODY, QUIT, COMPILE

// INSTRUCTION: Define IPv6 monitoring server endpoint.
HOST alert_sender_v6 { IP 2001:db8:feed::50 }

// INSTRUCTION: Define IPv6 destination MX server.
HOST alert_receiver_v6 { IP 2001:db8:feed::1 }

// INSTRUCTION: Define IPv6 notification delivery transaction flow.
FLOW smtp_v6_alert_flow(c, s) {
    c -> s SMTP MAIL_FROM PARAM "mon-daemon@ipv6-infra.net"
    c <- s SMTP CODE 250 REPLY "2.1.0 Sender ok"
    c -> s SMTP RCPT_TO PARAM "noc-ops@ipv6-infra.net"
    c <- s SMTP CODE 250 REPLY "2.1.5 Recipient ok"
    c -> s SMTP BODY "Subject: NOC Alert\r\n\r\nCore interface BGP peer online."
    c <- s SMTP CODE 250 REPLY "2.0.0 Queued"
    c -> s SMTP QUIT
}

// INSTRUCTION: Compile block executing IPv6 alert flow.
COMPILE {
    smtp_v6_alert_flow(alert_sender_v6, alert_receiver_v6)
}
"""

# ==========================================
# 2. SSDP (12 new files)
# ==========================================
files_data["examples/l7/ssdp/ssdp_media_renderer_search.fasm"] = """// PROMPT: SSDP M-SEARCH query discovering UPnP MediaRenderer devices.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, COMPILE

// INSTRUCTION: Define control point client endpoint.
HOST cp_client { IP 192.168.1.105 }

// INSTRUCTION: Define SSDP IPv4 multicast destination.
HOST ssdp_mcast { IP 239.255.255.250 }

// INSTRUCTION: Define MediaRenderer discovery search flow.
FLOW ssdp_renderer_flow(c, s) {
    c -> s SSDP MSEARCH
        ST "urn:schemas-upnp-org:device:MediaRenderer:1"
        MX 3 MAN "\\"ssdp:discover\\""
}

// INSTRUCTION: Compile block executing MediaRenderer search.
COMPILE {
    ssdp_renderer_flow(cp_client, ssdp_mcast)
}
"""

files_data["examples/l7/ssdp/ssdp_media_server_discovery.fasm"] = """// PROMPT: SSDP M-SEARCH broadcast locating DLNA MediaServer storage appliances.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, COMPILE

// INSTRUCTION: Define smart TV control point.
HOST smart_tv { IP 192.168.2.40 }

// INSTRUCTION: Define SSDP multicast group.
HOST upnp_multicast { IP 239.255.255.250 }

// INSTRUCTION: Define MediaServer discovery query flow.
FLOW ssdp_server_flow(c, s) {
    c -> s SSDP MSEARCH
        ST "urn:schemas-upnp-org:device:MediaServer:1"
        MX 2 MAN "\\"ssdp:discover\\""
}

// INSTRUCTION: Compile block executing MediaServer search.
COMPILE {
    ssdp_server_flow(smart_tv, upnp_multicast)
}
"""

files_data["examples/l7/ssdp/ssdp_internet_gateway_device.fasm"] = """// PROMPT: Gateway discovery query targeting UPnP InternetGatewayDevice services.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, COMPILE

// INSTRUCTION: Define residential client workstation.
HOST resident_pc { IP 10.0.1.75 }

// INSTRUCTION: Define SSDP multicast address.
HOST mcast_group { IP 239.255.255.250 }

// INSTRUCTION: Define InternetGatewayDevice discovery flow.
FLOW ssdp_igd_flow(c, s) {
    c -> s SSDP MSEARCH
        ST "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
        MX 5 MAN "\\"ssdp:discover\\""
}

// INSTRUCTION: Compile block executing IGD search.
COMPILE {
    ssdp_igd_flow(resident_pc, mcast_group)
}
"""

files_data["examples/l7/ssdp/ssdp_wan_ip_connection_service.fasm"] = """// PROMPT: Router WAN IP connection service query using ST urn:schemas-upnp-org:service:WANIPConnection:1.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, COMPILE

// INSTRUCTION: Define port mapping client.
HOST mapping_client { IP 192.168.10.82 }

// INSTRUCTION: Define UPnP multicast destination.
HOST igd_mcast { IP 239.255.255.250 }

// INSTRUCTION: Define WAN IP service discovery flow.
FLOW ssdp_wanip_flow(c, s) {
    c -> s SSDP MSEARCH
        ST "urn:schemas-upnp-org:service:WANIPConnection:1"
        MX 2 MAN "\\"ssdp:discover\\""
}

// INSTRUCTION: Compile block executing WAN IP discovery.
COMPILE {
    ssdp_wanip_flow(mapping_client, igd_mcast)
}
"""

files_data["examples/l7/ssdp/ssdp_notify_byebye_shutdown.fasm"] = """// PROMPT: Device graceful shutdown notification using NTS ssdp:byebye.
// TOKENS: HOST, IP, FLOW, ->, SSDP, NOTIFY, NT, NTS, USN, COMPILE

// INSTRUCTION: Define departing printer node.
HOST printer_node { IP 192.168.1.50 }

// INSTRUCTION: Define multicast notification group.
HOST ssdp_broadcast { IP 239.255.255.250 }

// INSTRUCTION: Define device shutdown departure flow.
FLOW ssdp_byebye_flow(c, s) {
    c -> s SSDP NOTIFY
        NT "urn:schemas-upnp-org:device:Printer:1"
        NTS "ssdp:byebye"
        USN "uuid:print-lab-uuid::urn:schemas-upnp-org:device:Printer:1"
}

// INSTRUCTION: Compile block executing byebye advertisement.
COMPILE {
    ssdp_byebye_flow(printer_node, ssdp_broadcast)
}
"""

files_data["examples/l7/ssdp/ssdp_notify_update_service.fasm"] = """// PROMPT: Device service configuration update notification using NTS ssdp:update.
// TOKENS: HOST, IP, FLOW, ->, SSDP, NOTIFY, NT, NTS, USN, LOCATION, COMPILE

// INSTRUCTION: Define multimedia gateway device.
HOST gateway_dev { IP 10.200.1.1 }

// INSTRUCTION: Define SSDP multicast destination.
HOST mcast_endpoint { IP 239.255.255.250 }

// INSTRUCTION: Define service configuration update flow.
FLOW ssdp_update_flow(c, s) {
    c -> s SSDP NOTIFY
        NT "upnp:rootdevice"
        NTS "ssdp:update"
        USN "uuid:media-gw-9900::upnp:rootdevice"
        LOCATION "http://10.200.1.1:8080/desc.xml"
}

// INSTRUCTION: Compile block executing update notification.
COMPILE {
    ssdp_update_flow(gateway_dev, mcast_endpoint)
}
"""

files_data["examples/l7/ssdp/ssdp_smart_tv_dial_service.fasm"] = """// PROMPT: Second-screen DIAL multiscreen protocol discovery query on multicast port 1900.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, COMPILE

// INSTRUCTION: Define mobile phone control client.
HOST mobile_client { IP 192.168.3.18 }

// INSTRUCTION: Define SSDP multicast destination address.
HOST dial_mcast { IP 239.255.255.250 }

// INSTRUCTION: Define DIAL multi-screen service discovery flow.
FLOW ssdp_dial_flow(c, s) {
    c -> s SSDP MSEARCH
        ST "urn:dial-multiscreen-org:service:dial:1"
        MX 3 MAN "\\"ssdp:discover\\""
}

// INSTRUCTION: Compile block executing DIAL search.
COMPILE {
    ssdp_dial_flow(mobile_client, dial_mcast)
}
"""

files_data["examples/l7/ssdp/ssdp_printers_embedded_device.fasm"] = """// PROMPT: Network printer device discovery targeting UPnP Printer device schema.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, COMPILE

// INSTRUCTION: Define office desktop endpoint.
HOST office_pc { IP 172.16.8.95 }

// INSTRUCTION: Define multicast query group.
HOST ssdp_group { IP 239.255.255.250 }

// INSTRUCTION: Define office printer discovery flow.
FLOW ssdp_printer_search(c, s) {
    c -> s SSDP MSEARCH
        ST "urn:schemas-upnp-org:device:Printer:1"
        MX 4 MAN "\\"ssdp:discover\\""
}

// INSTRUCTION: Compile block executing printer discovery.
COMPILE {
    ssdp_printer_search(office_pc, ssdp_group)
}
"""

files_data["examples/l7/ssdp/ssdp_home_automation_iot_sensor.fasm"] = """// PROMPT: Smart home IoT sensor discovery query targeting Basic device schema.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, COMPILE

// INSTRUCTION: Define IoT controller hub.
HOST iot_hub { IP 192.168.50.2 }

// INSTRUCTION: Define UPnP multicast target.
HOST upnp_target { IP 239.255.255.250 }

// INSTRUCTION: Define IoT basic device discovery flow.
FLOW ssdp_iot_search(c, s) {
    c -> s SSDP MSEARCH
        ST "urn:schemas-upnp-org:device:Basic:1"
        MX 1 MAN "\\"ssdp:discover\\""
}

// INSTRUCTION: Compile block executing IoT search.
COMPILE {
    ssdp_iot_search(iot_hub, upnp_target)
}
"""

files_data["examples/l7/ssdp/ssdp_ipv6_site_local_msearch.fasm"] = """// PROMPT: IPv6 site-local multicast discovery query to ff05::c address.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, COMPILE

// INSTRUCTION: Define IPv6 client terminal.
HOST terminal_v6 { IP 2001:db8:cafe::12 }

// INSTRUCTION: Define IPv6 site-local SSDP multicast group.
HOST ssdp_v6_site { IP ff05::c }

// INSTRUCTION: Define IPv6 site-local discovery flow.
FLOW ssdp_v6_flow(c, s) {
    c -> s SSDP MSEARCH
        ST "upnp:rootdevice"
        MX 2 MAN "\\"ssdp:discover\\""
}

// INSTRUCTION: Compile block executing IPv6 site-local search.
COMPILE {
    ssdp_v6_flow(terminal_v6, ssdp_v6_site)
}
"""

files_data["examples/l7/ssdp/ssdp_vlan_tagged_discovery.fasm"] = """// PROMPT: VLAN 100 tagged SSDP discovery frame with PCP priority tagging.
// TOKENS: HOST, IP, FLOW, ->, SSDP, MSEARCH, ST, MX, MAN, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define multimedia host on VLAN 100.
HOST vlan_host { IP 10.100.1.14 }

// INSTRUCTION: Define SSDP multicast destination.
HOST vlan_mcast { IP 239.255.255.250 }

// INSTRUCTION: Define prioritized VLAN SSDP discovery flow.
FLOW ssdp_vlan_flow(c, s) {
    c -> s SSDP MSEARCH
        ST "urn:schemas-upnp-org:device:MediaServer:1"
        MX 3 MAN "\\"ssdp:discover\\""
        VLAN 100 PCP 4 DEI 0
}

// INSTRUCTION: Compile block executing tagged search.
COMPILE {
    ssdp_vlan_flow(vlan_host, vlan_mcast)
}
"""

files_data["examples/l7/ssdp/ssdp_periodic_heartbeat_loop.fasm"] = """// PROMPT: Periodic SSDP alive announcement broadcast in a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, SSDP, NOTIFY, NT, NTS, USN, COMPILE, LOOP

// INSTRUCTION: Define home media server beacon.
HOST media_beacon { IP 192.168.1.200 }

// INSTRUCTION: Define UPnP multicast group endpoint.
HOST beacon_group { IP 239.255.255.250 }

// INSTRUCTION: Define periodic heartbeat notification flow.
FLOW ssdp_beacon_flow(c, s) {
    c -> s SSDP NOTIFY
        NT "upnp:rootdevice"
        NTS "ssdp:alive"
        USN "uuid:beacon-service-01::upnp:rootdevice"
}

// INSTRUCTION: Compile block broadcasting 3 periodic heartbeat frames.
COMPILE {
    LOOP 3 {
        ssdp_beacon_flow(media_beacon, beacon_group)
    }
}
"""

# ==========================================
# 3. SSH (12 new files)
# ==========================================
files_data["examples/l7/ssh/ssh_openssh_server_banner.fasm"] = """// PROMPT: Secure shell connection exchanging OpenSSH 9.5 protocol banner.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, BANNER, COMPILE

// INSTRUCTION: Define admin management client.
HOST admin_ws { IP 10.88.1.12 }

// INSTRUCTION: Define production server host.
HOST prod_svr { IP 10.88.1.2 }

// INSTRUCTION: Define OpenSSH banner exchange flow.
FLOW ssh_banner_flow(c, s) {
    c -> s SSH BANNER "SSH-2.0-OpenSSH_9.5p1 Debian-1"
    c <- s SSH BANNER "SSH-2.0-OpenSSH_9.5p1 Ubuntu-3"
}

// INSTRUCTION: Compile block executing banner exchange.
COMPILE {
    ssh_banner_flow(admin_ws, prod_svr)
}
"""

files_data["examples/l7/ssh/ssh_dropbear_embedded_banner.fasm"] = """// PROMPT: Embedded IoT gateway running Dropbear SSH banner exchange on port 22.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, BANNER, COMPILE

// INSTRUCTION: Define technician diagnostic laptop.
HOST tech_laptop { IP 192.168.100.8 }

// INSTRUCTION: Define embedded Linux router.
HOST embedded_rtr { IP 192.168.100.1 }

// INSTRUCTION: Define Dropbear SSH banner flow.
FLOW ssh_dropbear_flow(c, s) {
    c -> s SSH BANNER "SSH-2.0-OpenSSH_8.9"
    c <- s SSH BANNER "SSH-2.0-dropbear_2024.84"
}

// INSTRUCTION: Compile block executing Dropbear banner flow.
COMPILE {
    ssh_dropbear_flow(tech_laptop, embedded_rtr)
}
"""

files_data["examples/l7/ssh/ssh_cisco_ios_management_banner.fasm"] = """// PROMPT: Core switch management session exchanging Cisco IOS SSH banner.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, BANNER, COMPILE

// INSTRUCTION: Define network operations console.
HOST noc_console { IP 172.16.20.50 }

// INSTRUCTION: Define Cisco catalyst core switch.
HOST cisco_core { IP 172.16.20.1 }

// INSTRUCTION: Define Cisco IOS SSH banner exchange flow.
FLOW ssh_cisco_flow(c, s) {
    c -> s SSH BANNER "SSH-2.0-PuTTY_Release_0.80"
    c <- s SSH BANNER "SSH-2.0-Cisco-1.25"
}

// INSTRUCTION: Compile block executing Cisco SSH banner.
COMPILE {
    ssh_cisco_flow(noc_console, cisco_core)
}
"""

files_data["examples/l7/ssh/ssh_kexinit_diffie_hellman_group.fasm"] = """// PROMPT: Diffie-Hellman key exchange initialization with key exchange message code.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, KEXINIT, MSG_CODE, COMPILE

// INSTRUCTION: Define client node.
HOST client_node { IP 10.15.0.4 }

// INSTRUCTION: Define security gateway server.
HOST sec_gw { IP 10.15.0.1 }

// INSTRUCTION: Define KEXINIT parameter exchange flow.
FLOW ssh_kex_flow(c, s) {
    c -> s SSH KEXINIT MSG_CODE 20
    c <- s SSH KEXINIT MSG_CODE 20
}

// INSTRUCTION: Compile block executing KEXINIT exchange.
COMPILE {
    ssh_kex_flow(client_node, sec_gw)
}
"""

files_data["examples/l7/ssh/ssh_userauth_request_publickey.fasm"] = """// PROMPT: User authentication request message with MSG_CODE 50.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, MSG_CODE, COMPILE

// INSTRUCTION: Define remote developer laptop.
HOST dev_laptop { IP 192.168.4.15 }

// INSTRUCTION: Define build cluster node.
HOST build_node { IP 192.168.4.1 }

// INSTRUCTION: Define user authentication request flow.
FLOW ssh_userauth_req(c, s) {
    c -> s SSH MSG_CODE 50
    c <- s SSH MSG_CODE 51
}

// INSTRUCTION: Compile block executing auth request.
COMPILE {
    ssh_userauth_req(dev_laptop, build_node)
}
"""

files_data["examples/l7/ssh/ssh_userauth_success_session.fasm"] = """// PROMPT: Authentication accepted by server transmitting MSG_CODE 52.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, MSG_CODE, COMPILE

// INSTRUCTION: Define authenticated operator client.
HOST oper_client { IP 10.77.2.19 }

// INSTRUCTION: Define authenticating server.
HOST auth_server { IP 10.77.2.1 }

// INSTRUCTION: Define successful user authentication flow.
FLOW ssh_userauth_success(c, s) {
    c -> s SSH MSG_CODE 50
    c <- s SSH MSG_CODE 52
}

// INSTRUCTION: Compile block executing authentication success.
COMPILE {
    ssh_userauth_success(oper_client, auth_server)
}
"""

files_data["examples/l7/ssh/ssh_channel_open_session.fasm"] = """// PROMPT: Client requesting interactive shell channel allocation with MSG_CODE 90.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, MSG_CODE, COMPILE

// INSTRUCTION: Define interactive client terminal.
HOST term_client { IP 172.28.0.8 }

// INSTRUCTION: Define Linux application server.
HOST app_server { IP 172.28.0.2 }

// INSTRUCTION: Define channel open and confirmation flow.
FLOW ssh_channel_open_flow(c, s) {
    c -> s SSH MSG_CODE 90
    c <- s SSH MSG_CODE 91
}

// INSTRUCTION: Compile block executing channel allocation.
COMPILE {
    ssh_channel_open_flow(term_client, app_server)
}
"""

files_data["examples/l7/ssh/ssh_channel_window_adjust.fasm"] = """// PROMPT: Flow control window buffer adjustment packet with MSG_CODE 93.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, MSG_CODE, COMPILE

// INSTRUCTION: Define streaming file receiver.
HOST receiver_host { IP 10.120.3.5 }

// INSTRUCTION: Define file transfer source server.
HOST transfer_server { IP 10.120.3.1 }

// INSTRUCTION: Define bidirectional window adjustment flow.
FLOW ssh_window_adjust_flow(c, s) {
    c -> s SSH MSG_CODE 93
    c <- s SSH MSG_CODE 93
}

// INSTRUCTION: Compile block executing window adjustment.
COMPILE {
    ssh_window_adjust_flow(receiver_host, transfer_server)
}
"""

files_data["examples/l7/ssh/ssh_channel_data_transmission.fasm"] = """// PROMPT: Encrypted pseudo-terminal session data frame with MSG_CODE 94.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, MSG_CODE, COMPILE

// INSTRUCTION: Define interactive user shell.
HOST shell_client { IP 192.168.33.22 }

// INSTRUCTION: Define remote target bastion.
HOST target_bastion { IP 192.168.33.1 }

// INSTRUCTION: Define interactive data exchange flow.
FLOW ssh_data_flow(c, s) {
    c -> s SSH MSG_CODE 94
    c <- s SSH MSG_CODE 94
}

// INSTRUCTION: Compile block executing channel data transmission.
COMPILE {
    ssh_data_flow(shell_client, target_bastion)
}
"""

files_data["examples/l7/ssh/ssh_disconnect_normal_shutdown.fasm"] = """// PROMPT: Clean session termination packet transmitting MSG_CODE 1 disconnect.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, MSG_CODE, COMPILE

// INSTRUCTION: Define departing client terminal.
HOST departing_client { IP 10.250.0.10 }

// INSTRUCTION: Define corporate bastion host.
HOST corp_bastion { IP 10.250.0.1 }

// INSTRUCTION: Define clean SSH disconnect flow.
FLOW ssh_disconnect_flow(c, s) {
    c -> s SSH MSG_CODE 1
    c <- s SSH MSG_CODE 1
}

// INSTRUCTION: Compile block executing disconnect flow.
COMPILE {
    ssh_disconnect_flow(departing_client, corp_bastion)
}
"""

files_data["examples/l7/ssh/ssh_ipv6_admin_console_flow.fasm"] = """// PROMPT: IPv6 remote console administration session with version banner and KEXINIT.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, BANNER, KEXINIT, COMPILE

// INSTRUCTION: Define IPv6 administration station.
HOST admin_v6 { IP 2001:db8:8888::15 }

// INSTRUCTION: Define IPv6 firewall management interface.
HOST fw_v6 { IP 2001:db8:8888::1 }

// INSTRUCTION: Define IPv6 SSH session setup flow.
FLOW ssh_v6_session(c, s) {
    c -> s SSH BANNER "SSH-2.0-OpenSSH_9.3"
    c <- s SSH BANNER "SSH-2.0-OpenSSH_9.3"
    c -> s SSH KEXINIT
    c <- s SSH KEXINIT
}

// INSTRUCTION: Compile block executing IPv6 SSH setup.
COMPILE {
    ssh_v6_session(admin_v6, fw_v6)
}
"""

files_data["examples/l7/ssh/ssh_automated_backup_batch_loop.fasm"] = """// PROMPT: Automated configuration backup probe loop across network routers.
// TOKENS: HOST, IP, FLOW, ->, <-, SSH, BANNER, NEWKEYS, COMPILE, LOOP

// INSTRUCTION: Define configuration audit controller.
HOST audit_ctrl { IP 172.22.1.100 }

// INSTRUCTION: Define target router.
HOST target_rtr { IP 172.22.1.1 }

// INSTRUCTION: Define recurring configuration pull flow.
FLOW ssh_audit_flow(c, s) {
    c -> s SSH BANNER "SSH-2.0-Ansible_Automation"
    c <- s SSH BANNER "SSH-2.0-Cisco-1.25"
    c -> s SSH NEWKEYS
    c <- s SSH NEWKEYS
}

// INSTRUCTION: Compile block executing 3 repeated audit checks.
COMPILE {
    LOOP 3 {
        ssh_audit_flow(audit_ctrl, target_rtr)
    }
}
"""

# ==========================================
# 4. STUN (12 new files)
# ==========================================
files_data["examples/l7/stun/stun_voip_endpoint_nat_discovery.fasm"] = """// PROMPT: SIP telephone performing STUN binding request for NAT discovery.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, SOFTWARE, COMPILE

// INSTRUCTION: Define desk phone endpoint.
HOST sip_phone { IP 192.168.15.22 }

// INSTRUCTION: Define cloud STUN resolver.
HOST cloud_stun { IP 198.51.100.40 }

// INSTRUCTION: Define VoIP NAT discovery flow.
FLOW stun_sip_nat_flow(c, s) {
    c -> s STUN BINDING_REQUEST SOFTWARE "Polycom-VVX450"
    c <- s STUN BINDING_RESPONSE
        XOR_MAPPED_ADDR 203.0.113.190
        SOFTWARE "reTurnServer-0.4"
}

// INSTRUCTION: Compile block executing VoIP STUN discovery.
COMPILE {
    stun_sip_nat_flow(sip_phone, cloud_stun)
}
"""

files_data["examples/l7/stun/stun_webrtc_peer_reflexive_candidate.fasm"] = """// PROMPT: WebRTC browser endpoint acquiring server reflexive candidate address.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, SOFTWARE, COMPILE

// INSTRUCTION: Define WebRTC client browser.
HOST browser_client { IP 10.0.8.44 }

// INSTRUCTION: Define WebRTC STUN server.
HOST webrtc_stun { IP 198.51.100.88 }

// INSTRUCTION: Define peer reflexive candidate discovery flow.
FLOW stun_webrtc_flow(c, s) {
    c -> s STUN BINDING_REQUEST SOFTWARE "Chromium-WebRTC"
    c <- s STUN BINDING_RESPONSE
        XOR_MAPPED_ADDR 198.51.100.210
        SOFTWARE "coturn-4.5.2"
}

// INSTRUCTION: Compile block executing WebRTC STUN query.
COMPILE {
    stun_webrtc_flow(browser_client, webrtc_stun)
}
"""

files_data["examples/l7/stun/stun_carrier_grade_nat_mapping.fasm"] = """// PROMPT: Carrier-Grade NAT traversal query with XOR-MAPPED-ADDRESS mapping.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, COMPILE

// INSTRUCTION: Define cellular subscriber endpoint on CGNAT subnet.
HOST cgnat_subscriber { IP 100.64.12.90 }

// INSTRUCTION: Define carrier public STUN reflector.
HOST carrier_reflector { IP 203.0.113.5 }

// INSTRUCTION: Define CGNAT address binding flow.
FLOW stun_cgnat_flow(c, s) {
    c -> s STUN BINDING_REQUEST
    c <- s STUN BINDING_RESPONSE XOR_MAPPED_ADDR 203.0.113.150
}

// INSTRUCTION: Compile block executing CGNAT binding flow.
COMPILE {
    stun_cgnat_flow(cgnat_subscriber, carrier_reflector)
}
"""

files_data["examples/l7/stun/stun_ipv6_binding_request.fasm"] = """// PROMPT: Dual-stack IPv6 STUN binding request to public session controller.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, SOFTWARE, COMPILE

// INSTRUCTION: Define IPv6 dual-stack terminal.
HOST dual_terminal { IP 2001:db8:9000::25 }

// INSTRUCTION: Define IPv6 STUN controller.
HOST stun_v6_ctrl { IP 2001:db8:9000::1 }

// INSTRUCTION: Define IPv6 STUN binding flow.
FLOW stun_v6_flow(c, s) {
    c -> s STUN BINDING_REQUEST SOFTWARE "V6-Client-Lib"
    c <- s STUN BINDING_RESPONSE SOFTWARE "V6-Coturn-Core"
}

// INSTRUCTION: Compile block executing IPv6 STUN flow.
COMPILE {
    stun_v6_flow(dual_terminal, stun_v6_ctrl)
}
"""

files_data["examples/l7/stun/stun_coturn_server_software_attr.fasm"] = """// PROMPT: STUN binding response populated with server SOFTWARE attribute.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, SOFTWARE, COMPILE

// INSTRUCTION: Define enterprise teleconference client.
HOST conf_client { IP 172.25.1.80 }

// INSTRUCTION: Define Coturn enterprise server.
HOST coturn_svr { IP 198.51.100.99 }

// INSTRUCTION: Define Coturn response flow.
FLOW stun_coturn_flow(c, s) {
    c -> s STUN BINDING_REQUEST SOFTWARE "Jitsi-Meet-Client"
    c <- s STUN BINDING_RESPONSE
        XOR_MAPPED_ADDR 198.51.100.14
        SOFTWARE "Coturn-4.6.2 'dan Eiser'"
}

// INSTRUCTION: Compile block executing Coturn attribute validation.
COMPILE {
    stun_coturn_flow(conf_client, coturn_svr)
}
"""

files_data["examples/l7/stun/stun_unauthorized_error_challenge.fasm"] = """// PROMPT: STUN error response indicating unauthorized credential challenge.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_ERROR, SOFTWARE, COMPILE

// INSTRUCTION: Define unauthenticated client endpoint.
HOST unauth_client { IP 10.140.2.19 }

// INSTRUCTION: Define strict auth STUN gateway.
HOST auth_stun_gw { IP 10.140.2.1 }

// INSTRUCTION: Define STUN unauthorized error response flow.
FLOW stun_error_flow(c, s) {
    c -> s STUN BINDING_REQUEST SOFTWARE "Generic-STUN-Tester"
    c <- s STUN BINDING_ERROR SOFTWARE "Secure-STUN-Gateway"
}

// INSTRUCTION: Compile block executing STUN error response.
COMPILE {
    stun_error_flow(unauth_client, auth_stun_gw)
}
"""

files_data["examples/l7/stun/stun_server_error_try_alternate.fasm"] = """// PROMPT: STUN server error response directing client to try alternate server.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_ERROR, SOFTWARE, COMPILE

// INSTRUCTION: Define client endpoint.
HOST roving_client { IP 192.168.75.14 }

// INSTRUCTION: Define overloaded primary STUN server.
HOST primary_stun { IP 198.51.100.12 }

// INSTRUCTION: Define server error alternate redirect flow.
FLOW stun_try_alt_flow(c, s) {
    c -> s STUN BINDING_REQUEST SOFTWARE "SIP-Agent-3.0"
    c <- s STUN BINDING_ERROR SOFTWARE "Primary-Overloaded-TryAlternate"
}

// INSTRUCTION: Compile block executing try alternate flow.
COMPILE {
    stun_try_alt_flow(roving_client, primary_stun)
}
"""

files_data["examples/l7/stun/stun_enterprise_session_border_controller.fasm"] = """// PROMPT: Enterprise SBC performing STUN keepalive probe on UDP 3478.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, SOFTWARE, COMPILE

// INSTRUCTION: Define internal Session Border Controller.
HOST internal_sbc { IP 10.50.200.5 }

// INSTRUCTION: Define public carrier SBC edge.
HOST carrier_sbc { IP 203.0.113.120 }

// INSTRUCTION: Define SBC trunk binding validation flow.
FLOW stun_sbc_flow(c, s) {
    c -> s STUN BINDING_REQUEST SOFTWARE "Audiocodes-Mediant-SBC"
    c <- s STUN BINDING_RESPONSE
        XOR_MAPPED_ADDR 203.0.113.245
        SOFTWARE "Carrier-Edge-SBC-v7"
}

// INSTRUCTION: Compile block executing SBC binding exchange.
COMPILE {
    stun_sbc_flow(internal_sbc, carrier_sbc)
}
"""

files_data["examples/l7/stun/stun_dual_wan_uplink_nat_check.fasm"] = """// PROMPT: Multi-homed gateway verifying secondary WAN uplink NAT binding.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, COMPILE

// INSTRUCTION: Define secondary WAN branch interface.
HOST wan2_interface { IP 172.31.50.10 }

// INSTRUCTION: Define public STUN discovery node.
HOST public_stun { IP 198.51.100.222 }

// INSTRUCTION: Define secondary WAN NAT probe flow.
FLOW stun_wan2_flow(c, s) {
    c -> s STUN BINDING_REQUEST
    c <- s STUN BINDING_RESPONSE XOR_MAPPED_ADDR 198.51.100.77
}

// INSTRUCTION: Compile block executing secondary WAN NAT check.
COMPILE {
    stun_wan2_flow(wan2_interface, public_stun)
}
"""

files_data["examples/l7/stun/stun_udp_keepalive_refresh_loop.fasm"] = """// PROMPT: Periodic STUN binding refresh loop preserving firewall translation state.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, COMPILE, LOOP

// INSTRUCTION: Define mobile VoIP softphone.
HOST softphone { IP 192.168.10.14 }

// INSTRUCTION: Define public STUN keepalive node.
HOST stun_keepalive { IP 203.0.113.1 }

// INSTRUCTION: Define recurring NAT keepalive flow.
FLOW stun_keepalive_flow(c, s) {
    c -> s STUN BINDING_REQUEST
    c <- s STUN BINDING_RESPONSE XOR_MAPPED_ADDR 203.0.113.89
}

// INSTRUCTION: Compile block executing 4 periodic refresh cycles.
COMPILE {
    LOOP 4 {
        stun_keepalive_flow(softphone, stun_keepalive)
    }
}
"""

files_data["examples/l7/stun/stun_vlan_voice_network_mapping.fasm"] = """// PROMPT: Dedicated voice VLAN 200 STUN binding transaction with DSCP EF priority.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, VLAN, PCP, DEI, DSCP, COMPILE

// INSTRUCTION: Define voice VLAN IP phone.
HOST voice_phone { IP 10.200.10.15 }

// INSTRUCTION: Define cloud voice gateway.
HOST cloud_voice_gw { IP 198.51.100.60 }

// INSTRUCTION: Define voice prioritized STUN transaction flow.
FLOW stun_voice_vlan_flow(c, s) {
    c -> s STUN BINDING_REQUEST
        VLAN 200 PCP 5 DEI 0 DSCP 46
    c <- s STUN BINDING_RESPONSE
        XOR_MAPPED_ADDR 198.51.100.110
        VLAN 200 PCP 5 DEI 0 DSCP 46
}

// INSTRUCTION: Compile block executing prioritized voice STUN.
COMPILE {
    stun_voice_vlan_flow(voice_phone, cloud_voice_gw)
}
"""

files_data["examples/l7/stun/stun_gaming_console_full_cone_nat.fasm"] = """// PROMPT: Online multiplayer gaming console detecting full-cone NAT mapping.
// TOKENS: HOST, IP, FLOW, ->, <-, STUN, BINDING_REQUEST, BINDING_RESPONSE, XOR_MAPPED_ADDR, SOFTWARE, COMPILE

// INSTRUCTION: Define home gaming console.
HOST game_console { IP 192.168.1.180 }

// INSTRUCTION: Define multiplayer matchmaking STUN reflector.
HOST match_stun { IP 203.0.113.4 }

// INSTRUCTION: Define gaming NAT type detection flow.
FLOW stun_gaming_flow(c, s) {
    c -> s STUN BINDING_REQUEST SOFTWARE "Xbox-Net-Engine"
    c <- s STUN BINDING_RESPONSE
        XOR_MAPPED_ADDR 203.0.113.166
        SOFTWARE "Multiplayer-Reflector-v4"
}

// INSTRUCTION: Compile block executing gaming NAT test.
COMPILE {
    stun_gaming_flow(game_console, match_stun)
}
"""

# ==========================================
# 5. SYSLOG (12 new files)
# ==========================================
files_data["examples/l7/syslog/syslog_auth_priv_login_success.fasm"] = """// PROMPT: Secure authentication facility event reporting successful admin login.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, PROCID, MSG, COMPILE

// INSTRUCTION: Define secure server node.
HOST sec_server { IP 10.10.0.15 }

// INSTRUCTION: Define enterprise syslog collector.
HOST siem_collector { IP 10.10.0.50 }

// INSTRUCTION: Define authentication success log flow.
FLOW syslog_auth_flow(c, s) {
    c -> s SYSLOG FACILITY 10 SEVERITY 6
        HOSTNAME "sec-svr-01" APP "sshd" PROCID "2819"
        MSG "Accepted publickey for admin from 192.168.1.55 port 51234"
}

// INSTRUCTION: Compile block executing auth logging.
COMPILE {
    syslog_auth_flow(sec_server, siem_collector)
}
"""

files_data["examples/l7/syslog/syslog_auth_failure_bruteforce_alert.fasm"] = """// PROMPT: Authentication security warning recording repeated invalid password attempts.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, PROCID, MSG, COMPILE

// INSTRUCTION: Define exposed bastion server.
HOST exposed_bastion { IP 198.51.100.10 }

// INSTRUCTION: Define SOC SIEM aggregation system.
HOST soc_siem { IP 10.20.30.5 }

// INSTRUCTION: Define failed authentication alert flow.
FLOW syslog_bruteforce_flow(c, s) {
    c -> s SYSLOG FACILITY 10 SEVERITY 4
        HOSTNAME "bastion-ext" APP "sshd" PROCID "9940"
        MSG "Failed password for invalid user root from 203.0.113.90 port 44102"
}

// INSTRUCTION: Compile block executing brute force warning.
COMPILE {
    syslog_bruteforce_flow(exposed_bastion, soc_siem)
}
"""

files_data["examples/l7/syslog/syslog_kernel_panic_critical.fasm"] = """// PROMPT: Kernel facility critical error reporting memory allocation exhaustion.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, PROCID, MSG, COMPILE

// INSTRUCTION: Define compute node host.
HOST compute_node { IP 172.18.5.21 }

// INSTRUCTION: Define central logging host.
HOST central_syslog { IP 172.18.0.10 }

// INSTRUCTION: Define kernel critical alert flow.
FLOW syslog_kernel_flow(c, s) {
    c -> s SYSLOG FACILITY 0 SEVERITY 2
        HOSTNAME "compute-node-21" APP "kernel" PROCID "0"
        MSG "Out of memory: Kill process 1842 (java) score 950 or sacrifice child"
}

// INSTRUCTION: Compile block executing critical log.
COMPILE {
    syslog_kernel_flow(compute_node, central_syslog)
}
"""

files_data["examples/l7/syslog/syslog_daemon_service_restart.fasm"] = """// PROMPT: System daemon facility notice recording background service restart.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, PROCID, MSG, COMPILE

// INSTRUCTION: Define application gateway host.
HOST app_gw { IP 10.40.2.14 }

// INSTRUCTION: Define infrastructure syslog server.
HOST infra_syslog { IP 10.40.0.1 }

// INSTRUCTION: Define daemon restart notice flow.
FLOW syslog_daemon_flow(c, s) {
    c -> s SYSLOG FACILITY 3 SEVERITY 5
        HOSTNAME "app-gw-01" APP "systemd" PROCID "1"
        MSG "nginx.service: Deactivated successfully. Service reloaded."
}

// INSTRUCTION: Compile block executing daemon notice.
COMPILE {
    syslog_daemon_flow(app_gw, infra_syslog)
}
"""

files_data["examples/l7/syslog/syslog_firewall_drop_audit_event.fasm"] = """// PROMPT: Perimeter firewall security audit event logging blocked packet transmission.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, MSG, COMPILE

// INSTRUCTION: Define perimeter firewall device.
HOST edge_firewall { IP 192.168.1.1 }

// INSTRUCTION: Define network auditor collector.
HOST audit_collector { IP 10.100.1.25 }

// INSTRUCTION: Define firewall packet drop audit flow.
FLOW syslog_fw_drop_flow(c, s) {
    c -> s SYSLOG FACILITY 4 SEVERITY 4
        HOSTNAME "fw-edge-01" APP "nftables"
        MSG "DROP rule=WAN_IN src=198.51.100.44 dst=192.168.1.10 proto=TCP dport=445"
}

// INSTRUCTION: Compile block executing firewall audit event.
COMPILE {
    syslog_fw_drop_flow(edge_firewall, audit_collector)
}
"""

files_data["examples/l7/syslog/syslog_cron_scheduled_task_execution.fasm"] = """// PROMPT: Cron daemon informational log reporting hourly backup task completion.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, PROCID, MSG, COMPILE

// INSTRUCTION: Define backup utility node.
HOST backup_util { IP 10.60.12.8 }

// INSTRUCTION: Define operational syslog sink.
HOST ops_sink { IP 10.60.0.1 }

// INSTRUCTION: Define cron task completion flow.
FLOW syslog_cron_flow(c, s) {
    c -> s SYSLOG FACILITY 9 SEVERITY 6
        HOSTNAME "backup-srv" APP "crond" PROCID "10552"
        MSG "(root) CMD (/usr/local/bin/backup_hourly.sh >/dev/null 2>&1)"
}

// INSTRUCTION: Compile block executing cron log event.
COMPILE {
    syslog_cron_flow(backup_util, ops_sink)
}
"""

files_data["examples/l7/syslog/syslog_local0_router_bgp_flap.fasm"] = """// PROMPT: Local0 network equipment error reporting BGP neighbor state reset.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, MSG, COMPILE

// INSTRUCTION: Define edge routing router.
HOST edge_rtr { IP 172.16.0.1 }

// INSTRUCTION: Define network operations logging system.
HOST noc_syslog { IP 172.16.0.100 }

// INSTRUCTION: Define BGP neighbor flap error flow.
FLOW syslog_bgp_flap_flow(c, s) {
    c -> s SYSLOG FACILITY 16 SEVERITY 3
        HOSTNAME "core-rtr-01" APP "bgpd"
        MSG "%BGP-5-ADJCHANGE: neighbor 198.51.100.2 Down - BGP Notification sent"
}

// INSTRUCTION: Compile block executing BGP flap error event.
COMPILE {
    syslog_bgp_flap_flow(edge_rtr, noc_syslog)
}
"""

files_data["examples/l7/syslog/syslog_local1_switch_spanning_tree.fasm"] = """// PROMPT: Local1 switch facility notice reporting STP topology change event.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, MSG, COMPILE

// INSTRUCTION: Define access switch.
HOST access_switch { IP 192.168.10.2 }

// INSTRUCTION: Define campus monitoring collector.
HOST campus_mon { IP 192.168.10.1 }

// INSTRUCTION: Define spanning tree state notice flow.
FLOW syslog_stp_flow(c, s) {
    c -> s SYSLOG FACILITY 17 SEVERITY 5
        HOSTNAME "sw-access-4" APP "stp"
        MSG "%SPANTREE-5-TOPOTRANS: Topology change detected on port Gi1/0/24"
}

// INSTRUCTION: Compile block executing STP state notice.
COMPILE {
    syslog_stp_flow(access_switch, campus_mon)
}
"""

files_data["examples/l7/syslog/syslog_local4_vpn_tunnel_status.fasm"] = """// PROMPT: Local4 VPN gateway informational log reporting IPSec tunnel establishment.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, MSG, COMPILE

// INSTRUCTION: Define VPN concentration gateway.
HOST vpn_concentrator { IP 10.80.1.1 }

// INSTRUCTION: Define telemetry SIEM system.
HOST tele_siem { IP 10.80.1.200 }

// INSTRUCTION: Define VPN tunnel up notification flow.
FLOW syslog_vpn_flow(c, s) {
    c -> s SYSLOG FACILITY 20 SEVERITY 6
        HOSTNAME "vpn-gw-primary" APP "charon"
        MSG "IPsec SA established between 198.51.100.1 and 203.0.113.80"
}

// INSTRUCTION: Compile block executing VPN tunnel log event.
COMPILE {
    syslog_vpn_flow(vpn_concentrator, tele_siem)
}
"""

files_data["examples/l7/syslog/syslog_mail_postfix_delivery_stat.fasm"] = """// PROMPT: Mail server informational log recording queued email delivery to destination.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, PROCID, MSG, COMPILE

// INSTRUCTION: Define corporate mail host.
HOST mail_host { IP 172.20.10.5 }

// INSTRUCTION: Define central syslog archive.
HOST log_archive { IP 172.20.10.1 }

// INSTRUCTION: Define mail delivery log transmission flow.
FLOW syslog_postfix_flow(c, s) {
    c -> s SYSLOG FACILITY 2 SEVERITY 6
        HOSTNAME "mail-hub-01" APP "postfix/smtp" PROCID "14209"
        MSG "to=<alice@example.com>, relay=mx1.example.com[93.184.216.34], status=sent"
}

// INSTRUCTION: Compile block executing postfix delivery log.
COMPILE {
    syslog_postfix_flow(mail_host, log_archive)
}
"""

files_data["examples/l7/syslog/syslog_audit_compliance_heartbeat_loop.fasm"] = """// PROMPT: Periodic compliance logging loop transmitting SIEM heartbeat events.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, PRI, HOSTNAME, APP, MSG, COMPILE, LOOP

// INSTRUCTION: Define security audit agent.
HOST audit_agent { IP 10.5.15.20 }

// INSTRUCTION: Define SOC receiver.
HOST soc_receiver { IP 10.5.15.1 }

// INSTRUCTION: Define periodic heartbeat event flow.
FLOW syslog_heartbeat_flow(c, s) {
    c -> s SYSLOG PRI 134
        HOSTNAME "audit-probe-01" APP "watchdog"
        MSG "HEARTBEAT: Service operational, all intrusion sensors active."
}

// INSTRUCTION: Compile block transmitting 3 periodic heartbeat events.
COMPILE {
    LOOP 3 {
        syslog_heartbeat_flow(audit_agent, soc_receiver)
    }
}
"""

files_data["examples/l7/syslog/syslog_datacenter_vlan_monitoring.fasm"] = """// PROMPT: Datacenter VLAN 500 tagged syslog notification with CS2 network control.
// TOKENS: HOST, IP, FLOW, ->, SYSLOG, FACILITY, SEVERITY, HOSTNAME, APP, MSG, VLAN, PCP, DEI, DSCP, COMPILE

// INSTRUCTION: Define datacenter top-of-rack switch.
HOST tor_switch { IP 10.50.0.12 }

// INSTRUCTION: Define datacenter management syslog server.
HOST mgmt_syslog { IP 10.50.0.1 }

// INSTRUCTION: Define VLAN prioritized telemetry notification flow.
FLOW syslog_vlan_flow(c, s) {
    c -> s SYSLOG FACILITY 16 SEVERITY 6
        HOSTNAME "tor-rack-12" APP "telemetry"
        MSG "Interface 100G-Ethernet 1/1/1 link operational, zero CRC errors."
        VLAN 500 PCP 2 DEI 0 DSCP 16
}

// INSTRUCTION: Compile block executing VLAN tagged syslog event.
COMPILE {
    syslog_vlan_flow(tor_switch, mgmt_syslog)
}
"""

# ==========================================
# 6. TACACS (12 new files)
# ==========================================
files_data["examples/l7/tacacs/tacacs_authen_ascii_password_prompt.fasm"] = """// PROMPT: TACACS+ authentication session prompting user for login password.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHEN, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define edge switch NAS client.
HOST switch_nas { IP 192.168.100.10 }

// INSTRUCTION: Define AAA identity server.
HOST aaa_server { IP 192.168.100.1 }

// INSTRUCTION: Define TACACS+ password prompt authentication flow.
FLOW tacacs_prompt_flow(c, s) {
    c -> s TACACS TYPE AUTHEN USER "jdoe" SESSION_ID 5010
    c <- s TACACS TYPE AUTHEN USER "jdoe" SESSION_ID 5010
}

// INSTRUCTION: Compile block executing password prompt exchange.
COMPILE {
    tacacs_prompt_flow(switch_nas, aaa_server)
}
"""

files_data["examples/l7/tacacs/tacacs_authen_chap_challenge_response.fasm"] = """// PROMPT: CHAP authentication flow verifying administrative user credentials.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHEN, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define network aggregation router.
HOST agg_rtr { IP 172.16.5.2 }

// INSTRUCTION: Define centralized TACACS daemon.
HOST tacacs_daemon { IP 172.16.5.1 }

// INSTRUCTION: Define CHAP authentication validation flow.
FLOW tacacs_chap_flow(c, s) {
    c -> s TACACS TYPE AUTHEN USER "netops_lead" SESSION_ID 6020
    c <- s TACACS TYPE AUTHEN USER "netops_lead" SESSION_ID 6020
}

// INSTRUCTION: Compile block executing CHAP authentication.
COMPILE {
    tacacs_chap_flow(agg_rtr, tacacs_daemon)
}
"""

files_data["examples/l7/tacacs/tacacs_authen_enable_privilege_elevation.fasm"] = """// PROMPT: User privilege elevation request to access level 15 exec mode.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHEN, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define core router NAS.
HOST core_nas { IP 10.0.0.1 }

// INSTRUCTION: Define policy AAA server.
HOST policy_aaa { IP 10.0.0.254 }

// INSTRUCTION: Define enable privilege elevation flow.
FLOW tacacs_enable_flow(c, s) {
    c -> s TACACS TYPE AUTHEN USER "enable_admin" SESSION_ID 7030
    c <- s TACACS TYPE AUTHEN USER "enable_admin" SESSION_ID 7030
}

// INSTRUCTION: Compile block executing privilege elevation.
COMPILE {
    tacacs_enable_flow(core_nas, policy_aaa)
}
"""

files_data["examples/l7/tacacs/tacacs_author_command_permit.fasm"] = """// PROMPT: Command authorization verifying permission to run show running-config.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHOR, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define datacenter switch NAS.
HOST dc_switch { IP 10.150.1.20 }

// INSTRUCTION: Define authorization engine.
HOST author_engine { IP 10.150.1.1 }

// INSTRUCTION: Define permitted command authorization flow.
FLOW tacacs_permit_flow(c, s) {
    c -> s TACACS TYPE AUTHOR USER "auditor" SESSION_ID 8040
    c <- s TACACS TYPE AUTHOR USER "auditor" SESSION_ID 8040
}

// INSTRUCTION: Compile block executing command authorization.
COMPILE {
    tacacs_permit_flow(dc_switch, author_engine)
}
"""

files_data["examples/l7/tacacs/tacacs_author_command_deny_reboot.fasm"] = """// PROMPT: Command authorization denying non-admin request to reload hardware.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHOR, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define branch office switch.
HOST branch_sw { IP 192.168.40.5 }

// INSTRUCTION: Define enterprise AAA cluster.
HOST aaa_cluster { IP 192.168.40.1 }

// INSTRUCTION: Define reload command rejection flow.
FLOW tacacs_deny_flow(c, s) {
    c -> s TACACS TYPE AUTHOR USER "junior_tech" SESSION_ID 9050
    c <- s TACACS TYPE AUTHOR USER "junior_tech" SESSION_ID 9050
}

// INSTRUCTION: Compile block executing command denial.
COMPILE {
    tacacs_deny_flow(branch_sw, aaa_cluster)
}
"""

files_data["examples/l7/tacacs/tacacs_author_interface_config_args.fasm"] = """// PROMPT: Authorization check for interface configuration command parameters.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHOR, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define perimeter router NAS.
HOST perim_rtr { IP 172.24.10.1 }

// INSTRUCTION: Define policy enforcement host.
HOST policy_host { IP 172.24.10.200 }

// INSTRUCTION: Define configuration argument authorization flow.
FLOW tacacs_iface_flow(c, s) {
    c -> s TACACS TYPE AUTHOR USER "secops_eng" SESSION_ID 10060
    c <- s TACACS TYPE AUTHOR USER "secops_eng" SESSION_ID 10060
}

// INSTRUCTION: Compile block executing argument authorization.
COMPILE {
    tacacs_iface_flow(perim_rtr, policy_host)
}
"""

files_data["examples/l7/tacacs/tacacs_acct_start_cli_session.fasm"] = """// PROMPT: Accounting START record logging initial administrator login timestamp.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, ACCT, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define management gateway NAS.
HOST mgmt_gateway { IP 10.210.1.2 }

// INSTRUCTION: Define central accounting database.
HOST acct_db { IP 10.210.1.1 }

// INSTRUCTION: Define session accounting START flow.
FLOW tacacs_acct_start_flow(c, s) {
    c -> s TACACS TYPE ACCT USER "cisco_admin" SESSION_ID 11070
    c <- s TACACS TYPE ACCT USER "cisco_admin" SESSION_ID 11070
}

// INSTRUCTION: Compile block executing accounting START.
COMPILE {
    tacacs_acct_start_flow(mgmt_gateway, acct_db)
}
"""

files_data["examples/l7/tacacs/tacacs_acct_stop_command_executed.fasm"] = """// PROMPT: Accounting STOP record logging completed configuration change execution.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, ACCT, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define spine switch NAS.
HOST spine_nas { IP 10.70.1.1 }

// INSTRUCTION: Define audit logger endpoint.
HOST audit_logger { IP 10.70.1.250 }

// INSTRUCTION: Define accounting STOP record flow.
FLOW tacacs_acct_stop_flow(c, s) {
    c -> s TACACS TYPE ACCT USER "net_architect" SESSION_ID 12080
    c <- s TACACS TYPE ACCT USER "net_architect" SESSION_ID 12080
}

// INSTRUCTION: Compile block executing accounting STOP.
COMPILE {
    tacacs_acct_stop_flow(spine_nas, audit_logger)
}
"""

files_data["examples/l7/tacacs/tacacs_acct_update_long_session.fasm"] = """// PROMPT: Accounting UPDATE heartbeat record preserving active session audit trail.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, ACCT, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define lab console server.
HOST lab_console { IP 192.168.88.10 }

// INSTRUCTION: Define regional TACACS accounting node.
HOST reg_acct_node { IP 192.168.88.1 }

// INSTRUCTION: Define accounting UPDATE heartbeat flow.
FLOW tacacs_acct_update_flow(c, s) {
    c -> s TACACS TYPE ACCT USER "automation_bot" SESSION_ID 13090
    c <- s TACACS TYPE ACCT USER "automation_bot" SESSION_ID 13090
}

// INSTRUCTION: Compile block executing accounting UPDATE.
COMPILE {
    tacacs_acct_update_flow(lab_console, reg_acct_node)
}
"""

files_data["examples/l7/tacacs/tacacs_ipv6_core_switch_radius_fallback.fasm"] = """// PROMPT: IPv6 core switch authenticating operator credentials via TACACS+.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHEN, USER, SESSION_ID, COMPILE

// INSTRUCTION: Define IPv6 core switch NAS.
HOST switch_v6 { IP 2001:db8:7777::10 }

// INSTRUCTION: Define IPv6 enterprise TACACS server.
HOST tacacs_v6_svr { IP 2001:db8:7777::1 }

// INSTRUCTION: Define IPv6 authentication validation flow.
FLOW tacacs_v6_flow(c, s) {
    c -> s TACACS TYPE AUTHEN USER "ipv6_operator" SESSION_ID 14100
    c <- s TACACS TYPE AUTHEN USER "ipv6_operator" SESSION_ID 14100
}

// INSTRUCTION: Compile block executing IPv6 TACACS transaction.
COMPILE {
    tacacs_v6_flow(switch_v6, tacacs_v6_svr)
}
"""

files_data["examples/l7/tacacs/tacacs_vlan_mgmt_traffic_isolation.fasm"] = """// PROMPT: Out-of-band management VLAN 99 tagged TACACS+ session with CS6 priority.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHEN, USER, SESSION_ID, VLAN, PCP, DEI, DSCP, COMPILE

// INSTRUCTION: Define management VLAN switch client.
HOST mgmt_switch { IP 10.99.0.15 }

// INSTRUCTION: Define management AAA server.
HOST mgmt_aaa { IP 10.99.0.1 }

// INSTRUCTION: Define isolated management authentication flow.
FLOW tacacs_mgmt_vlan_flow(c, s) {
    c -> s TACACS TYPE AUTHEN USER "oob_admin" SESSION_ID 15110
        VLAN 99 PCP 6 DEI 0 DSCP 48
    c <- s TACACS TYPE AUTHEN USER "oob_admin" SESSION_ID 15110
        VLAN 99 PCP 6 DEI 0 DSCP 48
}

// INSTRUCTION: Compile block executing VLAN tagged TACACS session.
COMPILE {
    tacacs_mgmt_vlan_flow(mgmt_switch, mgmt_aaa)
}
"""

files_data["examples/l7/tacacs/tacacs_multi_admin_batch_auth_loop.fasm"] = """// PROMPT: Periodic administrative access validation loop simulating operator checks.
// TOKENS: HOST, IP, FLOW, ->, <-, TACACS, TYPE, AUTHEN, USER, SESSION_ID, COMPILE, LOOP

// INSTRUCTION: Define automated validation test bench.
HOST test_bench { IP 172.31.10.4 }

// INSTRUCTION: Define target TACACS daemon.
HOST target_tacacs { IP 172.31.10.1 }

// INSTRUCTION: Define repetitive authentication request flow.
FLOW tacacs_loop_flow(c, s) {
    c -> s TACACS TYPE AUTHEN USER "batch_test" SESSION_ID 16120
    c <- s TACACS TYPE AUTHEN USER "batch_test" SESSION_ID 16120
}

// INSTRUCTION: Compile block executing 3 repeated authentication queries.
COMPILE {
    LOOP 3 {
        tacacs_loop_flow(test_bench, target_tacacs)
    }
}
"""

# ==========================================
# 7. TELNET (12 new files)
# ==========================================
files_data["examples/l7/telnet/telnet_echo_option_negotiation.fasm"] = """// PROMPT: Telnet IAC WILL 1 and IAC DO 1 local character echo negotiation.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, WILL, DO, COMPILE

// INSTRUCTION: Define user terminal client.
HOST user_term { IP 192.168.1.15 }

// INSTRUCTION: Define Telnet host server.
HOST telnet_host { IP 192.168.1.1 }

// INSTRUCTION: Define echo option negotiation flow.
FLOW telnet_echo_negotiate(c, s) {
    c -> s TELNET WILL 1
    c <- s TELNET DO 1
    c <- s TELNET WILL 1
    c -> s TELNET DO 1
}

// INSTRUCTION: Compile block executing echo negotiation.
COMPILE {
    telnet_echo_negotiate(user_term, telnet_host)
}
"""

files_data["examples/l7/telnet/telnet_suppress_go_ahead_option.fasm"] = """// PROMPT: Telnet IAC WILL 3 and IAC DO 3 suppress go ahead transmission mode.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, WILL, DO, COMPILE

// INSTRUCTION: Define console workstation.
HOST console_ws { IP 10.10.5.20 }

// INSTRUCTION: Define network gateway terminal.
HOST gw_term { IP 10.10.5.1 }

// INSTRUCTION: Define suppress go ahead negotiation flow.
FLOW telnet_sga_flow(c, s) {
    c -> s TELNET WILL 3
    c <- s TELNET DO 3
    c <- s TELNET WILL 3
    c -> s TELNET DO 3
}

// INSTRUCTION: Compile block executing SGA negotiation.
COMPILE {
    telnet_sga_flow(console_ws, gw_term)
}
"""

files_data["examples/l7/telnet/telnet_window_size_naws_negotiation.fasm"] = """// PROMPT: Negotiate About Window Size option negotiation using IAC DO 31.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DO, WILL, COMPILE

// INSTRUCTION: Define graphical terminal emulator.
HOST gui_term { IP 172.16.8.50 }

// INSTRUCTION: Define Unix main server.
HOST unix_main { IP 172.16.8.1 }

// INSTRUCTION: Define NAWS option negotiation flow.
FLOW telnet_naws_flow(c, s) {
    c <- s TELNET DO 31
    c -> s TELNET WILL 31
}

// INSTRUCTION: Compile block executing NAWS negotiation.
COMPILE {
    telnet_naws_flow(gui_term, unix_main)
}
"""

files_data["examples/l7/telnet/telnet_dont_terminal_speed_option.fasm"] = """// PROMPT: Server rejecting terminal speed subnegotiation with IAC DONT 32.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, WILL, DONT, COMPILE

// INSTRUCTION: Define legacy terminal client.
HOST legacy_client { IP 192.168.12.9 }

// INSTRUCTION: Define terminal concentrator.
HOST term_concentrator { IP 192.168.12.2 }

// INSTRUCTION: Define terminal speed rejection flow.
FLOW telnet_speed_reject_flow(c, s) {
    c -> s TELNET WILL 32
    c <- s TELNET DONT 32
}

// INSTRUCTION: Compile block executing speed option refusal.
COMPILE {
    telnet_speed_reject_flow(legacy_client, term_concentrator)
}
"""

files_data["examples/l7/telnet/telnet_wont_linemode_option.fasm"] = """// PROMPT: Client declining linemode operation using IAC WONT 34.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DO, WONT, COMPILE

// INSTRUCTION: Define dumb terminal display.
HOST dumb_term { IP 10.30.0.14 }

// INSTRUCTION: Define timesharing host.
HOST timeshare_host { IP 10.30.0.1 }

// INSTRUCTION: Define linemode decline flow.
FLOW telnet_linemode_flow(c, s) {
    c <- s TELNET DO 34
    c -> s TELNET WONT 34
}

// INSTRUCTION: Compile block executing linemode refusal.
COMPILE {
    telnet_linemode_flow(dumb_term, timeshare_host)
}
"""

files_data["examples/l7/telnet/telnet_router_password_prompt_flow.fasm"] = """// PROMPT: Core router presenting password challenge string to connected client.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DATA, COMPILE

// INSTRUCTION: Define field engineer laptop.
HOST field_eng { IP 192.168.20.100 }

// INSTRUCTION: Define field distribution switch.
HOST dist_switch { IP 192.168.20.1 }

// INSTRUCTION: Define password challenge prompt flow.
FLOW telnet_password_prompt(c, s) {
    c <- s TELNET DATA "User Access Verification\\r\\nPassword: "
    c -> s TELNET DATA "cisco123\\r\\n"
}

// INSTRUCTION: Compile block executing password prompt exchange.
COMPILE {
    telnet_password_prompt(field_eng, dist_switch)
}
"""

files_data["examples/l7/telnet/telnet_switch_cli_banner_motd.fasm"] = """// PROMPT: Network switch presenting Message of the Day security warning banner.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DATA, COMPILE

// INSTRUCTION: Define operator terminal.
HOST oper_term { IP 10.75.1.40 }

// INSTRUCTION: Define edge switch device.
HOST edge_sw_dev { IP 10.75.1.1 }

// INSTRUCTION: Define MOTD banner presentation flow.
FLOW telnet_motd_flow(c, s) {
    c <- s TELNET DATA "Authorized Personnel Only. Violators will be prosecuted.\\r\\n"
    c <- s TELNET DATA "Switch-01> "
}

// INSTRUCTION: Compile block executing MOTD banner display.
COMPILE {
    telnet_motd_flow(oper_term, edge_sw_dev)
}
"""

files_data["examples/l7/telnet/telnet_cli_command_show_version.fasm"] = """// PROMPT: Management station sending show version command string to switch CLI.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DATA, COMPILE

// INSTRUCTION: Define NOC administration host.
HOST noc_admin { IP 172.22.4.18 }

// INSTRUCTION: Define target router device.
HOST target_router { IP 172.22.4.1 }

// INSTRUCTION: Define CLI command and response flow.
FLOW telnet_show_ver_flow(c, s) {
    c -> s TELNET DATA "show version\\r\\n"
    c <- s TELNET DATA "Cisco IOS Software, C2960 Software, Version 15.2(2)E\\r\\n"
}

// INSTRUCTION: Compile block executing show version interaction.
COMPILE {
    telnet_show_ver_flow(noc_admin, target_router)
}
"""

files_data["examples/l7/telnet/telnet_logout_exit_command.fasm"] = """// PROMPT: Administrative user sending exit command data to close telnet terminal.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DATA, COMPILE

// INSTRUCTION: Define departing operator workstation.
HOST departing_op { IP 192.168.60.25 }

// INSTRUCTION: Define active access router.
HOST active_rtr { IP 192.168.60.1 }

// INSTRUCTION: Define exit session termination flow.
FLOW telnet_exit_flow(c, s) {
    c -> s TELNET DATA "exit\\r\\n"
    c <- s TELNET DATA "Connection closed by foreign host.\\r\\n"
}

// INSTRUCTION: Compile block executing session exit.
COMPILE {
    telnet_exit_flow(departing_op, active_rtr)
}
"""

files_data["examples/l7/telnet/telnet_legacy_scada_rtu_poll.fasm"] = """// PROMPT: Legacy industrial RTU serial-to-ethernet console telemetry query.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DATA, COMPILE

// INSTRUCTION: Define SCADA polling master.
HOST scada_poller { IP 10.12.34.50 }

// INSTRUCTION: Define industrial terminal server RTU.
HOST scada_rtu { IP 10.12.34.1 }

// INSTRUCTION: Define RTU telemetry query flow.
FLOW telnet_rtu_flow(c, s) {
    c -> s TELNET DATA "READ STATUS\\r\\n"
    c <- s TELNET DATA "STATUS=OK VOLT=24.2 CURRENT=1.4A\\r\\n"
}

// INSTRUCTION: Compile block executing RTU polling.
COMPILE {
    telnet_rtu_flow(scada_poller, scada_rtu)
}
"""

files_data["examples/l7/telnet/telnet_ipv6_legacy_terminal_session.fasm"] = """// PROMPT: IPv6 terminal session negotiating character echo on port 23.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DO, WILL, COMPILE

// INSTRUCTION: Define IPv6 terminal workstation.
HOST term_v6_client { IP 2001:db8:beef::20 }

// INSTRUCTION: Define IPv6 access node.
HOST term_v6_server { IP 2001:db8:beef::1 }

// INSTRUCTION: Define IPv6 Telnet option negotiation flow.
FLOW telnet_v6_echo_flow(c, s) {
    c -> s TELNET DO 1
    c <- s TELNET WILL 1
}

// INSTRUCTION: Compile block executing IPv6 negotiation.
COMPILE {
    telnet_v6_echo_flow(term_v6_client, term_v6_server)
}
"""

files_data["examples/l7/telnet/telnet_port_listener_healthcheck_loop.fasm"] = """// PROMPT: Periodic telnet listener availability probe in a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, <-, TELNET, DO, WILL, COMPILE, LOOP

// INSTRUCTION: Define automated health monitor.
HOST health_mon { IP 172.30.9.15 }

// INSTRUCTION: Define monitored network switch.
HOST mon_switch { IP 172.30.9.1 }

// INSTRUCTION: Define availability ping flow.
FLOW telnet_health_flow(c, s) {
    c -> s TELNET DO 1
    c <- s TELNET WILL 1
}

// INSTRUCTION: Compile block executing 3 health probe cycles.
COMPILE {
    LOOP 3 {
        telnet_health_flow(health_mon, mon_switch)
    }
}
"""

# ==========================================
# 8. TFTP (12 new files)
# ==========================================
files_data["examples/l7/tftp/tftp_rrq_firmware_octet_mode.fasm"] = """// PROMPT: Read request downloading router firmware image in octet binary mode.
// TOKENS: HOST, IP, FLOW, ->, TFTP, RRQ, FILENAME, MODE, COMPILE

// INSTRUCTION: Define network switch upgrading firmware.
HOST upgrading_sw { IP 192.168.1.25 }

// INSTRUCTION: Define central TFTP repository.
HOST tftp_repo { IP 192.168.1.1 }

// INSTRUCTION: Define firmware download request flow.
FLOW tftp_fw_flow(c, s) {
    c -> s TFTP RRQ
        FILENAME "c2960x-universalk9-mz.152-7.E0a.bin"
        MODE "octet"
}

// INSTRUCTION: Compile block executing firmware RRQ.
COMPILE {
    tftp_fw_flow(upgrading_sw, tftp_repo)
}
"""

files_data["examples/l7/tftp/tftp_rrq_startup_config_netascii.fasm"] = """// PROMPT: Read request downloading startup configuration file in netascii mode.
// TOKENS: HOST, IP, FLOW, ->, TFTP, RRQ, FILENAME, MODE, COMPILE

// INSTRUCTION: Define edge router provisioning node.
HOST prov_rtr { IP 10.20.1.15 }

// INSTRUCTION: Define configuration repository TFTP server.
HOST cfg_tftp_svr { IP 10.20.1.1 }

// INSTRUCTION: Define netascii configuration download flow.
FLOW tftp_cfg_download(c, s) {
    c -> s TFTP RRQ
        FILENAME "router-startup-config.cfg"
        MODE "netascii"
}

// INSTRUCTION: Compile block executing config RRQ.
COMPILE {
    tftp_cfg_download(prov_rtr, cfg_tftp_svr)
}
"""

files_data["examples/l7/tftp/tftp_rrq_pxe_bootloader_image.fasm"] = """// PROMPT: Read request downloading PXE network boot loader pxelinux.0.
// TOKENS: HOST, IP, FLOW, ->, TFTP, RRQ, FILENAME, MODE, COMPILE

// INSTRUCTION: Define bare-metal compute node booting via PXE.
HOST pxe_client { IP 172.16.100.45 }

// INSTRUCTION: Define PXE boot TFTP server.
HOST pxe_tftp_host { IP 172.16.100.1 }

// INSTRUCTION: Define PXE bootloader retrieval flow.
FLOW tftp_pxe_flow(c, s) {
    c -> s TFTP RRQ
        FILENAME "pxelinux.0"
        MODE "octet"
}

// INSTRUCTION: Compile block executing PXE loader request.
COMPILE {
    tftp_pxe_flow(pxe_client, pxe_tftp_host)
}
"""

files_data["examples/l7/tftp/tftp_wrq_crash_dump_octet.fasm"] = """// PROMPT: Write request uploading kernel crash dump file to diagnostic TFTP server.
// TOKENS: HOST, IP, FLOW, ->, TFTP, WRQ, FILENAME, MODE, COMPILE

// INSTRUCTION: Define recovering host uploading diagnostic dump.
HOST crash_host { IP 10.80.4.12 }

// INSTRUCTION: Define diagnostic collection TFTP server.
HOST diag_tftp { IP 10.80.4.1 }

// INSTRUCTION: Define crash dump upload WRQ flow.
FLOW tftp_crash_upload(c, s) {
    c -> s TFTP WRQ
        FILENAME "vmcore-panic-20261024.dmp"
        MODE "octet"
}

// INSTRUCTION: Compile block executing crash dump upload.
COMPILE {
    tftp_crash_upload(crash_host, diag_tftp)
}
"""

files_data["examples/l7/tftp/tftp_wrq_switch_backup_archive.fasm"] = """// PROMPT: Write request uploading archived network switch configuration backup.
// TOKENS: HOST, IP, FLOW, ->, TFTP, WRQ, FILENAME, MODE, COMPILE

// INSTRUCTION: Define core switch initiating backup.
HOST core_sw_backup { IP 192.168.10.1 }

// INSTRUCTION: Define backup archive TFTP server.
HOST archive_tftp { IP 192.168.10.250 }

// INSTRUCTION: Define backup archive upload flow.
FLOW tftp_backup_upload(c, s) {
    c -> s TFTP WRQ
        FILENAME "core_switch_config_oct2026.tar.gz"
        MODE "octet"
}

// INSTRUCTION: Compile block executing backup WRQ.
COMPILE {
    tftp_backup_upload(core_sw_backup, archive_tftp)
}
"""

files_data["examples/l7/tftp/tftp_error_file_not_found.fasm"] = """// PROMPT: TFTP error response returning ERRCODE 1 File Not Found.
// TOKENS: HOST, IP, FLOW, ->, <-, TFTP, RRQ, FILENAME, MODE, ERRCODE, ERRMSG, COMPILE

// INSTRUCTION: Define querying client requesting missing file.
HOST query_client { IP 10.10.10.8 }

// INSTRUCTION: Define TFTP server returning error.
HOST error_tftp_svr { IP 10.10.10.1 }

// INSTRUCTION: Define File Not Found error transaction flow.
FLOW tftp_err_not_found(c, s) {
    c -> s TFTP RRQ FILENAME "nonexistent_image.bin" MODE "octet"
    c <- s TFTP ERRCODE 1 ERRMSG "File not found"
}

// INSTRUCTION: Compile block executing error response.
COMPILE {
    tftp_err_not_found(query_client, error_tftp_svr)
}
"""

files_data["examples/l7/tftp/tftp_error_access_violation.fasm"] = """// PROMPT: TFTP error packet returning ERRCODE 2 Access Violation.
// TOKENS: HOST, IP, FLOW, ->, <-, TFTP, WRQ, FILENAME, MODE, ERRCODE, ERRMSG, COMPILE

// INSTRUCTION: Define unauthorized client requesting restricted file.
HOST unauth_tftp_cli { IP 172.20.0.50 }

// INSTRUCTION: Define secure TFTP server.
HOST secure_tftp_svr { IP 172.20.0.1 }

// INSTRUCTION: Define Access Violation error flow.
FLOW tftp_err_access_viol(c, s) {
    c -> s TFTP WRQ FILENAME "system_root.key" MODE "octet"
    c <- s TFTP ERRCODE 2 ERRMSG "Access violation"
}

// INSTRUCTION: Compile block executing access violation error.
COMPILE {
    tftp_err_access_viol(unauth_tftp_cli, secure_tftp_svr)
}
"""

files_data["examples/l7/tftp/tftp_error_disk_full_allocation.fasm"] = """// PROMPT: TFTP error packet returning ERRCODE 3 Disk Full or Allocation Exceeded.
// TOKENS: HOST, IP, FLOW, ->, <-, TFTP, WRQ, FILENAME, MODE, ERRCODE, ERRMSG, COMPILE

// INSTRUCTION: Define client uploading large file.
HOST large_uploader { IP 192.168.90.15 }

// INSTRUCTION: Define storage exhausted TFTP server.
HOST full_storage_svr { IP 192.168.90.1 }

// INSTRUCTION: Define Disk Full error transaction flow.
FLOW tftp_err_disk_full(c, s) {
    c -> s TFTP WRQ FILENAME "large_backup_volume.img" MODE "octet"
    c <- s TFTP ERRCODE 3 ERRMSG "Disk full or allocation exceeded"
}

// INSTRUCTION: Compile block executing disk full error.
COMPILE {
    tftp_err_disk_full(large_uploader, full_storage_svr)
}
"""

files_data["examples/l7/tftp/tftp_error_illegal_operation.fasm"] = """// PROMPT: TFTP error packet returning ERRCODE 4 Illegal TFTP Operation.
// TOKENS: HOST, IP, FLOW, ->, <-, TFTP, RRQ, FILENAME, MODE, ERRCODE, ERRMSG, COMPILE

// INSTRUCTION: Define misconfigured client node.
HOST malformed_cli { IP 10.35.1.99 }

// INSTRUCTION: Define strict TFTP parser host.
HOST strict_tftp_host { IP 10.35.1.1 }

// INSTRUCTION: Define Illegal Operation error flow.
FLOW tftp_err_illegal_op(c, s) {
    c -> s TFTP RRQ FILENAME "bad_request" MODE "unsupported_mode"
    c <- s TFTP ERRCODE 4 ERRMSG "Illegal TFTP operation"
}

// INSTRUCTION: Compile block executing illegal operation error.
COMPILE {
    tftp_err_illegal_op(malformed_cli, strict_tftp_host)
}
"""

files_data["examples/l7/tftp/tftp_error_unknown_transfer_id.fasm"] = """// PROMPT: TFTP error packet returning ERRCODE 5 Unknown Transfer ID.
// TOKENS: HOST, IP, FLOW, ->, <-, TFTP, ERRCODE, ERRMSG, COMPILE

// INSTRUCTION: Define out-of-sync client endpoint.
HOST tid_client { IP 192.168.5.7 }

// INSTRUCTION: Define TFTP server enforcing TID validation.
HOST tid_server { IP 192.168.5.1 }

// INSTRUCTION: Define unknown TID error response flow.
FLOW tftp_err_tid_flow(c, s) {
    c <- s TFTP ERRCODE 5 ERRMSG "Unknown transfer ID"
}

// INSTRUCTION: Compile block executing unknown TID notification.
COMPILE {
    tftp_err_tid_flow(tid_client, tid_server)
}
"""

files_data["examples/l7/tftp/tftp_ipv6_pxe_boot_provisioning.fasm"] = """// PROMPT: IPv6 enterprise client requesting network bootstrap provisioning file.
// TOKENS: HOST, IP, FLOW, ->, TFTP, RRQ, FILENAME, MODE, COMPILE

// INSTRUCTION: Define IPv6 UEFI PXE boot station.
HOST uefi_station_v6 { IP 2001:db8:aaaa::30 }

// INSTRUCTION: Define IPv6 enterprise TFTP deployment server.
HOST deploy_tftp_v6 { IP 2001:db8:aaaa::1 }

// INSTRUCTION: Define IPv6 EFI bootloader retrieval flow.
FLOW tftp_v6_uefi_flow(c, s) {
    c -> s TFTP RRQ
        FILENAME "bootx64.efi"
        MODE "octet"
}

// INSTRUCTION: Compile block executing IPv6 bootloader request.
COMPILE {
    tftp_v6_uefi_flow(uefi_station_v6, deploy_tftp_v6)
}
"""

files_data["examples/l7/tftp/tftp_batch_config_backup_loop.fasm"] = """// PROMPT: Automated configuration backup trigger loop across multiple network switches.
// TOKENS: HOST, IP, FLOW, ->, TFTP, WRQ, FILENAME, MODE, COMPILE, LOOP

// INSTRUCTION: Define backup orchestrator client.
HOST orch_client { IP 172.28.1.10 }

// INSTRUCTION: Define central configuration TFTP store.
HOST store_tftp { IP 172.28.1.1 }

// INSTRUCTION: Define switch backup file push flow.
FLOW tftp_loop_backup(c, s) {
    c -> s TFTP WRQ
        FILENAME "switch_config_batch.cfg"
        MODE "octet"
}

// INSTRUCTION: Compile block executing 3 backup upload triggers.
COMPILE {
    LOOP 3 {
        tftp_loop_backup(orch_client, store_tftp)
    }
}
"""

# ==========================================
# 9. TLS (12 new files)
# ==========================================
files_data["examples/l7/tls/tls_server_hello_cipher_select.fasm"] = """// PROMPT: TLS server hello selecting AES-128-GCM cipher suite and handshake parameters.
// TOKENS: HOST, IP, FLOW, ->, <-, TLS, CLIENT_HELLO, SERVER_HELLO, SNI, COMPILE

// INSTRUCTION: Define web browser client.
HOST browser_host { IP 10.10.1.20 }

// INSTRUCTION: Define secure web server.
HOST web_server { IP 10.10.1.1 }

// INSTRUCTION: Define ServerHello selection flow.
FLOW tls_server_hello_flow(c, s) {
    c -> s TLS CLIENT_HELLO SNI "www.example.com"
    c <- s TLS SERVER_HELLO
}

// INSTRUCTION: Compile block executing ServerHello selection.
COMPILE {
    tls_server_hello_flow(browser_host, web_server)
}
"""

files_data["examples/l7/tls/tls_client_hello_http2_alpn.fasm"] = """// PROMPT: Client hello offering ALPN h2 application negotiation and SNI domain.
// TOKENS: HOST, IP, FLOW, ->, TLS, CLIENT_HELLO, SNI, ALPN, COMPILE

// INSTRUCTION: Define microservice API consumer.
HOST api_consumer { IP 172.16.50.15 }

// INSTRUCTION: Define cloud API gateway.
HOST api_gateway { IP 172.16.50.1 }

// INSTRUCTION: Define ClientHello with h2 ALPN flow.
FLOW tls_alpn_h2_flow(c, s) {
    c -> s TLS CLIENT_HELLO
        SNI "api.service.internal"
        ALPN "h2"
}

// INSTRUCTION: Compile block executing h2 ALPN request.
COMPILE {
    tls_alpn_h2_flow(api_consumer, api_gateway)
}
"""

files_data["examples/l7/tls/tls_client_hello_http3_alpn.fasm"] = """// PROMPT: Client hello offering ALPN h3 next-generation transport negotiation.
// TOKENS: HOST, IP, FLOW, ->, TLS, CLIENT_HELLO, SNI, ALPN, COMPILE

// INSTRUCTION: Define mobile application endpoint.
HOST mobile_app { IP 192.168.10.99 }

// INSTRUCTION: Define edge CDN POP server.
HOST cdn_edge { IP 192.168.10.1 }

// INSTRUCTION: Define ClientHello with h3 ALPN flow.
FLOW tls_alpn_h3_flow(c, s) {
    c -> s TLS CLIENT_HELLO
        SNI "cdn.fast-delivery.net"
        ALPN "h3"
}

// INSTRUCTION: Compile block executing h3 ALPN advertisement.
COMPILE {
    tls_alpn_h3_flow(mobile_app, cdn_edge)
}
"""

files_data["examples/l7/tls/tls_client_hello_multi_domain_sni.fasm"] = """// PROMPT: Client hello specifying enterprise internal portal SNI host indicator.
// TOKENS: HOST, IP, FLOW, ->, TLS, CLIENT_HELLO, SNI, COMPILE

// INSTRUCTION: Define corporate employee laptop.
HOST corp_laptop { IP 10.200.5.40 }

// INSTRUCTION: Define internal portal load balancer.
HOST portal_lb { IP 10.200.5.1 }

// INSTRUCTION: Define multi-domain portal SNI flow.
FLOW tls_portal_sni_flow(c, s) {
    c -> s TLS CLIENT_HELLO
        SNI "portal.corp.internal.net"
}

// INSTRUCTION: Compile block executing internal portal SNI request.
COMPILE {
    tls_portal_sni_flow(corp_laptop, portal_lb)
}
"""

files_data["examples/l7/tls/tls_record_version_tls12_legacy.fasm"] = """// PROMPT: TLS handshake record specifying legacy version 0x0303 compatibility.
// TOKENS: HOST, IP, FLOW, ->, TLS, CLIENT_HELLO, RECORD_VERSION, SNI, COMPILE

// INSTRUCTION: Define legacy banking terminal.
HOST legacy_terminal { IP 172.28.1.18 }

// INSTRUCTION: Define core transaction gateway.
HOST txn_gateway { IP 172.28.1.2 }

// INSTRUCTION: Define TLS 1.2 compatibility layer flow.
FLOW tls_legacy_ver_flow(c, s) {
    c -> s TLS CLIENT_HELLO
        RECORD_VERSION 771
        SNI "secure-banking.vault.org"
}

// INSTRUCTION: Compile block executing TLS 1.2 record flow.
COMPILE {
    tls_legacy_ver_flow(legacy_terminal, txn_gateway)
}
"""

files_data["examples/l7/tls/tls_alert_handshake_failure.fasm"] = """// PROMPT: TLS alert record signaling fatal handshake failure to peer endpoint.
// TOKENS: HOST, IP, FLOW, ->, <-, TLS, CLIENT_HELLO, ALERT, COMPILE

// INSTRUCTION: Define incompatible client cipher suite requester.
HOST incomp_client { IP 192.168.70.33 }

// INSTRUCTION: Define strict cipher policy server.
HOST strict_sec_svr { IP 192.168.70.1 }

// INSTRUCTION: Define TLS handshake failure alert flow.
FLOW tls_handshake_fail_flow(c, s) {
    c -> s TLS CLIENT_HELLO SNI "hardened.vault.local"
    c <- s TLS ALERT
}

// INSTRUCTION: Compile block executing handshake failure alert.
COMPILE {
    tls_handshake_fail_flow(incomp_client, strict_sec_svr)
}
"""

files_data["examples/l7/tls/tls_alert_bad_certificate.fasm"] = """// PROMPT: TLS alert record signaling rejected certificate validation failure.
// TOKENS: HOST, IP, FLOW, ->, <-, TLS, CLIENT_HELLO, SERVER_HELLO, ALERT, COMPILE

// INSTRUCTION: Define validating client endpoint.
HOST val_client { IP 10.90.14.8 }

// INSTRUCTION: Define untrusted certificate server.
HOST untrusted_server { IP 10.90.14.1 }

// INSTRUCTION: Define bad certificate alert rejection flow.
FLOW tls_bad_cert_flow(c, s) {
    c -> s TLS CLIENT_HELLO SNI "untrusted.domain.net"
    c <- s TLS SERVER_HELLO
    c -> s TLS ALERT
}

// INSTRUCTION: Compile block executing bad certificate alert.
COMPILE {
    tls_bad_cert_flow(val_client, untrusted_server)
}
"""

files_data["examples/l7/tls/tls_application_data_encrypted_payload.fasm"] = """// PROMPT: TLS application data record transmitting encrypted secure web payload.
// TOKENS: HOST, IP, FLOW, ->, <-, TLS, APP_DATA, COMPILE

// INSTRUCTION: Define established session client.
HOST established_client { IP 192.168.100.4 }

// INSTRUCTION: Define established session server.
HOST established_server { IP 192.168.100.1 }

// INSTRUCTION: Define encrypted application data transmission flow.
FLOW tls_app_data_flow(c, s) {
    c -> s TLS APP_DATA
    c <- s TLS APP_DATA
}

// INSTRUCTION: Compile block executing application data flow.
COMPILE {
    tls_app_data_flow(established_client, established_server)
}
"""

files_data["examples/l7/tls/tls_handshake_finished_verify.fasm"] = """// PROMPT: TLS finished handshake verification record confirming key exchange completion.
// TOKENS: HOST, IP, FLOW, ->, <-, TLS, CLIENT_HELLO, SERVER_HELLO, FINISHED, COMPILE

// INSTRUCTION: Define authenticating client host.
HOST auth_client_node { IP 10.115.1.10 }

// INSTRUCTION: Define authenticating server node.
HOST auth_server_node { IP 10.115.1.1 }

// INSTRUCTION: Define finished verification handshake flow.
FLOW tls_finished_flow(c, s) {
    c -> s TLS CLIENT_HELLO SNI "auth.internal.org"
    c <- s TLS SERVER_HELLO
    c -> s TLS FINISHED
    c <- s TLS FINISHED
}

// INSTRUCTION: Compile block executing finished verification exchange.
COMPILE {
    tls_finished_flow(auth_client_node, auth_server_node)
}
"""

files_data["examples/l7/tls/tls_ipv6_secure_gateway_handshake.fasm"] = """// PROMPT: IPv6 mutual TLS handshake exchange between gateway edge nodes.
// TOKENS: HOST, IP, FLOW, ->, <-, TLS, CLIENT_HELLO, SERVER_HELLO, SNI, COMPILE

// INSTRUCTION: Define IPv6 edge gateway client.
HOST gw_client_v6 { IP 2001:db8:9999::55 }

// INSTRUCTION: Define IPv6 cloud gateway server.
HOST gw_server_v6 { IP 2001:db8:9999::1 }

// INSTRUCTION: Define IPv6 TLS connection handshake flow.
FLOW tls_v6_gateway_flow(c, s) {
    c -> s TLS CLIENT_HELLO SNI "gateway.ipv6-cloud.org"
    c <- s TLS SERVER_HELLO
}

// INSTRUCTION: Compile block executing IPv6 gateway handshake.
COMPILE {
    tls_v6_gateway_flow(gw_client_v6, gw_server_v6)
}
"""

files_data["examples/l7/tls/tls_vlan_tagged_secure_api_flow.fasm"] = """// PROMPT: VLAN 400 tagged secure API transaction with AF41 differentiated service.
// TOKENS: HOST, IP, FLOW, ->, <-, TLS, CLIENT_HELLO, SERVER_HELLO, SNI, VLAN, PCP, DEI, DSCP, COMPILE

// INSTRUCTION: Define secure banking application host.
HOST secure_app_host { IP 10.40.100.8 }

// INSTRUCTION: Define financial transaction core.
HOST fin_core { IP 10.40.100.1 }

// INSTRUCTION: Define prioritized VLAN TLS session flow.
FLOW tls_vlan_tagged_flow(c, s) {
    c -> s TLS CLIENT_HELLO
        SNI "fin-api.banking.net"
        VLAN 400 PCP 4 DEI 0 DSCP 34
    c <- s TLS SERVER_HELLO
        VLAN 400 PCP 4 DEI 0 DSCP 34
}

// INSTRUCTION: Compile block executing prioritized VLAN TLS session.
COMPILE {
    tls_vlan_tagged_flow(secure_app_host, fin_core)
}
"""

files_data["examples/l7/tls/tls_load_balancer_health_probe_loop.fasm"] = """// PROMPT: Edge load balancer TLS ClientHello health probe in a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, <-, TLS, CLIENT_HELLO, SERVER_HELLO, SNI, COMPILE, LOOP

// INSTRUCTION: Define edge load balancer node.
HOST lb_probe_node { IP 192.168.220.10 }

// INSTRUCTION: Define upstream web backend.
HOST web_backend { IP 192.168.220.1 }

// INSTRUCTION: Define repeated TLS health probe flow.
FLOW tls_health_probe(c, s) {
    c -> s TLS CLIENT_HELLO SNI "healthcheck.backend.local"
    c <- s TLS SERVER_HELLO
}

// INSTRUCTION: Compile block executing 3 repeated health probe checks.
COMPILE {
    LOOP 3 {
        tls_health_probe(lb_probe_node, web_backend)
    }
}
"""

# ==========================================
# 10. WEBSOCKET (12 new files)
# ==========================================
files_data["examples/l7/websocket/websocket_text_masked_client_message.fasm"] = """// PROMPT: Client-to-server masked text frame transmitting JSON message with FIN bit.
// TOKENS: HOST, IP, FLOW, ->, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define web application browser.
HOST web_browser { IP 192.168.1.88 }

// INSTRUCTION: Define real-time WebSocket server.
HOST ws_server { IP 192.168.1.1 }

// INSTRUCTION: Define masked text frame transmission flow.
FLOW ws_masked_text_flow(c, s) {
    c -> s WEBSOCKET
        OPCODE "TEXT"
        FIN_BIT 1
        MASK_KEY 305419896
}

// INSTRUCTION: Compile block executing masked text frame transmission.
COMPILE {
    ws_masked_text_flow(web_browser, ws_server)
}
"""

files_data["examples/l7/websocket/websocket_binary_protobuf_telemetry.fasm"] = """// PROMPT: Binary opcode WebSocket frame transporting serialized sensor telemetry.
// TOKENS: HOST, IP, FLOW, ->, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define industrial IoT gateway client.
HOST iot_gateway { IP 10.10.4.15 }

// INSTRUCTION: Define cloud telemetry ingestion node.
HOST cloud_telemetry { IP 10.10.4.1 }

// INSTRUCTION: Define binary telemetry transmission flow.
FLOW ws_binary_flow(c, s) {
    c -> s WEBSOCKET
        OPCODE "BINARY"
        FIN_BIT 1
        MASK_KEY 1437227610
}

// INSTRUCTION: Compile block executing binary telemetry transmission.
COMPILE {
    ws_binary_flow(iot_gateway, cloud_telemetry)
}
"""

files_data["examples/l7/websocket/websocket_client_heartbeat_ping.fasm"] = """// PROMPT: Client liveness heartbeat ping frame with 32-bit masking key.
// TOKENS: HOST, IP, FLOW, ->, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define active client connection.
HOST client_conn { IP 172.16.2.9 }

// INSTRUCTION: Define streaming broker host.
HOST stream_broker { IP 172.16.2.1 }

// INSTRUCTION: Define heartbeat ping frame flow.
FLOW ws_ping_flow(c, s) {
    c -> s WEBSOCKET
        OPCODE "PING"
        FIN_BIT 1
        MASK_KEY 2863311530
}

// INSTRUCTION: Compile block executing heartbeat ping.
COMPILE {
    ws_ping_flow(client_conn, stream_broker)
}
"""

files_data["examples/l7/websocket/websocket_server_heartbeat_pong.fasm"] = """// PROMPT: Server unmasked pong frame confirming connection availability.
// TOKENS: HOST, IP, FLOW, ->, <-, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define interactive web client.
HOST inter_client { IP 192.168.4.12 }

// INSTRUCTION: Define interactive hub server.
HOST hub_server { IP 192.168.4.1 }

// INSTRUCTION: Define ping pong response flow.
FLOW ws_pong_response_flow(c, s) {
    c -> s WEBSOCKET OPCODE "PING" FIN_BIT 1 MASK_KEY 1985229328
    c <- s WEBSOCKET OPCODE "PONG" FIN_BIT 1 MASK_KEY 0
}

// INSTRUCTION: Compile block executing pong confirmation.
COMPILE {
    ws_pong_response_flow(inter_client, hub_server)
}
"""

files_data["examples/l7/websocket/websocket_connection_close_normal.fasm"] = """// PROMPT: WebSocket connection termination frame with CLOSE opcode and FIN bit 1.
// TOKENS: HOST, IP, FLOW, ->, <-, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define client closing connection.
HOST closing_client { IP 10.30.5.8 }

// INSTRUCTION: Define connected server instance.
HOST connected_svr { IP 10.30.5.1 }

// INSTRUCTION: Define graceful connection closure flow.
FLOW ws_close_flow(c, s) {
    c -> s WEBSOCKET OPCODE "CLOSE" FIN_BIT 1 MASK_KEY 2588014022
    c <- s WEBSOCKET OPCODE "CLOSE" FIN_BIT 1 MASK_KEY 0
}

// INSTRUCTION: Compile block executing clean close handshake.
COMPILE {
    ws_close_flow(closing_client, connected_svr)
}
"""

files_data["examples/l7/websocket/websocket_fragmented_first_text_frame.fasm"] = """// PROMPT: First fragment of multi-frame payload specifying FIN bit 0 and TEXT opcode.
// TOKENS: HOST, IP, FLOW, ->, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define streaming client sending large document.
HOST doc_client { IP 172.20.15.4 }

// INSTRUCTION: Define document indexing server.
HOST index_server { IP 172.20.15.1 }

// INSTRUCTION: Define fragmented initial frame flow.
FLOW ws_frag_first_flow(c, s) {
    c -> s WEBSOCKET
        OPCODE "TEXT"
        FIN_BIT 0
        MASK_KEY 3735928559
}

// INSTRUCTION: Compile block executing first fragment transmission.
COMPILE {
    ws_frag_first_flow(doc_client, index_server)
}
"""

files_data["examples/l7/websocket/websocket_fragmented_final_continuation.fasm"] = """// PROMPT: Final fragment of multi-frame message with FIN bit 1 completing payload.
// TOKENS: HOST, IP, FLOW, ->, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define data transmitter host.
HOST data_tx_host { IP 192.168.8.18 }

// INSTRUCTION: Define data collector host.
HOST data_rx_host { IP 192.168.8.1 }

// INSTRUCTION: Define final fragment completion flow.
FLOW ws_frag_final_flow(c, s) {
    c -> s WEBSOCKET
        OPCODE "TEXT"
        FIN_BIT 1
        MASK_KEY 1122334455
}

// INSTRUCTION: Compile block executing final fragment transmission.
COMPILE {
    ws_frag_final_flow(data_tx_host, data_rx_host)
}
"""

files_data["examples/l7/websocket/websocket_market_data_ticker_feed.fasm"] = """// PROMPT: Financial exchange market data streaming ticker updates via text frames.
// TOKENS: HOST, IP, FLOW, ->, <-, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define algorithmic trading workstation.
HOST algo_trader { IP 10.99.1.5 }

// INSTRUCTION: Define low-latency market exchange server.
HOST exchange_engine { IP 10.99.1.1 }

// INSTRUCTION: Define market quote streaming flow.
FLOW ws_ticker_flow(c, s) {
    c -> s WEBSOCKET OPCODE "TEXT" FIN_BIT 1 MASK_KEY 876543210
    c <- s WEBSOCKET OPCODE "TEXT" FIN_BIT 1 MASK_KEY 0
}

// INSTRUCTION: Compile block executing market ticker updates.
COMPILE {
    ws_ticker_flow(algo_trader, exchange_engine)
}
"""

files_data["examples/l7/websocket/websocket_chat_channel_broadcast.fasm"] = """// PROMPT: Multi-user chat broadcast message delivered via WebSocket text frame.
// TOKENS: HOST, IP, FLOW, ->, <-, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define chat client user node.
HOST chat_user { IP 192.168.55.19 }

// INSTRUCTION: Define chat channel relay server.
HOST chat_relay { IP 192.168.55.1 }

// INSTRUCTION: Define chat message exchange flow.
FLOW ws_chat_flow(c, s) {
    c -> s WEBSOCKET OPCODE "TEXT" FIN_BIT 1 MASK_KEY 1234567890
    c <- s WEBSOCKET OPCODE "TEXT" FIN_BIT 1 MASK_KEY 0
}

// INSTRUCTION: Compile block executing chat message delivery.
COMPILE {
    ws_chat_flow(chat_user, chat_relay)
}
"""

files_data["examples/l7/websocket/websocket_iot_sensor_metric_stream.fasm"] = """// PROMPT: Industrial sensor streaming continuous metrics via WebSocket frames.
// TOKENS: HOST, IP, FLOW, ->, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define manufacturing line vibration sensor.
HOST vibration_sensor { IP 10.70.3.14 }

// INSTRUCTION: Define factory floor telemetry receiver.
HOST floor_receiver { IP 10.70.3.1 }

// INSTRUCTION: Define telemetry metric transmission flow.
FLOW ws_sensor_metric_flow(c, s) {
    c -> s WEBSOCKET
        OPCODE "BINARY"
        FIN_BIT 1
        MASK_KEY 2468135790
}

// INSTRUCTION: Compile block executing sensor metric streaming.
COMPILE {
    ws_sensor_metric_flow(vibration_sensor, floor_receiver)
}
"""

files_data["examples/l7/websocket/websocket_ipv6_streaming_telemetry.fasm"] = """// PROMPT: IPv6 real-time monitoring session with masked WebSocket data frames.
// TOKENS: HOST, IP, FLOW, ->, <-, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE

// INSTRUCTION: Define IPv6 monitoring console client.
HOST console_v6 { IP 2001:db8:4444::12 }

// INSTRUCTION: Define IPv6 telemetry broadcast server.
HOST broadcast_v6 { IP 2001:db8:4444::1 }

// INSTRUCTION: Define IPv6 streaming telemetry flow.
FLOW ws_v6_stream_flow(c, s) {
    c -> s WEBSOCKET OPCODE "TEXT" FIN_BIT 1 MASK_KEY 3456789012
    c <- s WEBSOCKET OPCODE "TEXT" FIN_BIT 1 MASK_KEY 0
}

// INSTRUCTION: Compile block executing IPv6 streaming session.
COMPILE {
    ws_v6_stream_flow(console_v6, broadcast_v6)
}
"""

files_data["examples/l7/websocket/websocket_recurring_ping_pong_loop.fasm"] = """// PROMPT: Periodic WebSocket connection keepalive ping pong exchange loop.
// TOKENS: HOST, IP, FLOW, ->, <-, WEBSOCKET, OPCODE, FIN_BIT, MASK_KEY, COMPILE, LOOP

// INSTRUCTION: Define mobile background client.
HOST bg_client { IP 172.31.8.24 }

// INSTRUCTION: Define cloud gateway server.
HOST cloud_gw_svr { IP 172.31.8.1 }

// INSTRUCTION: Define recurring heartbeat exchange flow.
FLOW ws_heartbeat_loop(c, s) {
    c -> s WEBSOCKET OPCODE "PING" FIN_BIT 1 MASK_KEY 987654321
    c <- s WEBSOCKET OPCODE "PONG" FIN_BIT 1 MASK_KEY 0
}

// INSTRUCTION: Compile block executing 3 repeated ping pong cycles.
COMPILE {
    LOOP 3 {
        ws_heartbeat_loop(bg_client, cloud_gw_svr)
    }
}
"""

# ==========================================
# 11. WHOIS (12 new files)
# ==========================================
files_data["examples/l7/whois/whois_com_domain_lookup.fasm"] = """// PROMPT: Commercial registry domain lookup query for enterprise organization domain.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define security analyst workstation.
HOST analyst_ws { IP 10.10.20.15 }

// INSTRUCTION: Define Verisign COM registry server.
HOST verisign_svr { IP 192.52.178.30 }

// INSTRUCTION: Define commercial domain WHOIS lookup flow.
FLOW whois_com_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "enterprise-tech.com"
    c <- s WHOIS RESPONSE
        DOMAIN "enterprise-tech.com"
        REGISTRAR "MarkMonitor Inc"
}

// INSTRUCTION: Compile block executing COM domain query.
COMPILE {
    whois_com_flow(analyst_ws, verisign_svr)
}
"""

files_data["examples/l7/whois/whois_net_infrastructure_lookup.fasm"] = """// PROMPT: Network infrastructure domain registration query for backbone transit provider.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define network engineer terminal.
HOST net_engineer { IP 172.16.4.8 }

// INSTRUCTION: Define NET authoritative WHOIS registry.
HOST net_registry { IP 192.52.178.30 }

// INSTRUCTION: Define infrastructure domain WHOIS lookup flow.
FLOW whois_net_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "backbone-core.net"
    c <- s WHOIS RESPONSE
        DOMAIN "backbone-core.net"
        REGISTRAR "CSC Corporate Domains"
}

// INSTRUCTION: Compile block executing NET domain query.
COMPILE {
    whois_net_flow(net_engineer, net_registry)
}
"""

files_data["examples/l7/whois/whois_org_foundation_lookup.fasm"] = """// PROMPT: Public interest foundation domain lookup query for open source project.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define developer audit client.
HOST dev_audit { IP 192.168.10.45 }

// INSTRUCTION: Define Public Interest Registry ORG server.
HOST org_registry { IP 199.19.56.1 }

// INSTRUCTION: Define foundation domain WHOIS lookup flow.
FLOW whois_org_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "opensourcesoftware.org"
    c <- s WHOIS RESPONSE
        DOMAIN "opensourcesoftware.org"
        REGISTRAR "Public Interest Registry"
}

// INSTRUCTION: Compile block executing ORG domain query.
COMPILE {
    whois_org_flow(dev_audit, org_registry)
}
"""

files_data["examples/l7/whois/whois_io_tech_startup_lookup.fasm"] = """// PROMPT: Cloud computing startup domain availability query in ccTLD io registry.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define entrepreneur browser client.
HOST startup_cli { IP 10.40.1.18 }

// INSTRUCTION: Define IO registry authority.
HOST io_registry { IP 193.223.78.42 }

// INSTRUCTION: Define IO ccTLD WHOIS lookup flow.
FLOW whois_io_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "cloudnative.io"
    c <- s WHOIS RESPONSE
        DOMAIN "cloudnative.io"
        REGISTRAR "NameCheap Inc"
}

// INSTRUCTION: Compile block executing IO domain query.
COMPILE {
    whois_io_flow(startup_cli, io_registry)
}
"""

files_data["examples/l7/whois/whois_ai_machine_learning_domain.fasm"] = """// PROMPT: Machine learning platform domain query targeting registry whois database.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define research lab computer.
HOST lab_computer { IP 172.24.8.99 }

// INSTRUCTION: Define AI ccTLD registry server.
HOST ai_registry { IP 209.59.119.34 }

// INSTRUCTION: Define AI domain registration check flow.
FLOW whois_ai_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "neuralmodels.ai"
    c <- s WHOIS RESPONSE
        DOMAIN "neuralmodels.ai"
        REGISTRAR "GoDaddy.com LLC"
}

// INSTRUCTION: Compile block executing AI domain query.
COMPILE {
    whois_ai_flow(lab_computer, ai_registry)
}
"""

files_data["examples/l7/whois/whois_ripe_asn_allocation_query.fasm"] = """// PROMPT: RIPE NCC regional internet registry query for autonomous system allocation.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define European ISP operations client.
HOST ripe_client { IP 192.168.80.12 }

// INSTRUCTION: Define RIPE NCC WHOIS database server.
HOST ripe_whois { IP 193.0.6.135 }

// INSTRUCTION: Define Autonomous System allocation lookup flow.
FLOW whois_ripe_asn_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "AS3333"
    c <- s WHOIS RESPONSE
        DOMAIN "AS3333"
        REGISTRAR "RIPE NCC"
}

// INSTRUCTION: Compile block executing RIPE ASN lookup.
COMPILE {
    whois_ripe_asn_flow(ripe_client, ripe_whois)
}
"""

files_data["examples/l7/whois/whois_apnic_ipv4_block_lookup.fasm"] = """// PROMPT: APNIC regional internet registry lookup for IPv4 allocation subnets.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define Asia-Pacific regional network planner.
HOST apnic_cli { IP 10.120.5.8 }

// INSTRUCTION: Define APNIC WHOIS server.
HOST apnic_whois { IP 202.12.29.13 }

// INSTRUCTION: Define IPv4 allocation block lookup flow.
FLOW whois_apnic_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "203.0.113.0/24"
    c <- s WHOIS RESPONSE
        DOMAIN "203.0.113.0/24"
        REGISTRAR "APNIC"
}

// INSTRUCTION: Compile block executing APNIC subnet lookup.
COMPILE {
    whois_apnic_flow(apnic_cli, apnic_whois)
}
"""

files_data["examples/l7/whois/whois_arin_asn_org_registration.fasm"] = """// PROMPT: ARIN directory lookup for enterprise private autonomous system registration.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define North American network auditor.
HOST arin_auditor { IP 172.30.2.14 }

// INSTRUCTION: Define ARIN WHOIS database node.
HOST arin_whois { IP 199.212.0.43 }

// INSTRUCTION: Define autonomous system organization query flow.
FLOW whois_arin_asn_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "AS64512"
    c <- s WHOIS RESPONSE
        DOMAIN "AS64512"
        REGISTRAR "ARIN"
}

// INSTRUCTION: Compile block executing ARIN ASN query.
COMPILE {
    whois_arin_asn_flow(arin_auditor, arin_whois)
}
"""

files_data["examples/l7/whois/whois_lacnic_regional_query.fasm"] = """// PROMPT: LACNIC regional internet registry lookup for South American IP allocation.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define South American operations terminal.
HOST lacnic_cli { IP 192.168.99.20 }

// INSTRUCTION: Define LACNIC WHOIS directory.
HOST lacnic_whois { IP 200.3.14.10 }

// INSTRUCTION: Define LACNIC regional IP query flow.
FLOW whois_lacnic_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "200.7.84.0/22"
    c <- s WHOIS RESPONSE
        DOMAIN "200.7.84.0/22"
        REGISTRAR "LACNIC"
}

// INSTRUCTION: Compile block executing LACNIC query.
COMPILE {
    whois_lacnic_flow(lacnic_cli, lacnic_whois)
}
"""

files_data["examples/l7/whois/whois_response_domain_delegation.fasm"] = """// PROMPT: WHOIS server response payload returning domain delegation registrar records.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define domain registrar inspector.
HOST registrar_insp { IP 10.85.12.4 }

// INSTRUCTION: Define authoritative registry database.
HOST registry_db { IP 198.51.100.75 }

// INSTRUCTION: Define delegation response flow.
FLOW whois_delegation_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "hybrid-cloud-networks.com"
    c <- s WHOIS RESPONSE
        DOMAIN "hybrid-cloud-networks.com"
        REGISTRAR "VeriSign Global Registry"
}

// INSTRUCTION: Compile block executing delegation verification.
COMPILE {
    whois_delegation_flow(registrar_insp, registry_db)
}
"""

files_data["examples/l7/whois/whois_ipv6_ripe_prefix_query.fasm"] = """// PROMPT: Regional registry query verifying allocated IPv6 address prefix assignment.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE

// INSTRUCTION: Define IPv6 network architect.
HOST architect_v6 { IP 2001:db8:1234::10 }

// INSTRUCTION: Define RIPE NCC IPv6 directory server.
HOST ripe_v6_whois { IP 193.0.6.135 }

// INSTRUCTION: Define IPv6 prefix allocation query flow.
FLOW whois_v6_prefix_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "2001:db8::/32"
    c <- s WHOIS RESPONSE
        DOMAIN "2001:db8::/32"
        REGISTRAR "RIPE NCC Registry"
}

// INSTRUCTION: Compile block executing IPv6 prefix query.
COMPILE {
    whois_v6_prefix_flow(architect_v6, ripe_v6_whois)
}
"""

files_data["examples/l7/whois/whois_automated_dns_audit_loop.fasm"] = """// PROMPT: Automated domain registration audit loop verifying registry reachability.
// TOKENS: HOST, IP, FLOW, ->, <-, WHOIS, QUERY, DOMAIN, RESPONSE, REGISTRAR, COMPILE, LOOP

// INSTRUCTION: Define automated brand protection bot.
HOST brand_bot { IP 172.29.5.12 }

// INSTRUCTION: Define target domain registry.
HOST target_whois_svr { IP 198.51.100.10 }

// INSTRUCTION: Define recurring brand domain lookup flow.
FLOW whois_audit_flow(c, s) {
    c -> s WHOIS QUERY DOMAIN "brandprotection.com"
    c <- s WHOIS RESPONSE
        DOMAIN "brandprotection.com"
        REGISTRAR "SafeNames Ltd"
}

// INSTRUCTION: Compile block executing 3 repeated domain audit queries.
COMPILE {
    LOOP 3 {
        whois_audit_flow(brand_bot, target_whois_svr)
    }
}
"""

if __name__ == "__main__":
    print(f"Total files defined: {len(files_data)}")
    assert len(files_data) == 132, f"Expected 132 files, got {len(files_data)}"

    # First write all files
    for path, content in sorted(files_data.items()):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    print("All 132 files written. Verifying each file...")
    failures = []
    for path in sorted(files_data.keys()):
        ok, msg = verify_file(path)
        if not ok:
            failures.append((path, msg))
            print(f"FAIL: {path} -> {msg}")

    if failures:
        print(f"\n{len(failures)} verification failures encountered!")
        sys.exit(1)
    else:
        print("\nAll 132 files passed verification successfully!")
