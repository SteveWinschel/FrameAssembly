//! Shared Layer 2 through Layer 7 frame inspection and terminal packet ladder formatting.
//!
//! This module serves as the single source of truth for dissecting raw compiled or captured
//! Ethernet frames into human-readable endpoint arrows, protocol labels, and summary strings
//! across both the native CLI (`frameassembly show`) and WebAssembly preview targets. It
//! peels IEEE 802.1Q/802.1ad VLAN tags, RFC 3032 multi-label MPLS stacks, optional RFC 4448
//! Ethernet pseudowire control words, IEEE 802.3 LLC/SNAP frames (CDP, IS-IS, STP, RFC 1042),
//! industrial and metro EtherTypes (PPPoE, MACsec, PFC, NSH, PROFINET, GOOSE, SV, EtherCAT),
//! IPv4 options (`IHL >= 20`), IPv6 extension headers (stopping cleanly at SRv6 Routing Type
//! `4`), L3/L4 tunnels (IP-in-IP, GRE/ERSPAN, RSVP, L2TPv3, SCTP chunks & PPIDs), and
//! L7 port/payload disambiguation across all 146 native protocols.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;

/// Dissected human-readable summary components extracted from a raw Ethernet frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameSummary {
    /// Formatted `source -> destination` endpoint string (IPs for L3+, MACs for pure L2).
    pub endpoints: String,
    /// Uppercase display protocol label (e.g., `TCP`, `HTTP2`, `ARP`, `STP`).
    pub protocol: String,
    /// Concise detail string including peeled L2/L3 shim tags, ports, flags, or control codes.
    pub summary: String,
}

/// Maps well-known TCP/UDP port numbers to concise L7 and tunneled-L3 protocol display labels.
///
/// Unifies port assignments across the native CLI inspector and WebAssembly preview
/// engines, including cleartext and TLS variants (such as HTTP `80`/`8080`, TLS `443`/`8443`,
/// IMAP/POP3/SMTP/MQTT/AMQP/LDAP/Syslog/OpenFlow/IRC/TNS), EtherNet/IP UDP I/O (`2222`) vs
/// TCP SSH (`22`/`2222`), and shared-port defaults such as `102` (`S7COMM`), `830` (`NETCONF`),
/// UDP `3478` (`STUN`) vs TCP `3478` (`TURN`), and `4000` (`ROCPLUS`) before payload inspection.
pub fn port_to_l7_name(port: u16, is_tcp: bool) -> Option<&'static str> {
    match (port, is_tcp) {
        (20 | 21 | 2121, true) => Some("FTP"),
        (22 | 2222, true) => Some("SSH"),
        (23 | 2323 | 2001, true) => Some("TELNET"),
        (25 | 465 | 587 | 2525, true) => Some("SMTP"),
        (43, true) => Some("WHOIS"),
        (49, true) => Some("TACACS"),
        (53, _) => Some("DNS"),
        (67 | 68 | 546 | 547, false) => Some("DHCP"),
        (69, false) => Some("TFTP"),
        (80 | 8000 | 8080, true) => Some("HTTP"),
        (88, _) => Some("KERBEROS"),
        (102, true) => Some("S7COMM"),
        (110 | 995, true) => Some("POP3"),
        (123, false) => Some("NTP"),
        (135, true) => Some("DCERPC"),
        (137, false) => Some("NBNS"),
        (139 | 445, true) => Some("SMB"),
        (143 | 993, true) => Some("IMAP"),
        (161 | 162 | 10161 | 10162, false) => Some("SNMP"),
        (179, true) => Some("BGP"),
        (319 | 320, false) => Some("PTP"),
        (323, true) => Some("RPKIRTR"),
        (389, _) | (636 | 3268, true) => Some("LDAP"),
        (443 | 6443 | 8443, true) => Some("TLS"),
        (443 | 4433, false) => Some("QUIC"),
        (500 | 4500, false) => Some("IKEV2"),
        (502, _) => Some("MODBUS"),
        (514 | 6514, _) => Some("SYSLOG"),
        (520 | 521, false) => Some("RIP"),
        (554 | 8554, true) => Some("RTSP"),
        (623, false) => Some("IPMI"),
        (646, _) => Some("LDP"),
        (830, true) => Some("NETCONF"),
        (862, _) => Some("TWAMP"),
        (1080, true) => Some("SOCKS"),
        (1153, _) => Some("C1222"),
        (1234, _) => Some("BSAP"),
        (1433, _) => Some("MSSQL"),
        (1521 | 2483 | 2484, true) => Some("TNS"),
        (1701, false) => Some("L2TP"),
        (1719 | 1720, _) => Some("H323"),
        (1790, true) => Some("BMP"),
        (1645 | 1646 | 1812 | 1813, false) => Some("RADIUS"),
        (1883 | 8883, true) => Some("MQTT"),
        (1900, false) => Some("SSDP"),
        (1985 | 2029, false) => Some("HSRP"),
        (2000, true) => Some("SCCP"),
        (2049, _) => Some("NFS"),
        (2055, false) => Some("NETFLOW"),
        (2123, false) => Some("GTPC"),
        (2152, false) => Some("GTPU"),
        (2222, false) | (44818, _) => Some("ETHERNETIP"),
        (2404, true) => Some("IEC104"),
        (2427 | 2727, _) => Some("MGCP"),
        (3222, false) => Some("GLBP"),
        (3260, true) => Some("ISCSI"),
        (3306, true) => Some("MYSQL"),
        (3389, true) => Some("RDP"),
        (3478, true) => Some("TURN"),
        (3478, false) => Some("STUN"),
        (3671, _) => Some("KNXNETIP"),
        (3702, false) => Some("WSDISCOVERY"),
        (3784 | 4784, false) => Some("BFD"),
        (3868, true) => Some("DIAMETER"),
        (4000, _) => Some("ROCPLUS"),
        (4341 | 4342, false) => Some("LISP"),
        (4420 | 8009, true) => Some("NVMETCP"),
        (4712, _) => Some("SYNCHROPHASOR"),
        (4739, false) => Some("IPFIX"),
        (4789, false) => Some("VXLAN"),
        (4791, false) => Some("ROCEV2"),
        (4840, true) => Some("OPCUA"),
        (5000, _) => Some("MELSEC"),
        (5004, false) => Some("RTP"),
        (5005, false) => Some("RTCP"),
        (5060, _) | (5061, true) => Some("SIP"),
        (5094, _) => Some("HARTIP"),
        (5353, false) => Some("MDNS"),
        (5355, _) => Some("LLMNR"),
        (5432, true) => Some("POSTGRES"),
        (5671 | 5672, true) => Some("AMQP"),
        (5683 | 5684, false) => Some("COAP"),
        (5900..=5909, true) => Some("VNC"),
        (6081, false) => Some("GENEVE"),
        (6343 | 16343, false) => Some("SFLOW"),
        (6379 | 26379, true) => Some("REDIS"),
        (6633 | 6653, true) => Some("OPENFLOW"),
        (6665..=6669 | 6697, true) => Some("IRC"),
        (8805, false) => Some("PFCP"),
        (9092, _) => Some("KAFKA"),
        (9600, _) => Some("FINS"),
        (11211, _) => Some("MEMCACHED"),
        (13400, _) => Some("DOIP"),
        (18245, true) => Some("GESRTP"),
        (20000, _) => Some("DNP3"),
        (27017..=27019, true) => Some("MONGODB"),
        (30490, _) => Some("SOMEIP"),
        (34964, false) => Some("PROFINET"),
        (34980, false) => Some("ETHERCAT"),
        (47808, false) => Some("BACNET"),
        (50051, true) => Some("GRPC"),
        (51820, false) => Some("WIREGUARD"),
        _ => None,
    }
}

/// Formats a 6-byte Ethernet MAC address slice as lowercase colon-hex (`xx:xx:xx:xx:xx:xx`).
fn format_mac(bytes: &[u8]) -> String {
    let Some(&[b0, b1, b2, b3, b4, b5]) = bytes.first_chunk::<6>() else {
        return "00:00:00:00:00:00".to_string();
    };
    format!("{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
}

/// Peels stacked IEEE 802.1Q / 802.1ad VLAN tags, updating `offset`, `etype`, and `l2_tags`.
fn peel_vlan_tags(
    data: &[u8],
    offset: &mut usize,
    etype: &mut u16,
    l2_tags: &mut Vec<String>,
) {
    while matches!(*etype, 0x8100 | 0x88A8 | 0x9100) && *offset + 4 <= data.len() {
        let tci = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
        let vid = tci & 0x0FFF;
        let pcp = (tci >> 13) & 0x07;
        if *etype == 0x88A8 || *etype == 0x9100 {
            l2_tags.push(format!("SVLAN={vid}"));
        } else if l2_tags.iter().any(|t: &String| t.starts_with("SVLAN=")) {
            l2_tags.push(format!("CVLAN={vid}"));
        } else if pcp > 0 {
            l2_tags.push(format!("VLAN={vid}(PCP={pcp})"));
        } else {
            l2_tags.push(format!("VLAN={vid}"));
        }
        *etype = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
        *offset += 4;
    }
}

/// Returns `true` when an EoMPLS control word wraps a recognized inner Ethernet payload.
fn is_supported_eompls_inner(dst_bytes: &[u8], inner_et: u16, inner_llc: &[u8]) -> bool {
    let known_et = matches!(
        inner_et,
        0x0800
            | 0x86DD
            | 0x0806
            | 0x8100
            | 0x88A8
            | 0x9100
            | 0x88CC
            | 0x8809
            | 0x888E
            | 0x88E5
            | 0x8808
            | 0x8863
            | 0x8864
            | 0x894F
            | 0x8892
            | 0x88B8
            | 0x88BA
            | 0x88A4
    );
    let inner_is_stp = dst_bytes == [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00] && inner_et <= 1500;
    let inner_is_llc = (3..=1500).contains(&inner_et)
        && (inner_llc.starts_with(&[0x42, 0x42, 0x03])
            || inner_llc.starts_with(&[0xAA, 0xAA, 0x03])
            || inner_llc.starts_with(&[0xFE, 0xFE, 0x03]));
    known_et || inner_is_stp || inner_is_llc
}

/// Maps an IS-IS PDU type number (`byte & 0x1F`) to a concise display name.
fn isis_pdu_name(pdu_type: u8) -> &'static str {
    match pdu_type {
        15 => "L1 LAN IIH",
        16 => "L2 LAN IIH",
        17 => "P2P IIH",
        18 => "L1 LSP",
        20 => "L2 LSP",
        24 => "L1 CSNP",
        25 => "L2 CSNP",
        26 => "L1 PSNP",
        27 => "L2 PSNP",
        _ => "PDU",
    }
}

/// Maps a PPPoE Discovery code byte to its stage acronym.
fn pppoe_code_name(code: u8) -> &'static str {
    match code {
        0x09 => "PADI",
        0x07 => "PADO",
        0x19 => "PADR",
        0x65 => "PADS",
        0xA7 => "PADT",
        _ => "Discovery",
    }
}

/// Dissects a single raw Ethernet frame into `(endpoints, proto_label, summary_text)`.
///
/// Peels 802.1Q / 802.1ad VLAN tags, RFC 3032 multi-label MPLS stacks, RFC 4448 EoMPLS
/// control words when carrying Ethernet PDUs, IEEE 802.3 LLC/SNAP headers (CDP, IS-IS,
/// STP, RFC 1042 SNAP), L2 control/industrial EtherTypes (PPPoE, MACsec, PFC, NSH,
/// PROFINET, GOOSE, SV, EtherCAT), IPv4 headers (`IHL >= 20`), and IPv6 extension headers
/// (`0` Hop-by-Hop, `43` non-SRv6 Routing, `44` Fragment, `60` Destination Options).
pub fn summarize_frame(data: &[u8]) -> (String, String, String) {
    if data.len() < 14 {
        return (
            "unknown -> unknown".to_string(),
            "RAW".to_string(),
            format!("{} bytes", data.len()),
        );
    }

    let mut dst_mac = format_mac(&data[0..6]);
    let mut src_mac = format_mac(&data[6..12]);
    let mut etype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;
    let mut l2_tags = Vec::new();

    peel_vlan_tags(data, &mut offset, &mut etype, &mut l2_tags);

    if matches!(etype, 0x8847 | 0x8848) && offset + 4 <= data.len() {
        while let Some(&[b0, b1, b2, b3]) = data[offset..].first_chunk::<4>() {
            let entry = u32::from_be_bytes([b0, b1, b2, b3]);
            let label = entry >> 12;
            let bos = (entry >> 8) & 1;
            l2_tags.push(format!("MPLS={label}"));
            offset += 4;
            if bos == 1 {
                break;
            }
        }
        if let Some(&first_byte) = data.get(offset) {
            match first_byte >> 4 {
                4 if offset + 20 <= data.len() => etype = 0x0800,
                6 if offset + 40 <= data.len() => etype = 0x86DD,
                0 if offset + 18 <= data.len() && data[offset..offset + 4] == [0, 0, 0, 0] => {
                    let inner_et = u16::from_be_bytes([data[offset + 16], data[offset + 17]]);
                    let inner_llc = data.get(offset + 18..).unwrap_or(&[]);
                    if is_supported_eompls_inner(&data[offset + 4..offset + 10], inner_et, inner_llc)
                    {
                        dst_mac = format_mac(&data[offset + 4..offset + 10]);
                        src_mac = format_mac(&data[offset + 10..offset + 16]);
                        etype = inner_et;
                        offset += 18;
                        peel_vlan_tags(data, &mut offset, &mut etype, &mut l2_tags);
                    }
                }
                _ => {}
            }
        }
    }

    let frame_data: &[u8] = if etype <= 1500 {
        let l2_end = offset.saturating_add(usize::from(etype)).min(data.len());
        let llc = &data[offset.min(l2_end)..l2_end];
        let tag_prefix = format_tag_prefix(&l2_tags);
        if llc.starts_with(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00]) {
            let detail = if llc.len() >= 10 {
                format!(
                    "{tag_prefix}Cisco Discovery Protocol v{} (ttl={}s)",
                    llc[8], llc[9]
                )
            } else {
                format!("{tag_prefix}Cisco Discovery Protocol frame")
            };
            return (format!("{src_mac} -> {dst_mac}"), "CDP".to_string(), detail);
        }
        if llc.starts_with(&[0xFE, 0xFE, 0x03]) {
            let detail = if llc.get(3) == Some(&0x83) && llc.len() >= 8 {
                format!("{tag_prefix}IS-IS {}", isis_pdu_name(llc[7] & 0x1F))
            } else {
                format!("{tag_prefix}IS-IS PDU")
            };
            return (
                format!("{src_mac} -> {dst_mac}"),
                "ISIS".to_string(),
                detail,
            );
        }
        if llc.starts_with(&[0x42, 0x42, 0x03]) {
            return (
                format!("{src_mac} -> {dst_mac}"),
                "STP".to_string(),
                format!("{tag_prefix}Spanning Tree Protocol BPDU"),
            );
        }
        if llc.len() >= 8 && llc.starts_with(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]) {
            etype = u16::from_be_bytes([llc[6], llc[7]]);
            offset += 8;
            let sliced = &data[..l2_end];
            peel_vlan_tags(sliced, &mut offset, &mut etype, &mut l2_tags);
            sliced
        } else {
            &data[..l2_end]
        }
    } else {
        data
    };

    match etype {
        0x0806 if offset + 28 <= frame_data.len() => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let arp = &frame_data[offset..offset + 28];
            let oper = u16::from_be_bytes([arp[6], arp[7]]);
            let spa = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
            let tpa = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
            let detail = if oper == 1 {
                format!("{tag_prefix}Who has {tpa}? Tell {spa}")
            } else {
                format!("{tag_prefix}{spa} is at {src_mac}")
            };
            (format!("{spa} -> {tpa}"), "ARP".to_string(), detail)
        }
        0x0800 if offset + 20 <= frame_data.len() => {
            let ip = &frame_data[offset..];
            let ihl = ((ip[0] & 0x0F) as usize) * 4;
            let proto = ip[9];
            let frag_field = u16::from_be_bytes([ip[6], ip[7]]);
            let frag_off = frag_field & 0x1FFF;
            let mf = (frag_field & 0x2000) != 0;
            let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            if ihl < 20 || ihl > ip.len() {
                let tag_prefix = format_tag_prefix(&l2_tags);
                return (
                    format!("{src_ip} -> {dst_ip}"),
                    "IPv4".to_string(),
                    format!("{tag_prefix}Malformed IPv4 header (IHL={ihl})"),
                );
            }
            if frag_off > 0 || mf {
                l2_tags.push(format!("FRAG(off={frag_off})"));
            }
            let tag_prefix = format_tag_prefix(&l2_tags);
            let l4_slice = &ip[ihl..];
            if frag_off > 0 {
                return (
                    format!("{src_ip} -> {dst_ip}"),
                    format!("IP({proto})"),
                    format!(
                        "{tag_prefix}IPv4 fragment offset={} ({} bytes)",
                        frag_off * 8,
                        l4_slice.len()
                    ),
                );
            }
            let (p_label, summary) = summarize_l4(proto, l4_slice, &tag_prefix);
            (format!("{src_ip} -> {dst_ip}"), p_label, summary)
        }
        0x86DD if offset + 40 <= frame_data.len() => {
            let ip6 = &frame_data[offset..];
            let mut next_hdr = ip6[6];
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&ip6[8..24]);
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&ip6[24..40]);
            let src_ip = Ipv6Addr::from(src_bytes);
            let dst_ip = Ipv6Addr::from(dst_bytes);
            let mut l4_offset = 40usize;
            let mut frag_offset_units: Option<(u16, bool)> = None;

            for _ in 0..8 {
                match next_hdr {
                    0 | 43 | 60
                        if l4_offset + 8 <= ip6.len()
                            && (next_hdr != 43 || ip6.get(l4_offset + 2) != Some(&4)) =>
                    {
                        let ext_next = ip6[l4_offset];
                        let ext_len = (ip6[l4_offset + 1] as usize + 1) * 8;
                        if l4_offset + ext_len > ip6.len() {
                            break;
                        }
                        if next_hdr == 0 {
                            l2_tags.push("HBH".to_string());
                        }
                        next_hdr = ext_next;
                        l4_offset += ext_len;
                    }
                    44 if l4_offset + 8 <= ip6.len() => {
                        let ext_next = ip6[l4_offset];
                        let off_m = u16::from_be_bytes([ip6[l4_offset + 2], ip6[l4_offset + 3]]);
                        let off_units = (off_m >> 3) & 0x1FFF;
                        let mf = (off_m & 0x0001) != 0;
                        l2_tags.push(format!("FRAG(off={off_units})"));
                        frag_offset_units = Some((off_units, mf));
                        next_hdr = ext_next;
                        l4_offset += 8;
                    }
                    _ => break,
                }
            }

            let tag_prefix = format_tag_prefix(&l2_tags);
            let l4_slice = ip6.get(l4_offset..).unwrap_or(&[]);
            if let Some((off_units, _mf)) = frag_offset_units
                && off_units > 0
            {
                return (
                    format!("{src_ip} -> {dst_ip}"),
                    "IPv6-Frag".to_string(),
                    format!(
                        "{tag_prefix}IPv6 fragment offset={} next={next_hdr} ({} bytes)",
                        off_units * 8,
                        l4_slice.len()
                    ),
                );
            }
            let (p_label, summary) = summarize_l4(next_hdr, l4_slice, &tag_prefix);
            (format!("{src_ip} -> {dst_ip}"), p_label, summary)
        }
        0x88CC => (
            format!("{src_mac} -> {dst_mac}"),
            "LLDP".to_string(),
            format!("{}Link Layer Discovery Protocol frame", format_tag_prefix(&l2_tags)),
        ),
        0x8809 => (
            format!("{src_mac} -> {dst_mac}"),
            "LACP".to_string(),
            format!("{}Link Aggregation Control Protocol PDU", format_tag_prefix(&l2_tags)),
        ),
        0x888E => (
            format!("{src_mac} -> {dst_mac}"),
            "EAPOL".to_string(),
            format!("{}IEEE 802.1X EAP over LAN frame", format_tag_prefix(&l2_tags)),
        ),
        0x88E5 => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let ms = frame_data.get(offset..).unwrap_or(&[]);
            let detail = if ms.len() >= 6 {
                let tci_an = ms[0];
                let pn = u32::from_be_bytes([ms[2], ms[3], ms[4], ms[5]]);
                format!("{tag_prefix}IEEE 802.1AE MACsec (tci_an=0x{tci_an:02x} pn={pn})")
            } else {
                format!("{tag_prefix}IEEE 802.1AE MACsec")
            };
            (format!("{src_mac} -> {dst_mac}"), "MACSEC".to_string(), detail)
        }
        0x8808 if frame_data.get(offset..offset + 2) == Some(&[0x01, 0x01]) => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let detail = if let Some(&[hi, lo]) = frame_data.get(offset + 2..offset + 4) {
                let enable = u16::from_be_bytes([hi, lo]);
                format!("{tag_prefix}IEEE 802.1Qbb PFC (enable=0x{enable:04x})")
            } else {
                format!("{tag_prefix}IEEE 802.1Qbb PFC")
            };
            (format!("{src_mac} -> {dst_mac}"), "PFC".to_string(), detail)
        }
        0x8863 => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let pppoe = frame_data.get(offset..).unwrap_or(&[]);
            let detail = if pppoe.len() >= 6 {
                let stage = pppoe_code_name(pppoe[1]);
                let sid = u16::from_be_bytes([pppoe[2], pppoe[3]]);
                format!("{tag_prefix}PPPoE {stage} (session=0x{sid:04x})")
            } else {
                format!("{tag_prefix}PPPoE Discovery")
            };
            (format!("{src_mac} -> {dst_mac}"), "PPPOE".to_string(), detail)
        }
        0x8864 => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let pppoe = frame_data.get(offset..).unwrap_or(&[]);
            let detail = if pppoe.len() >= 8 {
                let sid = u16::from_be_bytes([pppoe[2], pppoe[3]]);
                let ppp_proto = u16::from_be_bytes([pppoe[6], pppoe[7]]);
                format!("{tag_prefix}PPPoE Session (session=0x{sid:04x} proto=0x{ppp_proto:04x})")
            } else if pppoe.len() >= 6 {
                let sid = u16::from_be_bytes([pppoe[2], pppoe[3]]);
                format!("{tag_prefix}PPPoE Session (session=0x{sid:04x})")
            } else {
                format!("{tag_prefix}PPPoE Session")
            };
            (format!("{src_mac} -> {dst_mac}"), "PPPOE".to_string(), detail)
        }
        0x894F => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let nsh = frame_data.get(offset..).unwrap_or(&[]);
            let detail = if nsh.len() >= 8 {
                let next_proto = nsh[3];
                let sph = u32::from_be_bytes([nsh[4], nsh[5], nsh[6], nsh[7]]);
                let spi = sph >> 8;
                let si = sph & 0xFF;
                format!("{tag_prefix}NSH (spi={spi} si={si} next=0x{next_proto:02x})")
            } else {
                format!("{tag_prefix}Network Service Header")
            };
            (format!("{src_mac} -> {dst_mac}"), "NSH".to_string(), detail)
        }
        0x8892 => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let pn = frame_data.get(offset..).unwrap_or(&[]);
            let detail = if pn.len() >= 2 {
                let frame_id = u16::from_be_bytes([pn[0], pn[1]]);
                let kind = if (0xFEFC..=0xFEFF).contains(&frame_id) {
                    "DCP"
                } else {
                    "Cyclic RT"
                };
                format!("{tag_prefix}PROFINET {kind} (frame_id=0x{frame_id:04x})")
            } else {
                format!("{tag_prefix}PROFINET Real-Time frame")
            };
            (
                format!("{src_mac} -> {dst_mac}"),
                "PROFINET".to_string(),
                detail,
            )
        }
        0x88B8 => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let g = frame_data.get(offset..).unwrap_or(&[]);
            let detail = if g.len() >= 2 {
                let appid = u16::from_be_bytes([g[0], g[1]]);
                format!("{tag_prefix}IEC 61850 GOOSE (appid=0x{appid:04x})")
            } else {
                format!("{tag_prefix}IEC 61850 GOOSE")
            };
            (format!("{src_mac} -> {dst_mac}"), "GOOSE".to_string(), detail)
        }
        0x88BA => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let sv = frame_data.get(offset..).unwrap_or(&[]);
            let detail = if sv.len() >= 2 {
                let appid = u16::from_be_bytes([sv[0], sv[1]]);
                format!("{tag_prefix}IEC 61850 SV (appid=0x{appid:04x})")
            } else {
                format!("{tag_prefix}IEC 61850 SV")
            };
            (format!("{src_mac} -> {dst_mac}"), "SV".to_string(), detail)
        }
        0x88A4 => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let ec = frame_data.get(offset..).unwrap_or(&[]);
            let detail = if ec.len() >= 3 {
                format!("{tag_prefix}EtherCAT frame (cmd={})", ec[2])
            } else {
                format!("{tag_prefix}EtherCAT frame")
            };
            (
                format!("{src_mac} -> {dst_mac}"),
                "ETHERCAT".to_string(),
                detail,
            )
        }
        _ => {
            let tag_prefix = format_tag_prefix(&l2_tags);
            let proto = if dst_mac == "01:80:c2:00:00:00" {
                "STP"
            } else if l2_tags.iter().any(|t| t.starts_with("SVLAN=")) {
                "QINQ"
            } else if l2_tags.iter().any(|t| t.starts_with("VLAN=")) {
                "VLAN"
            } else if l2_tags.iter().any(|t| t.starts_with("MPLS=")) {
                "MPLS"
            } else {
                "L2"
            };
            (
                format!("{src_mac} -> {dst_mac}"),
                proto.to_string(),
                format!("{tag_prefix}EtherType 0x{etype:04x}"),
            )
        }
    }
}

/// Formats accumulated Layer 2/3 shim tags into a bracketed summary prefix.
fn format_tag_prefix(l2_tags: &[String]) -> String {
    if l2_tags.is_empty() {
        String::new()
    } else {
        format!("[{}] ", l2_tags.join(" "))
    }
}

/// Dissects a raw Ethernet frame into a structured [`FrameSummary`].
pub fn inspect_frame(data: &[u8]) -> FrameSummary {
    let (endpoints, protocol, summary) = summarize_frame(data);
    FrameSummary {
        endpoints,
        protocol,
        summary,
    }
}

/// Returns the starting byte offset of `needle` within `haystack`, if found.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Returns `true` when `haystack` contains `needle` under ASCII case-insensitive matching.
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Returns `true` when `payload` begins with a cleartext HTTP/1.x or HTTP/2 start line.
fn starts_with_http(payload: &[u8]) -> bool {
    if payload.starts_with(b"HTTP/1.") || payload.starts_with(b"HTTP/2") {
        return true;
    }
    let is_method = [
        b"GET ".as_slice(),
        b"POST ".as_slice(),
        b"PUT ".as_slice(),
        b"DELETE ".as_slice(),
        b"HEAD ".as_slice(),
        b"OPTIONS ".as_slice(),
        b"PATCH ".as_slice(),
        b"CONNECT ".as_slice(),
        b"TRACE ".as_slice(),
    ]
    .iter()
    .any(|m| payload.starts_with(m));
    if !is_method {
        return false;
    }
    let line_end = payload
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(payload.len());
    let first_line = &payload[..line_end];
    !first_line.starts_with(b"OPTIONS rtsp:")
        && !first_line.starts_with(b"OPTIONS sip:")
        && find_subslice(first_line, b"RTSP/").is_none()
        && find_subslice(first_line, b"SIP/").is_none()
}

/// Returns `true` when an HTTP message carries an NTLM negotiation header.
fn is_ntlm_http_payload(payload: &[u8]) -> bool {
    starts_with_http(payload)
        && (contains_ascii_ci(payload, b"authorization: ntlm")
            || contains_ascii_ci(payload, b"www-authenticate: ntlm")
            || contains_ascii_ci(payload, b"proxy-authenticate: ntlm"))
}

/// Returns `true` when an HTTP message carries an RFC 8484 DNS-over-HTTPS request or reply.
fn is_doh_http_payload(payload: &[u8]) -> bool {
    starts_with_http(payload)
        && (contains_ascii_ci(payload, b"application/dns-message")
            || (payload.starts_with(b"GET ")
                && (find_subslice(payload, b"?dns=").is_some()
                    || find_subslice(payload, b"&dns=").is_some())))
}

/// Returns `true` when an HTTP message upgrades a connection to WebSocket.
fn is_websocket_http_upgrade(payload: &[u8]) -> bool {
    starts_with_http(payload) && contains_ascii_ci(payload, b"upgrade: websocket")
}

/// Returns `true` when `payload` matches an RFC 6455 unfragmented WebSocket frame.
fn is_websocket_frame(payload: &[u8]) -> bool {
    if payload.len() < 2 {
        return false;
    }
    let b0 = payload[0];
    let b1 = payload[1];
    let fin = (b0 & 0x80) != 0;
    let rsv = b0 & 0x70;
    let opcode = b0 & 0x0F;
    if !fin || rsv != 0 || !matches!(opcode, 1 | 2 | 8 | 9 | 10) {
        return false;
    }
    let masked = (b1 & 0x80) != 0;
    let mut pos = 2usize;
    let len_7 = (b1 & 0x7F) as usize;
    let body_len = match len_7 {
        0..=125 => len_7,
        126 => {
            let Some(ext) = payload.get(pos..pos + 2) else {
                return false;
            };
            pos += 2;
            u16::from_be_bytes([ext[0], ext[1]]) as usize
        }
        _ => {
            let Some(ext) = payload.get(pos..pos + 8) else {
                return false;
            };
            pos += 8;
            let len_u64 = u64::from_be_bytes([
                ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
            ]);
            let Ok(len_usize) = usize::try_from(len_u64) else {
                return false;
            };
            len_usize
        }
    };
    if masked {
        pos = pos.saturating_add(4);
    }
    pos.checked_add(body_len) == Some(payload.len())
}

/// Returns `true` when `payload` uses NETCONF XML or RFC 6242 chunked framing.
fn is_netconf_payload(payload: &[u8]) -> bool {
    if payload.starts_with(b"<?xml")
        || payload.starts_with(b"<hello")
        || payload.starts_with(b"<rpc")
        || find_subslice(payload, b"]]>]]>").is_some()
    {
        return true;
    }
    if let Some(after_prefix) = payload.strip_prefix(b"\n#") {
        let mut digits = 0usize;
        for &b in after_prefix {
            if b.is_ascii_digit() {
                digits += 1;
            } else {
                return digits > 0 && b == b'\n';
            }
        }
    }
    false
}

/// Returns `true` when `payload` matches an RFC 4253 SSH binary packet header and length.
fn is_ssh_binary_packet(payload: &[u8]) -> bool {
    let Some(&[b0, b1, b2, b3, pad_len]) = payload.first_chunk::<5>() else {
        return false;
    };
    let pkt_len = u32::from_be_bytes([b0, b1, b2, b3]) as usize;
    let pad = usize::from(pad_len);
    pkt_len >= 12 && pad >= 4 && pad < pkt_len && pkt_len.checked_add(4) == Some(payload.len())
}

/// Computes a reflected CRC-16 (`0xA001` polynomial) over `bytes` from the given seed.
fn crc16_a001(bytes: &[u8], init: u16) -> u16 {
    let mut crc = init;
    for &b in bytes {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Returns `true` when `payload` matches an Emerson ROCplus header and length/CRC check.
fn is_rocplus_payload(payload: &[u8]) -> bool {
    let len = payload.len();
    if len < 8 || payload[3] != 0 || payload[5] > 240 || 8 + usize::from(payload[5]) != len {
        return false;
    }
    if payload[0] == 0xFF && matches!(payload[1], 0xFB..=0xFE) {
        let body = &payload[..len - 2];
        let trailer_le = u16::from_le_bytes([payload[len - 2], payload[len - 1]]);
        let trailer_be = u16::from_be_bytes([payload[len - 2], payload[len - 1]]);
        let crc0 = crc16_a001(body, 0x0000);
        let crc1 = crc16_a001(body, 0xFFFF);
        return crc0 == trailer_le
            || crc0 == trailer_be
            || crc1 == trailer_le
            || crc1 == trailer_be;
    }
    true
}

/// Returns `true` when `payload` is Telnet IAC negotiation or printable ASCII NVT text.
fn is_telnet_payload(payload: &[u8]) -> bool {
    !payload.is_empty()
        && ((payload.len() >= 2 && payload[0] == 0xFF && matches!(payload[1], 0xFA..=0xFE))
            || payload
                .iter()
                .all(|&b| b.is_ascii_graphic() || matches!(b, b' ' | b'\r' | b'\n' | b'\t')))
}

/// Disambiguates ISO-on-TCP (TPKT + COTP DT) payloads into `S7COMM`, `S7COMMPLUS`, or `MMS`.
fn detect_iso_on_tcp(payload: &[u8]) -> Option<&'static str> {
    if payload.len() >= 8 && payload[0..2] == [0x03, 0x00] && payload[4..7] == [0x02, 0xF0, 0x80] {
        match payload[7] {
            0x32 => Some("S7COMM"),
            0x72 => Some("S7COMMPLUS"),
            0x0D | 0x0E => Some("MMS"),
            _ if payload.get(7..11) == Some(&[0x01, 0x00, 0x01, 0x00]) => Some("MMS"),
            _ => None,
        }
    } else {
        None
    }
}

/// Disambiguates RFC 5766 TURN vs RFC 5389/8489 STUN messages on shared port `3478`.
fn detect_turn_or_stun(payload: &[u8]) -> Option<&'static str> {
    if payload.len() >= 4 {
        let channel = u16::from_be_bytes([payload[0], payload[1]]);
        let data_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        let padded_len = (data_len + 3) & !3;
        if (0x4000..=0x7FFF).contains(&channel)
            && (4 + data_len == payload.len() || 4 + padded_len == payload.len())
        {
            return Some("TURN");
        }
    }
    if payload.len() >= 20
        && (payload[0] & 0xC0) == 0
        && payload[4..8] == [0x21, 0x12, 0xA4, 0x42]
    {
        let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
        let method = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2);
        return match method {
            0x0003 | 0x0004 | 0x0006..=0x000C => Some("TURN"),
            0x0001 => Some("STUN"),
            _ => None,
        };
    }
    None
}

/// Inspects a non-empty stream payload for signature-based L7 protocols and port disambiguation.
fn detect_stream_l7(sport: u16, dport: u16, payload: &[u8]) -> Option<&'static str> {
    if payload.starts_with(b"PRI * HTTP/2.0") {
        return Some("HTTP2");
    }

    let is_http_port =
        matches!(sport, 80 | 443 | 8000 | 8080 | 8443) || matches!(dport, 80 | 443 | 8000 | 8080 | 8443);
    if is_http_port || starts_with_http(payload) {
        if is_ntlm_http_payload(payload) {
            return Some("NTLM");
        }
        if is_doh_http_payload(payload) {
            return Some("DOH");
        }
        if is_websocket_http_upgrade(payload) {
            return Some("WEBSOCKET");
        }
        if is_http_port && is_websocket_frame(payload) {
            return Some("WEBSOCKET");
        }
        if (matches!(sport, 443 | 8443) || matches!(dport, 443 | 8443)) && starts_with_http(payload) {
            return Some("HTTP");
        }
    }

    if (sport == 102 || dport == 102 || (sport != 3389 && dport != 3389))
        && let Some(proto) = detect_iso_on_tcp(payload)
    {
        return Some(proto);
    }

    if sport == 830 || dport == 830 {
        if payload.starts_with(b"SSH-") {
            return Some("SSH");
        }
        if is_netconf_payload(payload) {
            return Some("NETCONF");
        }
        if is_ssh_binary_packet(payload) {
            return Some("SSH");
        }
        return Some("NETCONF");
    }

    if (sport == 3478 || dport == 3478)
        && let Some(proto) = detect_turn_or_stun(payload)
    {
        return Some(proto);
    }

    if sport == 4000 || dport == 4000 {
        if is_rocplus_payload(payload) {
            return Some("ROCPLUS");
        }
        if is_telnet_payload(payload) {
            return Some("TELNET");
        }
        return Some("ROCPLUS");
    }

    None
}

/// Maps an RFC 9260 SCTP chunk type identifier to its concise uppercase name.
fn sctp_chunk_name(chunk_type: u8) -> &'static str {
    match chunk_type {
        0 => "DATA",
        1 => "INIT",
        2 => "INIT-ACK",
        3 => "SACK",
        4 => "HEARTBEAT",
        5 => "HEARTBEAT-ACK",
        6 => "ABORT",
        7 => "SHUTDOWN",
        8 => "SHUTDOWN-ACK",
        9 => "ERROR",
        10 => "COOKIE-ECHO",
        11 => "COOKIE-ACK",
        14 => "SHUTDOWN-COMPLETE",
        _ => "CHUNK",
    }
}

/// Maps an RFC 2205 / RFC 4640 RSVP message type code to its human-readable name.
fn rsvp_msg_name(msg_type: u8) -> &'static str {
    match msg_type {
        1 => "Path",
        2 => "Resv",
        3 => "PathErr",
        4 => "ResvErr",
        5 => "PathTear",
        6 => "ResvTear",
        7 => "ResvConf",
        20 => "Hello",
        _ => "Message",
    }
}

/// Dissects the Layer 4 or Layer 3 control header carried inside an IPv4 or IPv6 packet.
pub fn summarize_l4(proto: u8, l4: &[u8], tag_prefix: &str) -> (String, String) {
    match proto {
        6 if l4.len() >= 20 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
            let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
            let hdr_len = (((l4[12] >> 4) as usize) * 4).max(20);
            let flags = l4[13];
            let payload_len = l4.len().saturating_sub(hdr_len);
            let payload = l4.get(hdr_len..).unwrap_or(&[]);

            let mut flag_names = Vec::new();
            for (bit, name) in [
                (0x02, "SYN"),
                (0x10, "ACK"),
                (0x08, "PSH"),
                (0x04, "RST"),
                (0x01, "FIN"),
                (0x20, "URG"),
                (0x40, "ECE"),
                (0x80, "CWR"),
            ] {
                if flags & bit != 0 {
                    flag_names.push(name);
                }
            }
            let flags_str = if flag_names.is_empty() {
                "NONE".to_string()
            } else {
                flag_names.join(" ")
            };

            let l7_proto = if payload_len > 0 {
                detect_stream_l7(sport, dport, payload)
                    .or_else(|| port_to_l7_name(dport, true))
                    .or_else(|| port_to_l7_name(sport, true))
            } else {
                None
            };
            let label = l7_proto.unwrap_or("TCP").to_string();
            let ack_part = if flags & 0x10 != 0 {
                format!(" ack={ack}")
            } else {
                String::new()
            };
            (
                label,
                format!(
                    "{tag_prefix}{sport} -> {dport} [{flags_str}] seq={seq}{ack_part} len={payload_len}"
                ),
            )
        }
        17 if l4.len() >= 8 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let payload_len = l4.len().saturating_sub(8);
            let payload = &l4[8..];
            let disambiguated = if (sport == 3478 || dport == 3478) && !payload.is_empty() {
                detect_turn_or_stun(payload)
            } else {
                None
            };
            let l7_proto = disambiguated
                .or_else(|| port_to_l7_name(dport, false))
                .or_else(|| port_to_l7_name(sport, false));
            let label = l7_proto.unwrap_or("UDP").to_string();
            (
                label,
                format!("{tag_prefix}{sport} -> {dport} len={payload_len}"),
            )
        }
        1 if l4.len() >= 4 => {
            let icmp_type = l4[0];
            let icmp_code = l4[1];
            let desc = match icmp_type {
                8 => "Echo Request",
                0 => "Echo Reply",
                3 => "Destination Unreachable",
                5 => "Redirect",
                11 => "Time Exceeded",
                _ => "Control Message",
            };
            (
                "ICMP".to_string(),
                format!("{tag_prefix}{desc} (type={icmp_type} code={icmp_code})"),
            )
        }
        58 if l4.len() >= 4 => {
            let icmp6_type = l4[0];
            let (label, desc) = match icmp6_type {
                128 => ("ICMPv6", "Echo Request"),
                129 => ("ICMPv6", "Echo Reply"),
                130..=132 | 143 => ("MLD", "Multicast Listener Discovery"),
                133..=137 => ("NDP", "Neighbor Discovery Protocol"),
                _ => ("ICMPv6", "Control Message"),
            };
            (
                label.to_string(),
                format!("{tag_prefix}{desc} (type={icmp6_type})"),
            )
        }
        2 => (
            "IGMP".to_string(),
            format!("{tag_prefix}Multicast Membership Message"),
        ),
        4 => {
            let detail = if l4.len() >= 20 && (l4[0] >> 4) == 4 {
                let src = Ipv4Addr::new(l4[12], l4[13], l4[14], l4[15]);
                let dst = Ipv4Addr::new(l4[16], l4[17], l4[18], l4[19]);
                format!("{tag_prefix}IPv4-in-IP ({src} -> {dst})")
            } else {
                format!("{tag_prefix}IPv4-in-IP Encapsulation ({} bytes)", l4.len())
            };
            ("IPIP".to_string(), detail)
        }
        41 => {
            let detail = if l4.len() >= 40 && (l4[0] >> 4) == 6 {
                let mut src_bytes = [0u8; 16];
                src_bytes.copy_from_slice(&l4[8..24]);
                let mut dst_bytes = [0u8; 16];
                dst_bytes.copy_from_slice(&l4[24..40]);
                let src = Ipv6Addr::from(src_bytes);
                let dst = Ipv6Addr::from(dst_bytes);
                format!("{tag_prefix}IPv6-in-IP ({src} -> {dst})")
            } else {
                format!("{tag_prefix}IPv6-in-IP Encapsulation ({} bytes)", l4.len())
            };
            ("IPIP".to_string(), detail)
        }
        43 if l4.len() >= 8 && l4[2] == 4 => (
            "SRV6".to_string(),
            format!("{tag_prefix}SRv6 Routing Header (sl={} le={})", l4[3], l4[4]),
        ),
        46 => {
            let detail = if l4.len() >= 8 && (l4[0] >> 4) == 1 {
                let msg_type = l4[1];
                format!("{tag_prefix}RSVP {} (type={msg_type})", rsvp_msg_name(msg_type))
            } else {
                format!("{tag_prefix}RSVP ({} bytes)", l4.len())
            };
            ("RSVP".to_string(), detail)
        }
        47 => {
            if l4.len() >= 4 {
                let flags = u16::from_be_bytes([l4[0], l4[1]]);
                let gre_proto = u16::from_be_bytes([l4[2], l4[3]]);
                if gre_proto == 0x22EB || (gre_proto == 0x88BE && (flags & 0x1000) != 0) {
                    return (
                        "ERSPAN".to_string(),
                        format!("{tag_prefix}ERSPAN Encapsulated Frame (proto=0x{gre_proto:04x})"),
                    );
                }
            }
            ("GRE".to_string(), format!("{tag_prefix}GRE Tunnel Packet"))
        }
        50 => (
            "ESP".to_string(),
            format!("{tag_prefix}IPsec Encapsulating Security Payload"),
        ),
        51 => (
            "AH".to_string(),
            format!("{tag_prefix}IPsec Authentication Header"),
        ),
        89 => (
            "OSPF".to_string(),
            format!("{tag_prefix}Open Shortest Path First"),
        ),
        103 => (
            "PIM".to_string(),
            format!("{tag_prefix}Protocol Independent Multicast"),
        ),
        112 => (
            "VRRP".to_string(),
            format!("{tag_prefix}Virtual Router Redundancy Protocol"),
        ),
        115 => {
            let detail = if l4.len() >= 4 {
                let sid = u32::from_be_bytes([l4[0], l4[1], l4[2], l4[3]]);
                let kind = if sid == 0 { "Control" } else { "Session" };
                format!("{tag_prefix}L2TPv3 {kind} (sid=0x{sid:08x})")
            } else {
                format!("{tag_prefix}L2TPv3 Packet ({} bytes)", l4.len())
            };
            ("L2TP".to_string(), detail)
        }
        132 if l4.len() >= 12 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if l4.len() >= 16 {
                let chunk_type = l4[12];
                let raw_chunk_len = usize::from(u16::from_be_bytes([l4[14], l4[15]]));
                let chunk_end = 12usize.saturating_add(raw_chunk_len.max(4)).min(l4.len());
                if chunk_type == 0 && chunk_end >= 28 && l4.len() >= 28 {
                    let ppid = u32::from_be_bytes([l4[24], l4[25], l4[26], l4[27]]);
                    let data_payload = &l4[28..chunk_end];
                    let ppid_proto = match ppid {
                        60 => Some("NGAP"),
                        18 => Some("S1AP"),
                        46 => Some("DIAMETER"),
                        _ => None,
                    };
                    let port_proto = if sport == 38412 || dport == 38412 {
                        Some("NGAP")
                    } else if sport == 36412 || dport == 36412 {
                        Some("S1AP")
                    } else if sport == 3868 || dport == 3868 {
                        Some("DIAMETER")
                    } else {
                        None
                    };
                    let l7_proto = ppid_proto
                        .or(port_proto)
                        .or_else(|| {
                            if !data_payload.is_empty() {
                                detect_stream_l7(sport, dport, data_payload)
                            } else {
                                None
                            }
                        })
                        .or_else(|| port_to_l7_name(dport, true))
                        .or_else(|| port_to_l7_name(sport, true))
                        .or_else(|| port_to_l7_name(dport, false))
                        .or_else(|| port_to_l7_name(sport, false));
                    let label = l7_proto.unwrap_or("SCTP").to_string();
                    return (
                        label,
                        format!(
                            "{tag_prefix}{sport} -> {dport} (ppid={ppid} len={})",
                            data_payload.len()
                        ),
                    );
                }
                let chunk_name = sctp_chunk_name(chunk_type);
                return (
                    "SCTP".to_string(),
                    format!("{tag_prefix}{sport} -> {dport} {chunk_name}"),
                );
            }
            (
                "SCTP".to_string(),
                format!("{tag_prefix}{sport} -> {dport}"),
            )
        }
        other => (
            format!("IP({other})"),
            format!("{tag_prefix}Protocol {other} ({} bytes)", l4.len()),
        ),
    }
}

/// Formats a single aligned row for the `frameassembly show` packet ladder table.
pub fn format_show_row(
    idx: usize,
    timestamp_ns: u64,
    base_ts: u64,
    data: &[u8],
    ast_proto_label: Option<&str>,
) -> String {
    let time_ms = timestamp_ns.saturating_sub(base_ts) as f64 / 1_000_000.0;
    let (endpoints, detected_proto, summary) = summarize_frame(data);
    let proto = ast_proto_label.unwrap_or(&detected_proto);
    format!(
        "{:<5}  {:<10.3}  {:<39}  {:<10}  {:<5}  {}",
        idx + 1,
        time_ms,
        endpoints,
        proto,
        data.len(),
        summary
    )
}

/// Formats a complete relative-timestamp packet ladder table for `frameassembly show`.
pub fn format_packet_ladder(frames: &[(Vec<u8>, u64)], ast_protocols: &[Protocol]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<5}  {:<10}  {:<39}  {:<10}  {:<5}  Summary",
        "#", "Time (ms)", "Source -> Destination", "Protocol", "Bytes"
    );
    let _ = writeln!(out, "{}", "-".repeat(110));
    let base_ts = frames.first().map(|(_, ts)| *ts).unwrap_or(0);
    for (idx, (data, timestamp_ns)) in frames.iter().enumerate() {
        let ast_label = ast_protocols.get(idx).map(|p| p.display_label());
        let row = format_show_row(idx, *timestamp_ns, base_ts, data, ast_label);
        let _ = writeln!(out, "{row}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a raw Ethernet II / IEEE 802.3 frame for unit tests.
    fn build_eth_frame(dst: [u8; 6], src: [u8; 6], ethertype_or_len: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&ethertype_or_len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Builds a minimal 20-byte TCP segment carrying `payload`.
    fn build_tcp_segment(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut seg = vec![0u8; 20 + payload.len()];
        seg[0..2].copy_from_slice(&sport.to_be_bytes());
        seg[2..4].copy_from_slice(&dport.to_be_bytes());
        seg[7] = 1;
        seg[11] = 1;
        seg[12] = 0x50;
        seg[13] = flags;
        seg[14..16].copy_from_slice(&0xFFFFu16.to_be_bytes());
        seg[20..].copy_from_slice(payload);
        seg
    }

    /// Builds an 8-byte UDP datagram carrying `payload`.
    fn build_udp_datagram(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(8 + payload.len()).unwrap_or(8);
        let mut dgram = vec![0u8; 8 + payload.len()];
        dgram[0..2].copy_from_slice(&sport.to_be_bytes());
        dgram[2..4].copy_from_slice(&dport.to_be_bytes());
        dgram[4..6].copy_from_slice(&total.to_be_bytes());
        dgram[8..].copy_from_slice(payload);
        dgram
    }

    #[test]
    fn test_port_to_l7_name_unified_ports() {
        assert_eq!(port_to_l7_name(6514, true), Some("SYSLOG"));
        assert_eq!(port_to_l7_name(2222, false), Some("ETHERNETIP"));
        assert_eq!(port_to_l7_name(44818, true), Some("ETHERNETIP"));
        assert_eq!(port_to_l7_name(6653, true), Some("OPENFLOW"));
    }

    #[test]
    fn test_port_to_l7_name_wave3a_protocols() {
        assert_eq!(port_to_l7_name(2222, true), Some("SSH"));
        assert_eq!(port_to_l7_name(323, true), Some("RPKIRTR"));
        assert_eq!(port_to_l7_name(646, true), Some("LDP"));
        assert_eq!(port_to_l7_name(646, false), Some("LDP"));
        assert_eq!(port_to_l7_name(1701, false), Some("L2TP"));
        assert_eq!(port_to_l7_name(1790, true), Some("BMP"));
        assert_eq!(port_to_l7_name(2152, false), Some("GTPU"));
        assert_eq!(port_to_l7_name(3222, false), Some("GLBP"));
        assert_eq!(port_to_l7_name(4341, false), Some("LISP"));
        assert_eq!(port_to_l7_name(34964, false), Some("PROFINET"));
        assert_eq!(port_to_l7_name(34980, false), Some("ETHERCAT"));

        assert_eq!(port_to_l7_name(135, true), Some("DCERPC"));
        assert_eq!(port_to_l7_name(137, false), Some("NBNS"));
        assert_eq!(port_to_l7_name(623, false), Some("IPMI"));
        assert_eq!(port_to_l7_name(830, true), Some("NETCONF"));
        assert_eq!(port_to_l7_name(862, false), Some("TWAMP"));
        assert_eq!(port_to_l7_name(1080, true), Some("SOCKS"));
        assert_eq!(port_to_l7_name(1153, true), Some("C1222"));
        assert_eq!(port_to_l7_name(1234, false), Some("BSAP"));
        assert_eq!(port_to_l7_name(1433, true), Some("MSSQL"));
        assert_eq!(port_to_l7_name(1521, true), Some("TNS"));
        assert_eq!(port_to_l7_name(1719, false), Some("H323"));
        assert_eq!(port_to_l7_name(1720, true), Some("H323"));
        assert_eq!(port_to_l7_name(2000, true), Some("SCCP"));
        assert_eq!(port_to_l7_name(2123, false), Some("GTPC"));
        assert_eq!(port_to_l7_name(2404, true), Some("IEC104"));
        assert_eq!(port_to_l7_name(2427, false), Some("MGCP"));
        assert_eq!(port_to_l7_name(3260, true), Some("ISCSI"));
        assert_eq!(port_to_l7_name(3389, true), Some("RDP"));
        assert_eq!(port_to_l7_name(3478, true), Some("TURN"));
        assert_eq!(port_to_l7_name(3478, false), Some("STUN"));
        assert_eq!(port_to_l7_name(3671, false), Some("KNXNETIP"));
        assert_eq!(port_to_l7_name(3702, false), Some("WSDISCOVERY"));
        assert_eq!(port_to_l7_name(3868, true), Some("DIAMETER"));
        assert_eq!(port_to_l7_name(4000, true), Some("ROCPLUS"));
        assert_eq!(port_to_l7_name(4420, true), Some("NVMETCP"));
        assert_eq!(port_to_l7_name(4712, true), Some("SYNCHROPHASOR"));
        assert_eq!(port_to_l7_name(4791, false), Some("ROCEV2"));
        assert_eq!(port_to_l7_name(5000, true), Some("MELSEC"));
        assert_eq!(port_to_l7_name(5005, false), Some("RTCP"));
        assert_eq!(port_to_l7_name(5094, false), Some("HARTIP"));
        assert_eq!(port_to_l7_name(5355, false), Some("LLMNR"));
        assert_eq!(port_to_l7_name(5900, true), Some("VNC"));
        assert_eq!(port_to_l7_name(6667, true), Some("IRC"));
        assert_eq!(port_to_l7_name(8805, false), Some("PFCP"));
        assert_eq!(port_to_l7_name(9092, true), Some("KAFKA"));
        assert_eq!(port_to_l7_name(9600, false), Some("FINS"));
        assert_eq!(port_to_l7_name(13400, true), Some("DOIP"));
        assert_eq!(port_to_l7_name(18245, true), Some("GESRTP"));
        assert_eq!(port_to_l7_name(27017, true), Some("MONGODB"));
        assert_eq!(port_to_l7_name(30490, false), Some("SOMEIP"));
    }

    #[test]
    fn test_summarize_l4_http2_preface_and_bad_ihl_guard() {
        let tcp_http2 = build_tcp_segment(49152, 443, 0x18, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let (label, summary) = summarize_l4(6, &tcp_http2, "");
        assert_eq!(label, "HTTP2");
        assert!(summary.contains("49152 -> 443"));

        let mut bad_ihl_frame = vec![0u8; 34];
        bad_ihl_frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        bad_ihl_frame[14] = 0x42; // Version 4, IHL = 2 (8 bytes < 20)
        bad_ihl_frame[23] = 17;
        let (_ep, proto, desc) = summarize_frame(&bad_ihl_frame);
        assert_eq!(proto, "IPv4");
        assert!(desc.contains("Malformed IPv4 header"));
    }

    #[test]
    fn test_summarize_frame_multi_mpls_and_ipv6_frag() {
        let mut frame = vec![0u8; 14 + 8 + 40 + 8 + 8];
        frame[12..14].copy_from_slice(&0x8847u16.to_be_bytes());
        // Outer MPLS label 100 (BoS=0)
        frame[14..18].copy_from_slice(&((100u32 << 12) | 64).to_be_bytes());
        // Inner MPLS label 200 (BoS=1)
        frame[18..22].copy_from_slice(&((200u32 << 12) | (1 << 8) | 64).to_be_bytes());
        // IPv6 header (Next Header = 44 Fragment)
        let ip6 = &mut frame[22..];
        ip6[0] = 0x60;
        ip6[6] = 44;
        // Fragment header: Next = 17 (UDP), offset = 0, MF = 1
        ip6[40] = 17;
        ip6[42] = 0x00;
        ip6[43] = 0x01;
        // UDP header 5000 -> 53
        ip6[48..50].copy_from_slice(&5000u16.to_be_bytes());
        ip6[50..52].copy_from_slice(&53u16.to_be_bytes());
        ip6[52..54].copy_from_slice(&8u16.to_be_bytes());

        let (_ep, proto, summary) = summarize_frame(&frame);
        assert_eq!(proto, "DNS");
        assert!(summary.contains("MPLS=100"));
        assert!(summary.contains("MPLS=200"));
        assert!(summary.contains("FRAG(off=0)"));
    }

    #[test]
    fn test_summarize_frame_wave3a_l2_ethertypes_and_llc() {
        let src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

        let pppoed = build_eth_frame(dst, src, 0x8863, &[0x11, 0x09, 0x00, 0x00, 0x00, 0x04]);
        let (_, p, s) = summarize_frame(&pppoed);
        assert_eq!(p, "PPPOE");
        assert!(s.contains("PADI"));

        let pppoes = build_eth_frame(dst, src, 0x8864, &[0x11, 0x00, 0x00, 0x2A, 0x00, 0x04, 0x00, 0x21]);
        let (_, p, s) = summarize_frame(&pppoes);
        assert_eq!(p, "PPPOE");
        assert!(s.contains("0x002a"));

        let pn_dcp = build_eth_frame(dst, src, 0x8892, &[0xFE, 0xFE, 0x05, 0x00]);
        assert_eq!(summarize_frame(&pn_dcp).1, "PROFINET");
        assert!(summarize_frame(&pn_dcp).2.contains("DCP"));

        let ecat = build_eth_frame(dst, src, 0x88A4, &[0x10, 0x10, 0x07, 0x00]);
        assert_eq!(summarize_frame(&ecat).1, "ETHERCAT");

        let goose = build_eth_frame(dst, src, 0x88B8, &[0x00, 0x01, 0x00, 0x10]);
        assert_eq!(summarize_frame(&goose).1, "GOOSE");

        let sv = build_eth_frame(dst, src, 0x88BA, &[0x40, 0x00, 0x00, 0x10]);
        assert_eq!(summarize_frame(&sv).1, "SV");

        let macsec = build_eth_frame(dst, src, 0x88E5, &[0x08, 0x00, 0, 0, 0, 1]);
        assert_eq!(summarize_frame(&macsec).1, "MACSEC");

        let pfc = build_eth_frame(dst, src, 0x8808, &[0x01, 0x01, 0x00, 0xFF]);
        assert_eq!(summarize_frame(&pfc).1, "PFC");

        let nsh = build_eth_frame(dst, src, 0x894F, &[0x02, 0x06, 0x00, 0x01, 0x00, 0x00, 0x2A, 0xFF]);
        let (_, p, s) = summarize_frame(&nsh);
        assert_eq!(p, "NSH");
        assert!(s.contains("spi=42 si=255"));

        // 802.3 CDP, IS-IS, STP, and padded RFC 1042 SNAP->DNS
        let cdp_llc = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00, 0x02, 180, 0, 0];
        let mut cdp = build_eth_frame(dst, src, cdp_llc.len() as u16, &cdp_llc);
        cdp.resize(60, 0);
        assert_eq!(summarize_frame(&cdp).1, "CDP");

        let isis_llc = [0xFE, 0xFE, 0x03, 0x83, 27, 1, 0, 18, 0, 0];
        let isis = build_eth_frame(dst, src, isis_llc.len() as u16, &isis_llc);
        let (_, p, s) = summarize_frame(&isis);
        assert_eq!(p, "ISIS");
        assert!(s.contains("L1 LSP"));

        let stp_llc = [0x42, 0x42, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        let stp = build_eth_frame(dst, src, stp_llc.len() as u16, &stp_llc);
        assert_eq!(summarize_frame(&stp).1, "STP");

        let mut snap_payload = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
        let mut ipv4_udp = vec![0u8; 28];
        ipv4_udp[0] = 0x45;
        ipv4_udp[9] = 17;
        ipv4_udp[20..28].copy_from_slice(&build_udp_datagram(53530, 53, &[]));
        snap_payload.extend_from_slice(&ipv4_udp);
        let snap_len = snap_payload.len() as u16;
        snap_payload.extend_from_slice(&[0u8; 10]); // Ethernet padding beyond IEEE 802.3 length
        let snap = build_eth_frame(dst, src, snap_len, &snap_payload);
        let (_, p, s) = summarize_frame(&snap);
        assert_eq!(p, "DNS");
        assert!(s.contains("len=0"));

        // EoMPLS CW wrapping MACsec
        let mut eompls_payload = vec![0, 0, 0, 0];
        eompls_payload.extend_from_slice(&macsec);
        let mut mpls_eompls = vec![0u8; 4];
        mpls_eompls[..4].copy_from_slice(&((500u32 << 12) | (1 << 8) | 64).to_be_bytes());
        mpls_eompls.extend_from_slice(&eompls_payload);
        let frame_eompls = build_eth_frame(dst, src, 0x8847, &mpls_eompls);
        assert_eq!(summarize_frame(&frame_eompls).1, "MACSEC");
    }

    #[test]
    fn test_summarize_l3_srv6_and_ip_protocols() {
        let mut srv6_frame = vec![0u8; 14 + 40 + 24];
        srv6_frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        srv6_frame[14] = 0x60;
        srv6_frame[20] = 43; // Routing Header
        srv6_frame[54] = 59; // No Next Header
        srv6_frame[55] = 2; // Hdr Ext Len = (2 + 1) * 8 = 24
        srv6_frame[56] = 4; // SRv6 Routing Type 4
        srv6_frame[57] = 1; // Segments Left
        assert_eq!(summarize_frame(&srv6_frame).1, "SRV6");

        let mut rt0_frame = vec![0u8; 14 + 40 + 8 + 8];
        rt0_frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        rt0_frame[14] = 0x60;
        rt0_frame[20] = 43; // Routing Header Type 0 (not SRv6) should still skip to UDP
        rt0_frame[54] = 17;
        rt0_frame[62..70].copy_from_slice(&build_udp_datagram(10000, 53, &[]));
        assert_eq!(summarize_frame(&rt0_frame).1, "DNS");

        assert_eq!(summarize_l4(4, &[0x45; 20], "").0, "IPIP");
        assert_eq!(summarize_l4(41, &[0x60; 40], "").0, "IPIP");
        assert_eq!(summarize_l4(46, &[0x10, 1, 0, 0, 0, 0, 0, 8], "").0, "RSVP");
        assert_eq!(summarize_l4(47, &[0x30, 0x00, 0x88, 0xBE], "").0, "ERSPAN");
        assert_eq!(summarize_l4(47, &[0x00, 0x00, 0x22, 0xEB], "").0, "ERSPAN");
        assert_eq!(summarize_l4(47, &[0x20, 0x00, 0x88, 0xBE], "").0, "GRE");
        assert_eq!(summarize_l4(115, &[0, 0, 0, 1], "").0, "L2TP");
    }

    #[test]
    fn test_summarize_l4_sctp_ppid_and_l7_disambiguation() {
        let make_sctp_data = |sport: u16, dport: u16, ppid: u32| -> Vec<u8> {
            let mut pkt = vec![0u8; 32];
            pkt[0..2].copy_from_slice(&sport.to_be_bytes());
            pkt[2..4].copy_from_slice(&dport.to_be_bytes());
            pkt[14..16].copy_from_slice(&20u16.to_be_bytes());
            pkt[24..28].copy_from_slice(&ppid.to_be_bytes());
            pkt
        };
        assert_eq!(summarize_l4(132, &make_sctp_data(38412, 38412, 60), "").0, "NGAP");
        assert_eq!(summarize_l4(132, &make_sctp_data(36412, 36412, 18), "").0, "S1AP");
        assert_eq!(summarize_l4(132, &make_sctp_data(40000, 3868, 46), "").0, "DIAMETER");
        let sctp_init = [0x96, 0x0C, 0x96, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 20];
        assert_eq!(summarize_l4(132, &sctp_init, "").0, "SCTP");

        // 830 NETCONF vs SSH
        assert_eq!(
            summarize_l4(6, &build_tcp_segment(50000, 830, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n"), "").0,
            "SSH"
        );
        assert_eq!(
            summarize_l4(6, &build_tcp_segment(50000, 830, 0x18, b"<?xml version=\"1.0\"?><hello/>"), "").0,
            "NETCONF"
        );

        // 102 S7COMM vs S7COMMPLUS vs MMS
        assert_eq!(
            summarize_l4(6, &build_tcp_segment(50000, 102, 0x18, &[3, 0, 0, 10, 2, 0xF0, 0x80, 0x32]), "").0,
            "S7COMM"
        );
        assert_eq!(
            summarize_l4(6, &build_tcp_segment(50000, 102, 0x18, &[3, 0, 0, 10, 2, 0xF0, 0x80, 0x72]), "").0,
            "S7COMMPLUS"
        );
        assert_eq!(
            summarize_l4(6, &build_tcp_segment(50000, 102, 0x18, &[3, 0, 0, 12, 2, 0xF0, 0x80, 0x01, 0, 1, 0]), "").0,
            "MMS"
        );

        // 80 / 443 NTLM, DoH, WebSocket, HTTP, TLS
        assert_eq!(
            summarize_l4(
                6,
                &build_tcp_segment(50000, 80, 0x18, b"GET / HTTP/1.1\r\nAuthorization: NTLM TlRMTV\r\n\r\n"),
                ""
            ).0,
            "NTLM"
        );
        assert_eq!(
            summarize_l4(
                6,
                &build_tcp_segment(
                    50000,
                    80,
                    0x18,
                    b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\n\r\n"
                ),
                ""
            ).0,
            "DOH"
        );
        assert_eq!(
            summarize_l4(
                6,
                &build_tcp_segment(50000, 80, 0x18, &[0x81, 0x82, 1, 2, 3, 4, b'h', b'i']),
                ""
            ).0,
            "WEBSOCKET"
        );
        assert_eq!(
            summarize_l4(
                6,
                &build_tcp_segment(50000, 443, 0x18, &[0x16, 0x03, 0x01, 0x00, 0x05, 1, 0, 0, 1, 0]),
                ""
            ).0,
            "TLS"
        );

        // 3478 TURN vs STUN
        let mut stun = vec![0u8; 20];
        stun[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        stun[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        assert_eq!(summarize_l4(17, &build_udp_datagram(50000, 3478, &stun), "").0, "STUN");

        let mut turn = stun.clone();
        turn[0..2].copy_from_slice(&0x0003u16.to_be_bytes());
        assert_eq!(summarize_l4(17, &build_udp_datagram(50000, 3478, &turn), "").0, "TURN");

        let turn_cd = [0x40, 0x00, 0x00, 0x02, 0xAA, 0xBB];
        assert_eq!(summarize_l4(17, &build_udp_datagram(50000, 3478, &turn_cd), "").0, "TURN");

        // 4000 ROCPLUS vs TELNET
        assert_eq!(
            summarize_l4(
                6,
                &build_tcp_segment(50000, 4000, 0x18, &[1, 1, 2, 0, 17, 2, 0xAA, 0xBB, 0x12, 0x34]),
                ""
            ).0,
            "ROCPLUS"
        );
        assert_eq!(
            summarize_l4(6, &build_tcp_segment(50000, 4000, 0x18, &[0xFF, 0xFD, 0x18]), "").0,
            "TELNET"
        );
        assert_eq!(
            summarize_l4(6, &build_tcp_segment(50000, 4000, 0x18, b"login: admin\r\n"), "").0,
            "TELNET"
        );
    }
}
