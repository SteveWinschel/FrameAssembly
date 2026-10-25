//! Low-level network packet construction, header framing, and wire serialization utilities.
//!
//! This module provides deterministic wire-format builders for Layer 2 (Ethernet II, IEEE 802.1Q
//! VLAN, IEEE 802.1ad QinQ, and RFC 3032 MPLS shim headers), Layer 3 (RFC 791 IPv4 and RFC 8200
//! IPv6 headers with DSCP, ECN, fragmentation, and Flow Label fields), and Layer 4 (RFC 9293 TCP
//! with options and RFC 768 UDP datagrams), including complete RFC 1071 one's-complement Internet
//! checksum and pseudo-header checksum computation.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::{L2Modifiers, L3Modifiers, L4Modifiers, TcpFlag, TcpOptions};
use crate::error::CompilerError;

/// Computes the 16-bit one's complement Internet Checksum (RFC 1071) over multiple byte slices.
///
/// # Examples
/// ```
/// use frameassembly::packet::internet_checksum;
///
/// let data = [0x45, 0x00, 0x00, 0x3c];
/// let csum = internet_checksum(&[&data]);
/// assert_ne!(csum, 0);
/// ```
pub fn internet_checksum(data: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for slice in data {
        let (chunks, remainder) = slice.as_chunks::<2>();
        for chunk in chunks {
            sum += u16::from_be_bytes(*chunk) as u32;
        }
        if !remainder.is_empty() {
            sum += (remainder[0] as u32) << 8;
        }
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Constructs a 20-byte IPv4 header with RFC 791 fields and header checksum.
pub fn build_ipv4_header(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    l3: &L3Modifiers,
    l4_and_payload_len: usize,
) -> Result<Vec<u8>, CompilerError> {
    let mut header = Vec::with_capacity(20);
    // Byte 0: Version 4, IHL 5 (20 bytes)
    header.push(0x45);
    // Byte 1: Type of Service (DSCP 6 bits + ECN 2 bits)
    let dscp = l3.dscp.unwrap_or(0) & 0x3F;
    let ecn = l3.ecn.unwrap_or(0) & 0x03;
    let tos = (dscp << 2) | ecn;
    header.push(tos);
    // Bytes 2..4: Total Length (header + payload)
    let total_len = (20 + l4_and_payload_len) as u16;
    header.extend_from_slice(&total_len.to_be_bytes());
    // Bytes 4..6: Identification
    let ipid = l3.ipid.unwrap_or(0);
    header.extend_from_slice(&ipid.to_be_bytes());
    // Bytes 6..8: Flags and Fragment Offset
    let mut flags_and_offset: u16 = l3.frag_offset.unwrap_or(0) & 0x1FFF;
    if l3.df {
        flags_and_offset |= 0x4000;
    }
    if l3.mf {
        flags_and_offset |= 0x2000;
    }
    header.extend_from_slice(&flags_and_offset.to_be_bytes());
    // Byte 8: TTL
    let ttl = l3.ttl.unwrap_or(64);
    header.push(ttl);
    // Byte 9: Protocol
    header.push(protocol);
    // Bytes 10..12: Checksum placeholder (0x0000)
    header.push(0);
    header.push(0);
    // Bytes 12..16: Source IPv4
    header.extend_from_slice(&src);
    // Bytes 16..20: Destination IPv4
    header.extend_from_slice(&dst);

    // Compute and insert header checksum
    let checksum = internet_checksum(&[&header[..]]);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());

    Ok(header)
}

/// Constructs a 40-byte IPv6 header per RFC 8200 with Traffic Class and Flow Label.
pub fn build_ipv6_header(
    src: [u8; 16],
    dst: [u8; 16],
    next_header: u8,
    l3: &L3Modifiers,
    l4_and_payload_len: usize,
) -> Result<Vec<u8>, CompilerError> {
    let mut header = Vec::with_capacity(40);
    // Version (4 bits: 6) + Traffic Class (8 bits: DSCP/ECN) + Flow Label (20 bits)
    let dscp = l3.dscp.unwrap_or(0) & 0x3F;
    let ecn = l3.ecn.unwrap_or(0) & 0x03;
    let tc = (dscp << 2) | ecn;
    let flow_label = l3.flowlabel.unwrap_or(0) & 0x000F_FFFF;
    let v_tc_fl: u32 = (0x6_u32 << 28) | ((tc as u32) << 20) | flow_label;
    header.extend_from_slice(&v_tc_fl.to_be_bytes());
    // Bytes 4..6: Payload Length
    let payload_len = l4_and_payload_len as u16;
    header.extend_from_slice(&payload_len.to_be_bytes());
    // Byte 6: Next Header
    header.push(next_header);
    // Byte 7: Hop Limit (from TTL)
    let hop_limit = l3.ttl.unwrap_or(64);
    header.push(hop_limit);
    // Bytes 8..24: Source IPv6 address
    header.extend_from_slice(&src);
    // Bytes 24..40: Destination IPv6 address
    header.extend_from_slice(&dst);

    Ok(header)
}

/// Encodes TCP options into a 4-byte-aligned byte vector.
fn encode_tcp_options(opts: &TcpOptions) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(mss) = opts.mss {
        buf.push(2); // Kind 2 (MSS)
        buf.push(4); // Length 4
        buf.extend_from_slice(&mss.to_be_bytes());
    }
    if let Some(wscale) = opts.wscale {
        buf.push(1); // NOP
        buf.push(3); // Kind 3 (Window Scale)
        buf.push(3); // Length 3
        buf.push(wscale);
    }
    if opts.sack_perm {
        buf.push(4); // Kind 4 (SACK Permitted)
        buf.push(2); // Length 2
        buf.push(1); // NOP
        buf.push(1); // NOP
    }
    if opts.tsval.is_some() || opts.tsecr.is_some() {
        buf.push(1); // NOP
        buf.push(1); // NOP
        buf.push(8); // Kind 8 (Timestamp)
        buf.push(10); // Length 10
        buf.extend_from_slice(&opts.tsval.unwrap_or(0).to_be_bytes());
        buf.extend_from_slice(&opts.tsecr.unwrap_or(0).to_be_bytes());
    }
    while buf.len() % 4 != 0 {
        buf.push(1); // Pad with NOP to 32-bit boundary
    }
    buf
}

/// Constructs a complete TCP segment including options, flags, and pseudo-header checksum.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_segment(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    flags: &[TcpFlag],
    seq: Option<u32>,
    ack_num: Option<u32>,
    win: Option<u16>,
    urgent: Option<u16>,
    tcp_options: Option<&TcpOptions>,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let opts_buf = tcp_options.map(encode_tcp_options).unwrap_or_default();
    let tcp_header_len = 20 + opts_buf.len();
    let data_offset = (tcp_header_len / 4) as u8;

    let mut tcp_header = Vec::with_capacity(tcp_header_len);
    tcp_header.extend_from_slice(&src_port.to_be_bytes());
    tcp_header.extend_from_slice(&dst_port.to_be_bytes());
    tcp_header.extend_from_slice(&seq.unwrap_or(0).to_be_bytes());
    tcp_header.extend_from_slice(&ack_num.unwrap_or(0).to_be_bytes());
    tcp_header.push(data_offset << 4);

    let mut flag_byte = 0u8;
    for f in flags {
        match f {
            TcpFlag::Fin => flag_byte |= 0x01,
            TcpFlag::Syn => flag_byte |= 0x02,
            TcpFlag::Rst => flag_byte |= 0x04,
            TcpFlag::Psh => flag_byte |= 0x08,
            TcpFlag::Ack => flag_byte |= 0x10,
            TcpFlag::Urg => flag_byte |= 0x20,
            TcpFlag::Ece => flag_byte |= 0x40,
            TcpFlag::Cwr => flag_byte |= 0x80,
        }
    }
    tcp_header.push(flag_byte);
    tcp_header.extend_from_slice(&win.unwrap_or(64240).to_be_bytes());
    // Checksum placeholder
    tcp_header.push(0);
    tcp_header.push(0);
    tcp_header.extend_from_slice(&urgent.unwrap_or(0).to_be_bytes());
    tcp_header.extend_from_slice(&opts_buf);

    let tcp_len = (tcp_header.len() + payload.len()) as u32;

    let checksum = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let pseudo = [
                s.octets()[0], s.octets()[1], s.octets()[2], s.octets()[3],
                d.octets()[0], d.octets()[1], d.octets()[2], d.octets()[3],
                0, 6,
                (tcp_len >> 8) as u8, tcp_len as u8,
            ];
            internet_checksum(&[&pseudo, &tcp_header, payload])
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut pseudo = Vec::with_capacity(40);
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&tcp_len.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
            internet_checksum(&[&pseudo, &tcp_header, payload])
        }
        _ => {
            return Err(CompilerError::BackendError(
                "Source and Destination IP versions must match".to_string(),
            ));
        }
    };

    tcp_header[16..18].copy_from_slice(&checksum.to_be_bytes());

    let mut segment = tcp_header;
    segment.extend_from_slice(payload);
    Ok(segment)
}

/// Constructs a UDP datagram including mandatory IPv6 checksum handling per RFC 8200 §8.1.
pub fn build_udp_datagram(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let udp_len = (8 + payload.len()) as u16;
    let mut udp_header = Vec::with_capacity(8);
    udp_header.extend_from_slice(&src_port.to_be_bytes());
    udp_header.extend_from_slice(&dst_port.to_be_bytes());
    udp_header.extend_from_slice(&udp_len.to_be_bytes());
    udp_header.push(0);
    udp_header.push(0);

    let udp_len_u32 = udp_len as u32;

    let checksum = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let pseudo = [
                s.octets()[0], s.octets()[1], s.octets()[2], s.octets()[3],
                d.octets()[0], d.octets()[1], d.octets()[2], d.octets()[3],
                0, 17,
                (udp_len >> 8) as u8, udp_len as u8,
            ];
            let c = internet_checksum(&[&pseudo, &udp_header, payload]);
            if c == 0 { 0xFFFF } else { c }
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut pseudo = Vec::with_capacity(40);
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&udp_len_u32.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
            let c = internet_checksum(&[&pseudo, &udp_header, payload]);
            if c == 0 { 0xFFFF } else { c }
        }
        _ => {
            return Err(CompilerError::BackendError(
                "Source and Destination IP versions must match".to_string(),
            ));
        }
    };

    udp_header[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut datagram = udp_header;
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

/// Constructs a complete IPv4 or IPv6 packet wrapping the given payload.
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP versions do not match.
pub fn build_ip_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    l3: &L3Modifiers,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let (mut header, _) = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            build_ipv4_header(s.octets(), d.octets(), protocol, l3, payload.len())?,
            0x0800_u16,
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            build_ipv6_header(s.octets(), d.octets(), protocol, l3, payload.len())?,
            0x86DD_u16,
        ),
        _ => {
            return Err(CompilerError::BackendError(
                "Source and Destination IP versions must match".to_string(),
            ));
        }
    };
    header.extend_from_slice(payload);
    Ok(header)
}

/// Prepends Ethernet, 802.1Q, 802.1ad QinQ, or RFC 3032 MPLS headers around an inner packet.
pub fn build_ethernet_and_l2(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    l2: &L2Modifiers,
    ip_ethertype: u16,
    inner_packet: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + 8 + 4 + inner_packet.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);

    if let Some(qinq) = &l2.qinq {
        frame.extend_from_slice(&0x88A8_u16.to_be_bytes());
        let pcp = l2.vlan.as_ref().and_then(|v| v.pcp).unwrap_or(0) & 0x07;
        let dei = l2.vlan.as_ref().and_then(|v| v.dei).unwrap_or(0) & 0x01;
        let outer_tci: u16 = ((pcp as u16) << 13) | ((dei as u16) << 12) | (qinq.outer_vid & 0x0FFF);
        frame.extend_from_slice(&outer_tci.to_be_bytes());

        if let Some(inner_vid) = qinq.inner_vid {
            frame.extend_from_slice(&0x8100_u16.to_be_bytes());
            let inner_tci: u16 = inner_vid & 0x0FFF;
            frame.extend_from_slice(&inner_tci.to_be_bytes());
        }

        if let Some(mpls) = &l2.mpls {
            frame.extend_from_slice(&0x8847_u16.to_be_bytes());
            let exp = mpls.exp.unwrap_or(0) & 0x07;
            let bos = mpls.bos.unwrap_or(1) & 0x01;
            let ttl = mpls.ttl.unwrap_or(64);
            let mpls_entry: u32 = ((mpls.label & 0x000F_FFFF) << 12)
                | ((exp as u32) << 9)
                | ((bos as u32) << 8)
                | (ttl as u32);
            frame.extend_from_slice(&mpls_entry.to_be_bytes());
        } else {
            let next_et = l2.ethertype.unwrap_or(ip_ethertype);
            frame.extend_from_slice(&next_et.to_be_bytes());
        }
    } else if let Some(vlan) = &l2.vlan {
        frame.extend_from_slice(&0x8100_u16.to_be_bytes());
        let pcp = vlan.pcp.unwrap_or(0) & 0x07;
        let dei = vlan.dei.unwrap_or(0) & 0x01;
        let tci: u16 = ((pcp as u16) << 13) | ((dei as u16) << 12) | (vlan.vid & 0x0FFF);
        frame.extend_from_slice(&tci.to_be_bytes());

        if let Some(mpls) = &l2.mpls {
            frame.extend_from_slice(&0x8847_u16.to_be_bytes());
            let exp = mpls.exp.unwrap_or(0) & 0x07;
            let bos = mpls.bos.unwrap_or(1) & 0x01;
            let ttl = mpls.ttl.unwrap_or(64);
            let mpls_entry: u32 = ((mpls.label & 0x000F_FFFF) << 12)
                | ((exp as u32) << 9)
                | ((bos as u32) << 8)
                | (ttl as u32);
            frame.extend_from_slice(&mpls_entry.to_be_bytes());
        } else {
            let next_et = l2.ethertype.unwrap_or(ip_ethertype);
            frame.extend_from_slice(&next_et.to_be_bytes());
        }
    } else if let Some(mpls) = &l2.mpls {
        frame.extend_from_slice(&0x8847_u16.to_be_bytes());
        let exp = mpls.exp.unwrap_or(0) & 0x07;
        let bos = mpls.bos.unwrap_or(1) & 0x01;
        let ttl = mpls.ttl.unwrap_or(64);
        let mpls_entry: u32 = ((mpls.label & 0x000F_FFFF) << 12)
            | ((exp as u32) << 9)
            | ((bos as u32) << 8)
            | (ttl as u32);
        frame.extend_from_slice(&mpls_entry.to_be_bytes());
    } else {
        let next_et = l2.ethertype.unwrap_or(ip_ethertype);
        frame.extend_from_slice(&next_et.to_be_bytes());
    }

    frame.extend_from_slice(inner_packet);
    frame
}

/// Builds a complete wire-level packet supporting dual-stack IPv4/IPv6, L2, L3, and L4 modifiers.
///
/// # Examples
/// ```
/// use std::net::Ipv4Addr;
/// use frameassembly::ast::{L2Modifiers, L3Modifiers, L4Modifiers};
/// use frameassembly::packet::build_wire_packet;
///
/// let src_ip = Ipv4Addr::new(10, 0, 0, 1).into();
/// let dst_ip = Ipv4Addr::new(10, 0, 0, 2).into();
/// let mac = [0; 6];
///
/// let packet = build_wire_packet(
///     src_ip, dst_ip, mac, mac,
///     &L2Modifiers::default(), &L3Modifiers::default(), &L4Modifiers::default(),
///     true, 12345, 80, &[frameassembly::ast::TcpFlag::Syn],
///     None, None, None, None, Some(b"Hello"),
/// ).unwrap();
/// assert!(!packet.is_empty());
/// ```
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP version matching fails or limits are exceeded.
#[allow(clippy::too_many_arguments)]
pub fn build_wire_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    l2: &L2Modifiers,
    l3: &L3Modifiers,
    l4: &L4Modifiers,
    is_tcp: bool,
    src_port: u16,
    dst_port: u16,
    flags: &[TcpFlag],
    seq: Option<u32>,
    ack_num: Option<u32>,
    win: Option<u16>,
    urgent: Option<u16>,
    payload: Option<&[u8]>,
) -> Result<Vec<u8>, CompilerError> {
    let payload_bytes = payload.unwrap_or(&[]);

    let (l4_segment, l4_proto_num) = if is_tcp {
        (
            build_tcp_segment(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                flags,
                seq,
                ack_num,
                win,
                urgent,
                l4.tcp_options.as_ref(),
                payload_bytes,
            )?,
            6_u8,
        )
    } else {
        (
            build_udp_datagram(src_ip, dst_ip, src_port, dst_port, payload_bytes)?,
            17_u8,
        )
    };

    let (ip_header, ip_ethertype) = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            build_ipv4_header(s.octets(), d.octets(), l4_proto_num, l3, l4_segment.len())?,
            0x0800_u16,
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            build_ipv6_header(s.octets(), d.octets(), l4_proto_num, l3, l4_segment.len())?,
            0x86DD_u16,
        ),
        _ => {
            return Err(CompilerError::BackendError(
                "Source and Destination IP versions must match".to_string(),
            ));
        }
    };

    let mut ip_packet = ip_header;
    ip_packet.extend_from_slice(&l4_segment);

    let frame = build_ethernet_and_l2(src_mac, dst_mac, l2, ip_ethertype, &ip_packet);
    Ok(frame)
}

/// Builds a complete Ethernet, IPv4/IPv6, and TCP packet.
///
/// Backward-compatible wrapper forwarding to [`build_wire_packet`].
///
/// # Examples
/// ```
/// use std::net::Ipv4Addr;
/// use frameassembly::packet::build_tcp_packet;
///
/// let src_ip = Ipv4Addr::new(10, 0, 0, 1).into();
/// let dst_ip = Ipv4Addr::new(10, 0, 0, 2).into();
/// let mac = [0; 6];
///
/// let packet = build_tcp_packet(
///     src_ip, 12345, dst_ip, 80, &[frameassembly::ast::TcpFlag::Syn], None, None, None, Some(b"Hello"), mac, mac
/// ).unwrap();
/// assert!(!packet.is_empty());
/// ```
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP versions do not match or serialization fails.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    flags: &[crate::ast::TcpFlag],
    seq: Option<u32>,
    ack_num: Option<u32>,
    win: Option<u16>,
    payload: Option<&[u8]>,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Result<Vec<u8>, CompilerError> {
    let l2 = L2Modifiers::default();
    let l3 = L3Modifiers::default();
    let l4 = L4Modifiers::default();
    build_wire_packet(
        src_ip,
        dst_ip,
        src_mac,
        dst_mac,
        &l2,
        &l3,
        &l4,
        true,
        src_port,
        dst_port,
        flags,
        seq,
        ack_num,
        win,
        None,
        payload,
    )
}

/// Builds a complete Ethernet, IPv4/IPv6, and UDP packet.
///
/// Backward-compatible wrapper forwarding to [`build_wire_packet`].
///
/// # Examples
/// ```
/// use std::net::Ipv4Addr;
/// use frameassembly::packet::build_udp_packet;
///
/// let src_ip = Ipv4Addr::new(10, 0, 0, 1).into();
/// let dst_ip = Ipv4Addr::new(10, 0, 0, 2).into();
/// let mac = [0; 6];
///
/// let packet = build_udp_packet(
///     src_ip, 12345, dst_ip, 53, Some(b"DNS Query"), mac, mac
/// ).unwrap();
/// assert!(!packet.is_empty());
/// ```
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP versions do not match or serialization fails.
pub fn build_udp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: Option<&[u8]>,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Result<Vec<u8>, CompilerError> {
    let l2 = L2Modifiers::default();
    let l3 = L3Modifiers::default();
    let l4 = L4Modifiers::default();
    build_wire_packet(
        src_ip,
        dst_ip,
        src_mac,
        dst_mac,
        &l2,
        &l3,
        &l4,
        false,
        src_port,
        dst_port,
        &[],
        None,
        None,
        None,
        None,
        payload,
    )
}
