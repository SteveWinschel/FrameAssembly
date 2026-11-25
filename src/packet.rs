//! Low-level network packet construction, header framing, and wire serialization utilities.
//!
//! This module provides deterministic wire-format builders for Layer 2 (Ethernet II, IEEE 802.3
//! LLC, IEEE 802.1Q VLAN, IEEE 802.1ad QinQ, IEEE 802.3 CRC-32 FCS trailers, RFC 4448 EoMPLS
//! pseudowire framing, and RFC 3032 multi-label MPLS shim stacks), Layer 3 (RFC 791 IPv4 with
//! Router Alert and RFC 8200 IPv6 with Hop-by-Hop and Fragment extension headers), and Layer 4
//! (RFC 9293/7323 TCP with compact options, SACK blocks, MD5, TFO, and RFC 768 UDP datagrams),
//! including RFC 1071 checksums and negative-test corruption toggles.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::{L2Modifiers, L3Modifiers, L4Modifiers, MplsSpec, TcpFlag, TcpOptions};
use crate::error::CompilerError;

/// Computes the reflected IEEE 802.3 CRC-32 Frame Check Sequence over `data`.
///
/// Uses the standard IEEE 802.3 polynomial (`0xEDB88320`), `init = 0xFFFFFFFF`, and
/// `xorout = 0xFFFFFFFF`; callers serialize the resulting value in little-endian wire order.
pub fn ieee8023_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

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

/// Constructs a 20-byte (or 24-byte with Router Alert) IPv4 header with RFC 791 fields and checksum.
pub fn build_ipv4_header(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    l3: &L3Modifiers,
    l4_and_payload_len: usize,
) -> Result<Vec<u8>, CompilerError> {
    let hdr_len: usize = if l3.router_alert { 24 } else { 20 };
    let mut header = Vec::with_capacity(hdr_len);
    // Byte 0: Version 4, IHL 5 (20 bytes) or IHL 6 (24 bytes with Router Alert option)
    header.push(if l3.router_alert { 0x46 } else { 0x45 });
    // Byte 1: Type of Service (DSCP 6 bits + ECN 2 bits)
    let dscp = l3.dscp.unwrap_or(0) & 0x3F;
    let ecn = l3.ecn.unwrap_or(0) & 0x03;
    let tos = (dscp << 2) | ecn;
    header.push(tos);
    // Bytes 2..4: Total Length (header + payload)
    let total_len_usize = hdr_len
        .checked_add(l4_and_payload_len)
        .filter(|&n| n <= u16::MAX as usize)
        .ok_or_else(|| {
            CompilerError::BackendError(alloc::format!(
                "IPv4 total packet length ({} bytes) exceeds the 65,535-byte RFC 791 maximum",
                hdr_len.saturating_add(l4_and_payload_len)
            ))
        })?;
    let total_len = total_len_usize as u16;
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
    // Optional 4-byte RFC 2113 Router Alert IP option (copied=1, class=0, number=20 -> 0x94, len=4, val=0x0000)
    if l3.router_alert {
        header.extend_from_slice(&[0x94, 0x04, 0x00, 0x00]);
    }

    // Compute and insert header checksum (inverted when `bad_ip_checksum` negative testing is enabled)
    let mut checksum = internet_checksum(&[&header[..]]);
    if l3.bad_ip_checksum {
        checksum ^= 0xFFFF;
    }
    header[10..12].copy_from_slice(&checksum.to_be_bytes());

    Ok(header)
}

/// Constructs a 40-byte IPv6 header per RFC 8200 with optional Hop-by-Hop Router Alert (`0`)
/// and Fragment (`44`) extension headers.
pub fn build_ipv6_header(
    src: [u8; 16],
    dst: [u8; 16],
    next_header: u8,
    l3: &L3Modifiers,
    l4_and_payload_len: usize,
) -> Result<Vec<u8>, CompilerError> {
    let has_hbh = l3.router_alert;
    let has_frag = l3.ipid.is_some() || l3.mf || l3.frag_offset.is_some();
    let ext_len = usize::from(has_hbh) * 8 + usize::from(has_frag) * 8;
    let after_hbh_nh = if has_frag { 44_u8 } else { next_header };
    let outer_nh = if has_hbh { 0_u8 } else { after_hbh_nh };

    let mut header = Vec::with_capacity(40 + ext_len);
    // Version (4 bits: 6) + Traffic Class (8 bits: DSCP/ECN) + Flow Label (20 bits)
    let dscp = l3.dscp.unwrap_or(0) & 0x3F;
    let ecn = l3.ecn.unwrap_or(0) & 0x03;
    let tc = (dscp << 2) | ecn;
    let flow_label = l3.flowlabel.unwrap_or(0) & 0x000F_FFFF;
    let v_tc_fl: u32 = (0x6_u32 << 28) | ((tc as u32) << 20) | flow_label;
    header.extend_from_slice(&v_tc_fl.to_be_bytes());
    // Bytes 4..6: Payload Length (extension headers + L4 + payload)
    let total_v6_payload = ext_len
        .checked_add(l4_and_payload_len)
        .filter(|&n| n <= u16::MAX as usize)
        .ok_or_else(|| {
            CompilerError::BackendError(alloc::format!(
                "IPv6 payload length ({} bytes) exceeds the 65,535-byte RFC 8200 header limit",
                ext_len.saturating_add(l4_and_payload_len)
            ))
        })?;
    let payload_len = total_v6_payload as u16;
    header.extend_from_slice(&payload_len.to_be_bytes());
    // Byte 6: Next Header
    header.push(outer_nh);
    // Byte 7: Hop Limit (from TTL)
    let hop_limit = l3.ttl.unwrap_or(64);
    header.push(hop_limit);
    // Bytes 8..24: Source IPv6 address
    header.extend_from_slice(&src);
    // Bytes 24..40: Destination IPv6 address
    header.extend_from_slice(&dst);

    // Optional RFC 2711 Hop-by-Hop Router Alert extension header (NextHeader = 0)
    if has_hbh {
        header.extend_from_slice(&[after_hbh_nh, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00]);
    }
    // Optional RFC 8200 Fragment extension header (NextHeader = 44)
    if has_frag {
        let frag_off = l3.frag_offset.unwrap_or(0) & 0x1FFF;
        let mf_bit = u16::from(l3.mf);
        let off_m = (frag_off << 3) | mf_bit;
        let frag_id = u32::from(l3.ipid.unwrap_or(0));
        header.push(next_header);
        header.push(0x00);
        header.extend_from_slice(&off_m.to_be_bytes());
        header.extend_from_slice(&frag_id.to_be_bytes());
    }

    Ok(header)
}

/// Encodes TCP options into a 4-byte-aligned byte vector capped at the 40-byte RFC 9293 limit.
fn encode_tcp_options(opts: &TcpOptions) -> Result<Vec<u8>, CompilerError> {
    let mut buf = Vec::new();
    if let Some(mss) = opts.mss {
        buf.push(2); // Kind 2 (MSS)
        buf.push(4); // Length 4
        buf.extend_from_slice(&mss.to_be_bytes());
    }
    let has_ts = opts.tsval.is_some() || opts.tsecr.is_some();
    if opts.sack_perm && has_ts {
        // Compact Linux-style 20-byte SYN option packing: MSS(4) + SACKPerm(2) + TS(10) + NOP+WS(4)
        buf.push(4);
        buf.push(2);
        buf.push(8);
        buf.push(10);
        buf.extend_from_slice(&opts.tsval.unwrap_or(0).to_be_bytes());
        buf.extend_from_slice(&opts.tsecr.unwrap_or(0).to_be_bytes());
    } else {
        if opts.sack_perm {
            buf.push(4); // Kind 4 (SACK Permitted)
            buf.push(2); // Length 2
        }
        if has_ts {
            while buf.len() % 4 != 2 {
                buf.push(1); // NOP align so 8-byte timestamps sit on 4-byte boundary
            }
            buf.push(8); // Kind 8 (Timestamp)
            buf.push(10); // Length 10
            buf.extend_from_slice(&opts.tsval.unwrap_or(0).to_be_bytes());
            buf.extend_from_slice(&opts.tsecr.unwrap_or(0).to_be_bytes());
        }
    }
    if let Some(wscale) = opts.wscale {
        if buf.len() % 4 != 1 {
            buf.push(1); // NOP align before 3-byte WScale
        }
        buf.push(3); // Kind 3 (Window Scale)
        buf.push(3); // Length 3
        buf.push(wscale);
    }
    if !opts.sack_blocks.is_empty() {
        let opt_len = 2 + opts.sack_blocks.len() * 8;
        if buf.len() + opt_len > 40 {
            return Err(CompilerError::BackendError(
                "TCP options exceed the 40-byte RFC 9293 header options limit".to_string(),
            ));
        }
        buf.push(5); // Kind 5 (SACK blocks)
        buf.push(opt_len as u8);
        for &(left, right) in &opts.sack_blocks {
            buf.extend_from_slice(&left.to_be_bytes());
            buf.extend_from_slice(&right.to_be_bytes());
        }
    }
    if let Some(md5) = &opts.tcp_md5 {
        let opt_len = 2usize.saturating_add(md5.len());
        if buf.len().saturating_add(opt_len) > 40 {
            return Err(CompilerError::BackendError(
                "TCP options exceed the 40-byte RFC 9293 header options limit".to_string(),
            ));
        }
        buf.push(19); // Kind 19 (RFC 2385 TCP MD5 Signature)
        buf.push(opt_len as u8);
        buf.extend_from_slice(md5);
    }
    if let Some(tfo) = &opts.tfo {
        let opt_len = 2usize.saturating_add(tfo.len());
        if buf.len().saturating_add(opt_len) > 40 {
            return Err(CompilerError::BackendError(
                "TCP options exceed the 40-byte RFC 9293 header options limit".to_string(),
            ));
        }
        buf.push(34); // Kind 34 (RFC 7413 TCP Fast Open Cookie)
        buf.push(opt_len as u8);
        buf.extend_from_slice(tfo);
    }
    while buf.len() % 4 != 0 {
        buf.push(1); // Pad with NOP to 32-bit boundary
    }
    if buf.len() > 40 {
        return Err(CompilerError::BackendError(
            "TCP options exceed the 40-byte RFC 9293 header options limit".to_string(),
        ));
    }
    Ok(buf)
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
    build_tcp_segment_with_opts(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        flags,
        seq,
        ack_num,
        win,
        urgent,
        tcp_options,
        payload,
        false,
    )
}

/// Constructs a complete TCP segment with optional negative-testing checksum corruption.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_segment_with_opts(
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
    bad_checksum: bool,
) -> Result<Vec<u8>, CompilerError> {
    let opts_buf = match tcp_options {
        Some(opts) => encode_tcp_options(opts)?,
        None => Vec::new(),
    };
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

    let tcp_len_usize = tcp_header
        .len()
        .checked_add(payload.len())
        .filter(|&n| n <= u16::MAX as usize)
        .ok_or_else(|| {
            CompilerError::BackendError(alloc::format!(
                "TCP segment length ({} bytes) exceeds the 65,535-byte packet limit",
                tcp_header.len().saturating_add(payload.len())
            ))
        })?;
    let tcp_len = tcp_len_usize as u32;

    let mut checksum = match (src_ip, dst_ip) {
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
    if bad_checksum {
        checksum ^= 0x0001;
    }

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
    build_udp_datagram_with_opts(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
        &L4Modifiers::default(),
    )
}

/// Constructs a UDP datagram honoring `no_checksum` (`0x0000`) and `bad_checksum` negative toggles.
pub fn build_udp_datagram_with_opts(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    l4: &L4Modifiers,
) -> Result<Vec<u8>, CompilerError> {
    let udp_len_usize = 8usize
        .checked_add(payload.len())
        .filter(|&n| n <= u16::MAX as usize)
        .ok_or_else(|| {
            CompilerError::BackendError(alloc::format!(
                "UDP datagram length ({} bytes) exceeds the 65,535-byte RFC 768 header limit",
                8usize.saturating_add(payload.len())
            ))
        })?;
    let udp_len = udp_len_usize as u16;
    let mut udp_header = Vec::with_capacity(8);
    udp_header.extend_from_slice(&src_port.to_be_bytes());
    udp_header.extend_from_slice(&dst_port.to_be_bytes());
    udp_header.extend_from_slice(&udp_len.to_be_bytes());
    udp_header.push(0);
    udp_header.push(0);

    let udp_len_u32 = udp_len as u32;

    let checksum = if l4.no_checksum {
        match (src_ip, dst_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => 0_u16,
            _ => {
                return Err(CompilerError::BackendError(
                    "Source and Destination IP versions must match".to_string(),
                ));
            }
        }
    } else {
        let computed = match (src_ip, dst_ip) {
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
        if l4.bad_checksum {
            let flipped = computed ^ 0x0001;
            if flipped == 0 { computed ^ 0x0002 } else { flipped }
        } else {
            computed
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

/// Prepends Ethernet, 802.1Q, 802.1ad QinQ, RFC 3032 multi-label MPLS (with RFC 4448 EoMPLS for
/// pure-L2 payloads), and optional IEEE 802.3 CRC-32 FCS trailers around an inner packet.
///
/// Note: Minimum 60-byte Ethernet runt padding is intentionally NOT appended implicitly so exact
/// unpadded wire-length expectations in unit and reverse-roundtrip suites remain deterministic.
pub fn build_ethernet_and_l2(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    l2: &L2Modifiers,
    ip_ethertype: u16,
    inner_packet: &[u8],
) -> Vec<u8> {
    let mpls_labels: &[MplsSpec] = if !l2.mpls_stack.is_empty() {
        &l2.mpls_stack
    } else {
        l2.mpls.as_slice()
    };
    let fcs_len = if l2.fcs || l2.bad_fcs { 4 } else { 0 };
    let mut frame = Vec::with_capacity(
        14 + 8 + (mpls_labels.len() * 4) + 18 + inner_packet.len() + fcs_len,
    );
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);

    if let Some(qinq) = &l2.qinq {
        frame.extend_from_slice(&crate::builders::l2::qinq::encode_qinq_tags(
            qinq,
            l2.vlan.as_ref(),
        ));
    } else if let Some(vlan) = &l2.vlan {
        frame.extend_from_slice(&0x8100_u16.to_be_bytes());
        let pcp = vlan.pcp.unwrap_or(0) & 0x07;
        let dei = vlan.dei.unwrap_or(0) & 0x01;
        let tci: u16 = ((pcp as u16) << 13) | ((dei as u16) << 12) | (vlan.vid & 0x0FFF);
        frame.extend_from_slice(&tci.to_be_bytes());
    }

    if !mpls_labels.is_empty() {
        let mpls_et = l2.ethertype.unwrap_or(
            if matches!(ip_ethertype, 0x8847 | 0x8848) {
                ip_ethertype
            } else {
                0x8847
            },
        );
        frame.extend_from_slice(&mpls_et.to_be_bytes());
        for (idx, mpls) in mpls_labels.iter().enumerate() {
            let is_last = idx + 1 == mpls_labels.len();
            let exp = mpls.exp.unwrap_or(0) & 0x07;
            let bos = mpls.bos.unwrap_or(u8::from(is_last)) & 0x01;
            let ttl = mpls.ttl.unwrap_or(64);
            let mpls_entry: u32 = ((mpls.label & 0x000F_FFFF) << 12)
                | ((exp as u32) << 9)
                | ((bos as u32) << 8)
                | (ttl as u32);
            frame.extend_from_slice(&mpls_entry.to_be_bytes());
        }
        // RFC 4448 EoMPLS Ethernet encapsulation when carrying pure-L2 protocols over MPLS
        if !matches!(ip_ethertype, 0x0800 | 0x86DD | 0x8847 | 0x8848) {
            frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // PWE3 Control Word
            frame.extend_from_slice(&dst_mac);
            frame.extend_from_slice(&src_mac);
            frame.extend_from_slice(&ip_ethertype.to_be_bytes());
        }
    } else {
        let next_et = l2.ethertype.unwrap_or(ip_ethertype);
        frame.extend_from_slice(&next_et.to_be_bytes());
    }

    frame.extend_from_slice(inner_packet);

    if l2.fcs || l2.bad_fcs {
        let crc = ieee8023_crc32(&frame);
        let wire_crc = if l2.bad_fcs { crc ^ 0xFFFF_FFFF } else { crc };
        frame.extend_from_slice(&wire_crc.to_le_bytes());
    }

    frame
}

/// Builds an IEEE 802.3 Ethernet frame wrapping a 3-byte LLC header (`dsap`, `ssap`, `ctrl`)
/// and `llc_payload` using an IEEE 802.3 length field (`<= 1500`, falling back to `0x88B5`).
pub fn build_ieee8023_llc_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    l2: &L2Modifiers,
    dsap: u8,
    ssap: u8,
    ctrl: u8,
    llc_payload: &[u8],
) -> Vec<u8> {
    let mut llc_packet = Vec::with_capacity(3 + llc_payload.len());
    llc_packet.push(dsap);
    llc_packet.push(ssap);
    llc_packet.push(ctrl);
    llc_packet.extend_from_slice(llc_payload);
    let length_field = u16::try_from(llc_packet.len())
        .ok()
        .filter(|&n| n <= 1500)
        .unwrap_or(0x88B5);
    build_ethernet_and_l2(src_mac, dst_mac, l2, length_field, &llc_packet)
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

    let l4_proto_num = if is_tcp { 6_u8 } else { 17_u8 };
    let l4_segment = if l3.frag_offset.unwrap_or(0) > 0 {
        payload_bytes.to_vec()
    } else if is_tcp {
        build_tcp_segment_with_opts(
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
            l4.bad_checksum,
        )?
    } else {
        build_udp_datagram_with_opts(src_ip, dst_ip, src_port, dst_port, payload_bytes, l4)?
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_oversized_ipv4_ipv6_udp_packets_rejected() {
        let l3 = L3Modifiers::default();
        assert!(build_ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 17, &l3, 65520).is_err());
        assert!(build_ipv6_header([0; 16], [0; 16], 17, &l3, 65536).is_err());
        let big = alloc::vec![0u8; 65530];
        assert!(
            build_udp_datagram(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                1000,
                2000,
                &big,
            )
            .is_err()
        );
        assert!(
            build_udp_datagram(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                1000,
                2000,
                &big,
            )
            .is_err()
        );
    }

    #[test]
    fn test_ieee8023_crc32_and_fcs_trailer() {
        assert_eq!(ieee8023_crc32(b"123456789"), 0xCBF4_3926);
        let l2_good = L2Modifiers {
            fcs: true,
            ..L2Modifiers::default()
        };
        let l2_bad = L2Modifiers {
            bad_fcs: true,
            ..L2Modifiers::default()
        };
        let good = build_ethernet_and_l2([1; 6], [2; 6], &l2_good, 0x88B5, b"hi");
        let bad = build_ethernet_and_l2([1; 6], [2; 6], &l2_bad, 0x88B5, b"hi");
        assert_eq!(good.len(), 14 + 2 + 4);
        assert_eq!(bad.len(), 14 + 2 + 4);
        let good_crc = u32::from_le_bytes(good[16..20].try_into().unwrap());
        let bad_crc = u32::from_le_bytes(bad[16..20].try_into().unwrap());
        assert_eq!(good_crc ^ 0xFFFF_FFFF, bad_crc);
    }

    #[test]
    fn test_mpls_stack_eompls_and_ipv6_extensions() {
        let l2 = L2Modifiers {
            mpls_stack: alloc::vec![
                MplsSpec {
                    label: 100,
                    exp: Some(3),
                    bos: None,
                    ttl: Some(64),
                },
                MplsSpec {
                    label: 200,
                    exp: Some(1),
                    bos: None,
                    ttl: Some(32),
                },
            ],
            ..L2Modifiers::default()
        };
        let eompls = build_ieee8023_llc_frame([1; 6], [2; 6], &l2, 0x42, 0x42, 0x03, b"bpdu");
        assert_eq!(&eompls[12..14], &0x8847u16.to_be_bytes());
        assert_eq!((u32::from_be_bytes(eompls[14..18].try_into().unwrap()) >> 8) & 1, 0);
        assert_eq!((u32::from_be_bytes(eompls[18..22].try_into().unwrap()) >> 8) & 1, 1);
        assert_eq!(&eompls[22..26], &[0, 0, 0, 0]);

        let l3 = L3Modifiers {
            router_alert: true,
            ipid: Some(0x1234),
            frag_offset: Some(8),
            mf: true,
            bad_ip_checksum: true,
            ..L3Modifiers::default()
        };
        let v4 = build_ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 17, &l3, 4).unwrap();
        assert_eq!(v4[0], 0x46);
        assert_eq!(&v4[20..24], &[0x94, 0x04, 0x00, 0x00]);
        assert_ne!(internet_checksum(&[&v4]), 0);

        let v6 = build_ipv6_header([0; 16], [0; 16], 17, &l3, 4).unwrap();
        assert_eq!(v6[6], 0); // Hop-by-Hop next header
        assert_eq!(v6[40], 44); // Fragment next header
        assert_eq!(v6[48], 17); // Inner protocol UDP
    }

    #[test]
    fn test_compact_tcp_options_and_negative_udp() {
        let opts = TcpOptions {
            mss: Some(1460),
            wscale: Some(7),
            sack_perm: true,
            tsval: Some(100),
            tsecr: Some(50),
            sack_blocks: alloc::vec![(10, 20)],
            tcp_md5: None,
            tfo: Some(alloc::vec![1, 2, 3, 4]),
        };
        let encoded = encode_tcp_options(&opts).unwrap();
        assert_eq!(encoded.len() % 4, 0);
        assert!(encoded.len() <= 40);

        let compact_syn = TcpOptions {
            mss: Some(1460),
            wscale: Some(7),
            sack_perm: true,
            tsval: Some(100),
            tsecr: Some(0),
            ..TcpOptions::default()
        };
        assert_eq!(encode_tcp_options(&compact_syn).unwrap().len(), 20);

        let l4_nocsum = L4Modifiers {
            no_checksum: true,
            ..L4Modifiers::default()
        };
        let udp_zero = build_udp_datagram_with_opts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1000,
            53,
            b"abc",
            &l4_nocsum,
        )
        .unwrap();
        assert_eq!(&udp_zero[6..8], &[0, 0]);
    }
}
