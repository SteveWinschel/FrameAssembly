//! Transmission Control Protocol (TCP, RFC 9293 / RFC 7323) Layer 4 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 9293 Transmission
//! Control Protocol (`TCP`, IP protocol `6`) headers and RFC 7323 TCP header options in
//! FrameAssembly. It extracts source and destination ports (`srcport`, `dstport`), 32-bit sequence
//! and acknowledgment numbers (`seq`, `acknum`), control flags (`syn`, `ack`, `fin`, `rst`, `psh`,
//! `urg`, `ece`, `cwr`), receive window (`win`), urgent pointer (`urgent`), and TCP options (`mss`,
//! `wscale`, `sack_perm`, `tsval`, `tsecr`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{L4Modifiers, Protocol, TcpFlag, TcpOptions};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, sd};

/// Slices a 20+ byte TCP header from `ip_body`, populating `l4`, `seq`, `ack_num`, `win`, and
/// `l4_payload`, and returning `Some((src_port, dst_port))` when at least 20 bytes are present.
pub(crate) fn dissect_tcp_header(
    ip_body: &[u8],
    l4: &mut L4Modifiers,
    seq: &mut Option<u32>,
    ack_num: &mut Option<u32>,
    win: &mut Option<u16>,
    l4_payload: &mut Vec<u8>,
) -> Option<(u16, u16)> {
    if ip_body.len() < 20 {
        return None;
    }
    let (sp, dp) = (be_u16(ip_body, 0), be_u16(ip_body, 2));
    let doff = (((ip_body[12] >> 4) as usize) * 4).clamp(20, ip_body.len());
    let (fb, urg) = (ip_body[13], be_u16(ip_body, 18));
    let flags = [
        (0x02, TcpFlag::Syn),
        (0x01, TcpFlag::Fin),
        (0x04, TcpFlag::Rst),
        (0x08, TcpFlag::Psh),
        (0x10, TcpFlag::Ack),
        (0x20, TcpFlag::Urg),
        (0x40, TcpFlag::Ece),
        (0x80, TcpFlag::Cwr),
    ];
    l4.tcp_flags = flags
        .into_iter()
        .filter_map(|(m, f)| ((fb & m) != 0).then_some(f))
        .collect();

    let ap = &ip_body[doff..];
    *l4_payload = ap.to_vec();
    *seq = Some(be_u32(ip_body, 4));
    *ack_num = Some(be_u32(ip_body, 8));
    *win = Some(be_u16(ip_body, 14));
    l4.src_port = Some(sp);
    l4.dst_port = Some(dp);
    l4.urgent = (urg != 0).then_some(urg);
    l4.tcp_options = parse_tcp_options(&ip_body[20..doff]);
    Some((sp, dp))
}

/// Parses RFC 793 / RFC 7323 TCP header options (`MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`/`TSECR`).
pub(crate) fn parse_tcp_options(opts: &[u8]) -> Option<TcpOptions> {
    let (mut p, mut any, mut i) = (TcpOptions::default(), false, 0usize);
    while i < opts.len() {
        match opts[i] {
            0 => break,
            1 => i += 1,
            2 if i + 4 <= opts.len() && opts[i + 1] == 4 => {
                (p.mss, any, i) = (Some(be_u16(opts, i + 2)), true, i + 4);
            }
            3 if i + 3 <= opts.len() && opts[i + 1] == 3 => {
                (p.wscale, any, i) = (Some(opts[i + 2]), true, i + 3);
            }
            4 if i + 2 <= opts.len() && opts[i + 1] == 2 => {
                (p.sack_perm, any, i) = (true, true, i + 2);
            }
            8 if i + 10 <= opts.len() && opts[i + 1] == 10 => {
                (p.tsval, p.tsecr, any, i) = (
                    Some(be_u32(opts, i + 2)),
                    Some(be_u32(opts, i + 6)),
                    true,
                    i + 10,
                );
            }
            _ if i + 2 <= opts.len() => i = i.saturating_add((opts[i + 1] as usize).max(2)),
            _ => break,
        }
    }
    any.then_some(p)
}

/// Constructs a raw `tcp` [`ProtocolDissection`] preserving `payload` as residual payload bytes.
pub(crate) fn dissect_tcp(payload: &[u8]) -> ProtocolDissection {
    sd(Protocol::Tcp, String::from("tcp"), payload.to_vec())
}
