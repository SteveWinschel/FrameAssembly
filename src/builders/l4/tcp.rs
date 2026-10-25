//! Transmission Control Protocol (TCP, RFC 9293 / RFC 7323) Layer 4 wire builder module.
//!
//! Documents the wire-level framing rules for RFC 9293 TCP segments over IPv4 (`0x0800`) and
//! IPv6 (`0x86DD`) using IP Protocol number `6`. The 20-byte base TCP header encodes 16-bit
//! `SRCPORT`, 16-bit `DSTPORT`, 32-bit `SEQ`, 32-bit `ACKNUM`, 4-bit Data Offset, 8-bit
//! Control Flags (`CWR`, `ECE`, `URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN`), 16-bit `WIN`,
//! 16-bit one's complement pseudo-header Checksum, and 16-bit `URGENT` pointer, followed by
//! 32-bit aligned TLV options (`MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`, `TSECR`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b TCP [SYN] [ACK] [FIN] [RST] [PSH] [URG] [ECE] [CWR] [SRCPORT <u16>] [DSTPORT <u16>] [SEQ <u32>] [ACKNUM <u32>] [WIN <u16>] [MSS <u16>] [WSCALE <u8>] [SACK_PERM] [TSVAL <u32>] [TSECR <u32>]`

use crate::ast::{TcpFlag, TcpOptions};
use alloc::vec::Vec;

/// Encodes a slice of [`TcpFlag`] variants into the 8-bit RFC 9293 TCP control flags byte.
pub fn encode_tcp_flags(flags: &[TcpFlag]) -> u8 {
    let mut byte = 0u8;
    for flag in flags {
        match flag {
            TcpFlag::Fin => byte |= 0x01,
            TcpFlag::Syn => byte |= 0x02,
            TcpFlag::Rst => byte |= 0x04,
            TcpFlag::Psh => byte |= 0x08,
            TcpFlag::Ack => byte |= 0x10,
            TcpFlag::Urg => byte |= 0x20,
            TcpFlag::Ece => byte |= 0x40,
            TcpFlag::Cwr => byte |= 0x80,
        }
    }
    byte
}

/// Encodes [`TcpOptions`] into 32-bit aligned RFC 9293 / RFC 7323 TCP option TLV bytes.
pub fn encode_tcp_options(opts: &TcpOptions) -> Vec<u8> {
    let mut tcp_opts = Vec::new();
    if let Some(mss) = opts.mss {
        tcp_opts.push(2); // Kind 2: MSS
        tcp_opts.push(4); // Length 4
        tcp_opts.extend_from_slice(&mss.to_be_bytes());
    }
    if let Some(ws) = opts.wscale {
        tcp_opts.push(1); // NOP for alignment
        tcp_opts.push(3); // Kind 3: Window Scale
        tcp_opts.push(3); // Length 3
        tcp_opts.push(ws);
    }
    if opts.sack_perm {
        tcp_opts.push(4); // Kind 4: SACK Permitted
        tcp_opts.push(2); // Length 2
    }
    if opts.tsval.is_some() || opts.tsecr.is_some() {
        let ts_val = opts.tsval.unwrap_or(0);
        let ts_ecr = opts.tsecr.unwrap_or(0);
        tcp_opts.push(8); // Kind 8: Timestamps
        tcp_opts.push(10); // Length 10
        tcp_opts.extend_from_slice(&ts_val.to_be_bytes());
        tcp_opts.extend_from_slice(&ts_ecr.to_be_bytes());
    }
    while !tcp_opts.len().is_multiple_of(4) {
        tcp_opts.push(0); // EOL padding
    }
    tcp_opts
}

