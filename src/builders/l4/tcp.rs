//! Transmission Control Protocol (TCP, RFC 9293 / RFC 7323) Layer 4 wire builder module.
//!
//! Documents the wire-level framing rules for RFC 9293 TCP segments over IPv4 (`0x0800`) and
//! IPv6 (`0x86DD`) using IP Protocol number `6`. The 20-byte base TCP header encodes 16-bit
//! `srcport`, 16-bit `dstport`, 32-bit `seq`, 32-bit `acknum`, 4-bit Data Offset, 8-bit
//! Control Flags (`cwr`, `ece`, `urg`, `ack`, `psh`, `rst`, `syn`, `fin`), 16-bit `win`,
//! 16-bit one's complement pseudo-header Checksum, and 16-bit `urgent` pointer, followed by
//! 32-bit aligned TLV options (`mss`, `wscale`, `sackperm`, `tsval`, `tsecr`, `sackblock`,
//! `tcpmd5`, `tfo`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b tcp [syn] [ack] [fin] [rst] [psh] [urg] [ece] [cwr] [srcport <u16>] [dstport <u16>] [seq <u32>] [acknum <u32>] [win <u16>] [mss <u16>] [wscale <u8>] [sackperm] [tsval <u32>] [tsecr <u32>]`

use crate::ast::TcpFlag;

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

