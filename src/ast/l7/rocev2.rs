//! RDMA over Converged Ethernet v2 (RoCEv2, IBTA Annex A17) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`Rocev2Spec`], the zero-copy AST representation of an IBTA Annex A17
//! RoCEv2 (`rocev2`) transport frame encapsulated over UDP port 4791. On the wire, every RoCEv2
//! packet carries a 12-byte InfiniBand Base Transport Header (`BTH` containing 8-bit Opcode,
//! PadCount, 16-bit Partition Key `P_Key`, 24-bit Destination Queue Pair `DestQP`, Acknowledge
//! Request bit `A`, and 24-bit Packet Sequence Number `PSN`), optional extended headers (`RETH`,
//! `AETH`, `ImmDt`, `DETH`), 4-byte padded RDMA payload, and a 4-byte Invariant CRC (`ICRC`).
//! Canonical `.frasm` syntax:
//! `rocev2 [read | write | opcode <str|u8>] [pkey <u16>] [destqp <u32>] [ackreq] [seqnum <u32>] [addr <u64>] [key <u32>] [count <u32>] [status <u8>] [msgid <u32>] [crc <u32>]`.

/// IBTA Annex A17 RDMA over Converged Ethernet v2 (RoCEv2) protocol specification.
///
/// Syntax mapping: `rocev2 [read | write | opcode <str|u8>] [pkey <u16>] [destqp <u32>] [ackreq] [seqnum <u32>] [addr <u64>] [key <u32>] [count <u32>] [status <u8>] [msgid <u32>] [crc <u32>]`
#[doc(alias = "rocev2")]
#[doc(alias = "RoCEv2")]
#[doc(alias = "RRoCE")]
#[doc(alias = "InfiniBand")]
#[doc(alias = "RDMA")]
#[doc(alias = "4791")]
#[doc(alias = "opcode")]
#[doc(alias = "pkey")]
#[doc(alias = "destqp")]
#[doc(alias = "ackreq")]
#[doc(alias = "seqnum")]
#[doc(alias = "addr")]
#[doc(alias = "key")]
#[doc(alias = "count")]
#[doc(alias = "status")]
#[doc(alias = "msgid")]
#[doc(alias = "crc")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rocev2Spec<'a> {
    /// BTH InfiniBand opcode name or 8-bit code (`opcode <str|u8>`, default `"rdmawrite"` / `0x0A`).
    pub opcode: Option<&'a str>,
    /// 16-bit BTH Partition Key (`pkey <u16>`, default `0xFFFF`).
    pub pkey: Option<u16>,
    /// 24-bit BTH Destination Queue Pair (`destqp <u32>`, default `2`).
    pub dest_qp: Option<u32>,
    /// BTH Acknowledge Request bit (`ackreq`, default `false`).
    pub ack_req: bool,
    /// 24-bit BTH Packet Sequence Number (`seqnum <u32>`, default `1`).
    pub psn: Option<u32>,
    /// 64-bit RETH Virtual Address (`addr <u64>`, default `0x1000`).
    pub va: Option<u64>,
    /// 32-bit RETH Remote Key (`key <u32>`, default `0x1234`).
    pub rkey: Option<u32>,
    /// 32-bit RETH DMA Transfer Length (`count <u32>`, default `4` on writes / `64` on reads).
    pub dma_len: Option<u32>,
    /// 8-bit AETH Syndrome byte (`status <u8>`, default `0` = ACK).
    pub syndrome: Option<u8>,
    /// 24-bit AETH Message Sequence Number (`msgid <u32>`, default `1`).
    pub msn: Option<u32>,
    /// Optional 32-bit Invariant CRC trailer override for negative testing (`crc <u32>`).
    pub icrc: Option<u32>,
}
