//! Emerson ROC Plus (ROC+) SCADA Remote Terminal Unit (RTU) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`RocplusSpec`], the zero-copy AST representation of an Emerson Bristol
//! ROC800 / FloBoss 107 ROC Plus (`rocplus`) protocol message over TCP or UDP port 4000. On the
//! wire, a ROC+ frame consists of a 6-byte routing and opcode header (Destination Unit Address,
//! Destination Group, Source Unit Address, Source Group, 8-bit Opcode such as `180` Read Multiple
//! TLP Parameters, `181` Write Multiple TLP Parameters, `17` Read System Configuration, `7` Login,
//! or `255` Error, and Data Length byte), followed by Type-Logical-Parameter (TLP) payload octets
//! and a 16-bit little-endian CRC-16 trailer. Canonical `.frasm` syntax:
//! `rocplus [read | write | error | opcode <str|u8> | func <str|u8>] [dst <u8>] [group <u8>] [src <u8>] [type <u8>] [addr <u8>] [param <u8>] [value <u32>] [isresponse] [crc <u16>]`.

/// Emerson ROC Plus (ROC+) SCADA RTU communication specification.
///
/// Syntax mapping: `rocplus [read | write | error | opcode <str|u8> | func <str|u8>] [dst <u8>] [group <u8>] [src <u8>] [type <u8>] [addr <u8>] [param <u8>] [value <u32>] [isresponse] [crc <u16>]`
#[doc(alias = "rocplus")]
#[doc(alias = "ROC+")]
#[doc(alias = "ROC800")]
#[doc(alias = "FloBoss")]
#[doc(alias = "4000")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "error")]
#[doc(alias = "opcode")]
#[doc(alias = "func")]
#[doc(alias = "dst")]
#[doc(alias = "group")]
#[doc(alias = "src")]
#[doc(alias = "type")]
#[doc(alias = "addr")]
#[doc(alias = "param")]
#[doc(alias = "value")]
#[doc(alias = "isresponse")]
#[doc(alias = "crc")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RocplusSpec<'a> {
    /// 8-bit destination RTU unit address (`dst <u8>`, default `1`).
    pub dst: Option<u8>,
    /// 8-bit destination RTU group identifier (`group <u8>`, default `2`).
    pub group: Option<u8>,
    /// 8-bit source host/RTU unit address (`src <u8>`, default `3`).
    pub src: Option<u8>,
    /// ROC+ command opcode name or numeric code (`opcode <str|u8>`, default `"read"` / `180`).
    pub opcode: Option<&'a str>,
    /// TLP Point Type byte (`type <u8>`, default `7` for Analog Input).
    pub point_type: Option<u8>,
    /// TLP Logical / Point Number byte (`addr <u8>`, default `0`).
    pub addr: Option<u8>,
    /// TLP Parameter Number byte (`param <u8>`, default `14` for Engineering Units Value).
    pub param: Option<u8>,
    /// 32-bit little-endian parameter value for write requests or read responses (`value <u32>`).
    pub value: Option<u32>,
    /// Response framing indicator flag (`isresponse`).
    pub is_response: bool,
    /// Optional 16-bit little-endian CRC-16 trailer override (`crc <u16>`).
    pub crc: Option<u16>,
}
