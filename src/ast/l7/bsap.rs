//! Bristol Standard Asynchronous Protocol over IP (BSAP-IP) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`BsapSpec`], the zero-copy AST representation of an Emerson Bristol
//! ControlWave / OpenBSI BSAP-IP (`bsap`) telemetry frame over UDP or TCP port 1234. On the wire,
//! a Local BSAP message carries a 6-byte header (`SER` serial frame byte `0x01`, 8-bit `DADD`
//! destination address, 8-bit `SADD` source address, `CTL` control byte `0x00`/`0x40`, 8-bit
//! function code such as `0x01` Read Data Block, `0x02` Write Data Block, or `0x0C` Poll, and
//! 8-bit message sequence), while Global BSAP (`dst > 255` or `src > 255`) expands addresses to
//! 16-bit little-endian fields with a Node Status Byte. Canonical `.frasm` syntax:
//! `bsap [read | write | poll | func <str|u8>] [dst <u16>] [src <u16>] [seqnum <u8>] [addr <u16>] [count <u8>] [value <u32>] [isresponse]`.

/// Emerson Bristol Standard Asynchronous Protocol over IP (BSAP-IP) specification.
///
/// Syntax mapping: `bsap [read | write | poll | func <str|u8>] [dst <u16>] [src <u16>] [seqnum <u8>] [addr <u16>] [count <u8>] [value <u32>] [isresponse]`
#[doc(alias = "bsap")]
#[doc(alias = "BSAP-IP")]
#[doc(alias = "ControlWave")]
#[doc(alias = "OpenBSI")]
#[doc(alias = "1234")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "poll")]
#[doc(alias = "func")]
#[doc(alias = "dst")]
#[doc(alias = "src")]
#[doc(alias = "seqnum")]
#[doc(alias = "addr")]
#[doc(alias = "count")]
#[doc(alias = "value")]
#[doc(alias = "isresponse")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BsapSpec<'a> {
    /// Destination station or global RTU node address (`dst <u16>`, default `1`).
    pub dst: Option<u16>,
    /// Source host or RTU node address (`src <u16>`, default `2`).
    pub src: Option<u16>,
    /// BSAP function code name or numeric identifier (`func <str|u8>`, default `"read"` / `0x01`).
    pub func: Option<&'a str>,
    /// 8-bit BSAP transaction sequence number (`seqnum <u8>`, default `1`).
    pub seq_num: Option<u8>,
    /// 16-bit little-endian signal/register block address (`addr <u16>`, default `0`).
    pub addr: Option<u16>,
    /// 8-bit signal item count (`count <u8>`, default `1`).
    pub count: Option<u8>,
    /// 32-bit little-endian write or response data value (`value <u32>`).
    pub value: Option<u32>,
    /// Response control bit flag (`isresponse`, sets `CTL` `0x40` bit).
    pub is_response: bool,
}
