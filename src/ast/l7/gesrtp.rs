//! GE Fanuc Service Request Transport Protocol (GE-SRTP) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`GesrtpSpec`], the zero-copy AST representation of a GE Fanuc Series 90
//! and PACSystems RX3i/RX7i Service Request Transport Protocol (`gesrtp`) frame over TCP port
//! 18245. On the wire, every GE-SRTP packet carries a fixed 56-byte little-endian header encoding
//! the packet type (`0x00` Init, `0x01` InitAck, `0x02` Request, `0x03` Response), 16-bit sequence
//! number, trailing text payload length, mailbox type (`0xC0`/`0xD4`/`0x94`), service request code
//! (`0x04` Read System Memory, `0x07` Write System Memory), memory segment selector (`%R`, `%AI`,
//! `%AQ`, `%I`, `%Q`, `%M`, `%T`, `%G`), starting address, element count, and inline value or
//! response status. Canonical `.frasm` syntax:
//! `gesrtp [init | initack | request | response | read | write | type <str>] [seqnum <u16>] [func <str|u8>] [area <str|u8>] [addr <u16>] [count <u16>] [value <u32>] [status <u16>]`.

/// GE Fanuc Series 90 / PACSystems Service Request Transport Protocol (GE-SRTP) specification.
///
/// Syntax mapping: `gesrtp [init | initack | request | response | read | write | type <str>] [seqnum <u16>] [func <str|u8>] [area <str|u8>] [addr <u16>] [count <u16>] [value <u32>] [status <u16>]`
#[doc(alias = "gesrtp")]
#[doc(alias = "GE-SRTP")]
#[doc(alias = "SRTP")]
#[doc(alias = "PACSystems")]
#[doc(alias = "18245")]
#[doc(alias = "init")]
#[doc(alias = "initack")]
#[doc(alias = "request")]
#[doc(alias = "response")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "seqnum")]
#[doc(alias = "func")]
#[doc(alias = "area")]
#[doc(alias = "addr")]
#[doc(alias = "count")]
#[doc(alias = "value")]
#[doc(alias = "status")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GesrtpSpec<'a> {
    /// SRTP packet type (`type <str>`, e.g., `"init"`, `"initack"`, `"request"`, `"response"`, default `"request"`).
    pub ptype: Option<&'a str>,
    /// 16-bit little-endian sequence/invoke identifier (`seqnum <u16>`, default `1` on requests/responses, `0` on init).
    pub seq_num: Option<u16>,
    /// 8-bit SRTP service request code or name (`func <str|u8>`, default `"readsysmem"` / `0x04`).
    pub func: Option<&'a str>,
    /// 8-bit PLC memory segment selector (`area <str|u8>`, default `0x08` for `%R` registers).
    pub area: Option<u8>,
    /// 16-bit little-endian starting memory address (`addr <u16>`, default `0`).
    pub addr: Option<u16>,
    /// 16-bit little-endian register/bit element count (`count <u16>`, default `1`).
    pub count: Option<u16>,
    /// 32-bit little-endian inline write or response value (`value <u32>`).
    pub value: Option<u32>,
    /// 16-bit little-endian response status code (`status <u16>`, default `0`).
    pub status: Option<u16>,
}
