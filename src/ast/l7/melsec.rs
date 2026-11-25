//! Mitsubishi MELSEC MC Protocol / SLMP Binary 3E Frame Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`MelsecSpec`], the zero-copy AST representation of a Mitsubishi Electric
//! MELSEC MC Protocol (SLMP Binary 3E Frame) message over TCP port 5000 (default) or UDP port
//! 5000. On the wire, a 3E binary frame begins with a 9-byte little-endian encapsulation header
//! (`0x50 0x00` request or `0xD0 0x00` response subheader, `network`, `pc`, `io`, `station`, and
//! 16-bit data length) followed by monitoring `timer`, `cmd` (`0x0401` Batch Read, `0x1401` Batch
//! Write), `subcmd`, 24-bit device address `addr`, `device` type (`0xA8` D-register), `count`,
//! and register data or response `endcode`. Canonical `.frasm` syntax:
//! `melsec [read | write | cmd <str|u16>] [response | isresponse] [subcmd <u16>] [network <u8>] [pc <u8>] [io <u16>] [station <u8>] [timer <u16>] [device <str|u8>] [addr <u32>] [count <u16>] [value <u16>] [endcode <u16>]`.

/// Mitsubishi MELSEC MC Protocol / SLMP Binary 3E Frame specification.
///
/// Syntax mapping: `melsec [read | write | cmd <str|u16>] [response | isresponse] [subcmd <u16>] [network <u8>] [pc <u8>] [io <u16>] [station <u8>] [timer <u16>] [device <str|u8>] [addr <u32>] [count <u16>] [value <u16>] [endcode <u16>]`
#[doc(alias = "melsec")]
#[doc(alias = "SLMP")]
#[doc(alias = "MC Protocol")]
#[doc(alias = "5000")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "cmd")]
#[doc(alias = "subcmd")]
#[doc(alias = "network")]
#[doc(alias = "pc")]
#[doc(alias = "io")]
#[doc(alias = "station")]
#[doc(alias = "timer")]
#[doc(alias = "device")]
#[doc(alias = "addr")]
#[doc(alias = "count")]
#[doc(alias = "value")]
#[doc(alias = "endcode")]
#[doc(alias = "response")]
#[doc(alias = "isresponse")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MelsecSpec<'a> {
    /// SLMP/MC 3E command selector (`read`, `write`, or `cmd <str|u16>`, default `"read"` `0x0401`).
    pub cmd: Option<&'a str>,
    /// 16-bit subcommand selector (`subcmd <u16>`, `0` word units or `1` bit units, default `0`).
    pub subcmd: Option<u16>,
    /// 8-bit target network number (`network <u8>`, default `0`).
    pub network: Option<u8>,
    /// 8-bit target PC / station number (`pc <u8>`, default `0xFF`).
    pub pc: Option<u8>,
    /// 16-bit destination module I/O number (`io <u16>`, default `0x03FF`).
    pub io: Option<u16>,
    /// 8-bit destination module station number (`station <u8>`, default `0`).
    pub station: Option<u8>,
    /// 16-bit CPU monitoring timer in 250ms units (`timer <u16>`, default `0x0010`).
    pub timer: Option<u16>,
    /// 8-bit MELSEC device memory code (`device <str|u8>`, default `0xA8` for `D` register).
    pub device: Option<u8>,
    /// 24-bit head device address (`addr <u32>`, `0..=0xFFFFFF`, default `0`).
    pub addr: Option<u32>,
    /// Number of device words or bits (`count <u16>`, default `1`).
    pub count: Option<u16>,
    /// 16-bit register or byte fill value for writes and read responses (`value <u16>`, default `0`).
    pub value: Option<u16>,
    /// 16-bit 3E response End Code (`endcode <u16>`, `0` for normal completion).
    pub endcode: Option<u16>,
    /// Response frame flag (`response` or `isresponse`).
    pub is_response: bool,
}
