//! Distributed Network Protocol v3 (DNP3, IEEE 1815-2012) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`Dnp3Spec`], the zero-copy AST representation of an IEEE 1815-2012
//! Distributed Network Protocol (DNP3) SCADA frame over TCP or UDP port 20000. On the wire, a
//! DNP3 frame begins with a 10-byte Data Link Layer header (`0x0564` start bytes, length, control
//! byte, 16-bit little-endian destination and source addresses, and 16-bit DNP3 CRC), followed by
//! a 1-byte Transport Header (`0xC0`), an Application Layer header (Application Control + Function
//! Code), and Object Header group/variation descriptors with trailing 16-bit data chunk CRCs.
//! Canonical `.fasm` syntax:
//! `DNP3 [FUNC <str>] [SRC <u16>] [DST <u16>] [GROUP <u8>] [VARIATION <u8>] [CRC <u16>]`.

/// IEEE 1815-2012 Distributed Network Protocol v3 (DNP3) specification.
///
/// Syntax mapping: `DNP3 [FUNC <str>] [SRC <u16>] [DST <u16>] [GROUP <u8>] [VARIATION <u8>] [CRC <u16>]`
#[doc(alias = "DNP3")]
#[doc(alias = "IEEE 1815")]
#[doc(alias = "IEEE1815")]
#[doc(alias = "20000")]
#[doc(alias = "FUNC")]
#[doc(alias = "SRC")]
#[doc(alias = "DST")]
#[doc(alias = "GROUP")]
#[doc(alias = "VARIATION")]
#[doc(alias = "CRC")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dnp3Spec<'a> {
    /// Application layer function name (`FUNC <str>`, e.g., `"READ"`, `"WRITE"`, `"SELECT"`, `"OPERATE"`, `"DIRECT_OPERATE"`, `"RESPONSE"`, `"UNSOLICITED_RESPONSE"`, `"CONFIRM"`).
    pub func: Option<&'a str>,
    /// 16-bit Data Link source address (`SRC <u16>`, default `1`).
    pub src: Option<u16>,
    /// 16-bit Data Link destination address (`DST <u16>`, default `10`).
    pub dst: Option<u16>,
    /// DNP3 Object Group number (`GROUP <u8>`, default `60` for Class Data).
    pub group: Option<u8>,
    /// DNP3 Object Variation number (`VARIATION <u8>`, default `1`).
    pub variation: Option<u8>,
    /// Optional 16-bit Data Link header CRC override (`CRC <u16>`).
    pub crc: Option<u16>,
}
