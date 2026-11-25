//! Omron Factory Interface Network Service (FINS) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`FinsSpec`], the zero-copy AST representation of an Omron FINS
//! industrial PLC automation message over UDP port 9600 (default) or FINS/TCP over TCP port
//! 9600. On the wire, a FINS packet begins with a 10-byte FINS header (`icf`, reserved `0x00`,
//! gateway count `0x02`, destination `dna`/`da1`/`da2`, source `sna`/`sa1`/`sa2`, and Service ID
//! `sid`) followed by a 2-byte command code (`0x0101` Memory Area Read, `0x0102` Memory Area
//! Write, `0x0501` Controller Data Read) and optional `mres`/`sres` response status codes.
//! Canonical `.frasm` syntax:
//! `fins [read | write | cmd <str|u16>] [response | isresponse] [icf <u8>] [dna <u8>] [da1 <u8>] [da2 <u8>] [sna <u8>] [sa1 <u8>] [sa2 <u8>] [sid <u8>] [area <str|u8>] [addr <u16>] [count <u16>] [value <u16>] [errcode <u16>]`.

/// Omron Factory Interface Network Service (FINS) industrial protocol specification.
///
/// Syntax mapping: `fins [read | write | cmd <str|u16>] [response | isresponse] [icf <u8>] [dna <u8>] [da1 <u8>] [da2 <u8>] [sna <u8>] [sa1 <u8>] [sa2 <u8>] [sid <u8>] [area <str|u8>] [addr <u16>] [count <u16>] [value <u16>] [errcode <u16>]`
#[doc(alias = "fins")]
#[doc(alias = "Omron FINS")]
#[doc(alias = "9600")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "cmd")]
#[doc(alias = "icf")]
#[doc(alias = "dna")]
#[doc(alias = "da1")]
#[doc(alias = "da2")]
#[doc(alias = "sna")]
#[doc(alias = "sa1")]
#[doc(alias = "sa2")]
#[doc(alias = "sid")]
#[doc(alias = "area")]
#[doc(alias = "addr")]
#[doc(alias = "count")]
#[doc(alias = "value")]
#[doc(alias = "errcode")]
#[doc(alias = "response")]
#[doc(alias = "isresponse")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FinsSpec<'a> {
    /// FINS MRC/SRC command selector (`read`, `write`, or `cmd <str|u16>`, default `"read"` `0x0101`).
    pub cmd: Option<&'a str>,
    /// Information Control Field byte (`icf <u8>`, default `0x80` request or `0xC0` response).
    pub icf: Option<u8>,
    /// Destination Network Address (`dna <u8>`, default `0`).
    pub dna: Option<u8>,
    /// Destination Node Address (`da1 <u8>`, default `0`).
    pub da1: Option<u8>,
    /// Destination Unit Address (`da2 <u8>`, default `0` CPU unit).
    pub da2: Option<u8>,
    /// Source Network Address (`sna <u8>`, default `0`).
    pub sna: Option<u8>,
    /// Source Node Address (`sa1 <u8>`, default `0`).
    pub sa1: Option<u8>,
    /// Source Unit Address (`sa2 <u8>`, default `0` CPU unit).
    pub sa2: Option<u8>,
    /// Service ID transaction identifier (`sid <u8>`, default `1`).
    pub sid: Option<u8>,
    /// FINS PLC memory area code (`area <str|u8>`, default `0x82` DM Word).
    pub area: Option<u8>,
    /// Beginning 16-bit word or bit address (`addr <u16>`, default `0`).
    pub addr: Option<u16>,
    /// Number of memory words or bits to read or write (`count <u16>`, default `1`).
    pub count: Option<u16>,
    /// 16-bit word or byte value for memory writes and read responses (`value <u16>`, default `0`).
    pub value: Option<u16>,
    /// 16-bit FINS response status code (`errcode <u16>`, MRES/SRES, default `0x0000`).
    pub errcode: Option<u16>,
    /// Response frame flag (`response` or `isresponse`).
    pub is_response: bool,
}
