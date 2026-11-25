//! NetBIOS Name Service (`nbns`, RFC 1001 / RFC 1002) Layer 7 AST definitions.
//!
//! This module defines the zero-copy Abstract Syntax Tree (AST) configuration parameters for
//! synthesizing RFC 1001 and RFC 1002 NetBIOS Name Service (`nbns`) packets over UDP port 137. On
//! the wire, NBNS carries a 12-byte header (`NAME_TRN_ID`, `R`/`OPCODE`/`NM_FLAGS`/`RCODE`,
//! `QDCOUNT`, `ANCOUNT`, `NSCOUNT`, `ARCOUNT`), 32-byte first-level encoded NetBIOS names with
//! 1-byte suffix type (`0x00` Workstation, `0x20` File Server, `0x1C` Domain Controller), optional
//! NetBIOS scope labels, and `NB` (`0x0020`) or `NBSTAT` (`0x0021`) resource records. Canonical
//! `.frasm` syntax:
//! `a -> b nbns [query | register | release | refresh] [response] [opcode <str>] [txid <u16>] [qname <str>] [nbtype <u8>] [qtype <str>] [scope <str>] [rdata <str>] [rcode <u8>] [ansttl <u32>] [flags <u16>] [group]`.

/// RFC 1001 / RFC 1002 NetBIOS Name Service (`nbns`) Layer 7 protocol specification.
///
/// Syntax mapping: `nbns [query | register | release | refresh] [response] [opcode <str>] [txid <u16>] [qname <str>] [nbtype <u8>] [qtype <str>] [scope <str>] [rdata <str>] [rcode <u8>] [ansttl <u32>] [flags <u16>] [group]`
#[doc(alias = "nbns")]
#[doc(alias = "NetBIOS")]
#[doc(alias = "RFC 1001")]
#[doc(alias = "RFC 1002")]
#[doc(alias = "query")]
#[doc(alias = "register")]
#[doc(alias = "release")]
#[doc(alias = "refresh")]
#[doc(alias = "response")]
#[doc(alias = "opcode")]
#[doc(alias = "txid")]
#[doc(alias = "qname")]
#[doc(alias = "nbtype")]
#[doc(alias = "qtype")]
#[doc(alias = "scope")]
#[doc(alias = "rdata")]
#[doc(alias = "rcode")]
#[doc(alias = "ansttl")]
#[doc(alias = "flags")]
#[doc(alias = "group")]
#[doc(alias = "137")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NbnsSpec<'a> {
    /// NBNS operation (`query`, `register`, `release`, `refresh`, or `opcode <str>`).
    pub opcode: Option<&'a str>,
    /// NBNS response bit (`response`, sets `R = 1`).
    pub is_response: bool,
    /// 16-bit Transaction ID (`txid <u16>`, default `0x1337`).
    pub txid: Option<u16>,
    /// NetBIOS name (`qname <str>`, up to 15 ASCII chars or `"*"` for `NBSTAT`, default `"WORKSTATION"`).
    pub qname: Option<&'a str>,
    /// 1-byte NetBIOS name suffix type (`nbtype <u8>`, e.g., `0x00`, `0x20`, `0x1c`, default `0x00`).
    pub nb_type: Option<u8>,
    /// Question / RR type (`qtype <str>`, `"nb"` `0x0020` or `"nbstat"` `0x0021`, default `"nb"`).
    pub qtype: Option<&'a str>,
    /// Optional NetBIOS scope identifier (`scope <str>`).
    pub scope: Option<&'a str>,
    /// IPv4 address for `NB` Resource Records in responses, registrations, or refreshes (`rdata <str>`).
    pub rdata: Option<&'a str>,
    /// 4-bit NBNS response code (`rcode <u8>`, default `0`).
    pub rcode: Option<u8>,
    /// Resource record TTL in seconds (`ansttl <u32>`, default `300`).
    pub ans_ttl: Option<u32>,
    /// Explicit 16-bit NBNS header flags override (`flags <u16>`).
    pub flags: Option<u16>,
    /// Group name flag (`group`, sets `NB_FLAGS` `0x8000` in `NB` RDATA).
    pub is_group: bool,
}
