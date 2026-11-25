//! Manufacturing Message Specification (ISO 9506 / IEC 61850 MMS) AST definitions.
//!
//! This module defines [`MmsSpec`], the zero-copy AST representation of an ISO 9506 / IEC 61850
//! Manufacturing Message Specification (MMS) frame carried inside ISO-on-TCP (RFC 1006 TPKT,
//! port 102), ISO 8073 COTP DT, ISO 8327-1 Session (`CN`/`AC` or `GT`+`DT`), ISO 8823
//! Presentation (`CP`/`CPA` or `User-data`), optional ISO 8650-1 ACSE (`AARQ`/`AARE`), and ASN.1
//! BER MMS PDUs (`Initiate`, `GetNameList`, `Read`, `Write`, `InformationReport`, `Conclude`).
//! Canonical `.frasm` syntax:
//! `mms [init | initack | getnamelist | read | write | report | conclude | service <str>] [isresponse] [invokeid <u32>] [domain <str>] [item <str>] [value <u32>]`.

/// ISO 9506 / IEC 61850 Manufacturing Message Specification (MMS over ISO-on-TCP) specification.
///
/// Syntax mapping: `mms [init | initack | getnamelist | read | write | report | conclude | service <str>] [isresponse] [invokeid <u32>] [domain <str>] [item <str>] [value <u32>]`
#[doc(alias = "mms")]
#[doc(alias = "IEC 61850")]
#[doc(alias = "IEC61850")]
#[doc(alias = "ISO 9506")]
#[doc(alias = "ACSE")]
#[doc(alias = "102")]
#[doc(alias = "service")]
#[doc(alias = "init")]
#[doc(alias = "initack")]
#[doc(alias = "getnamelist")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "report")]
#[doc(alias = "conclude")]
#[doc(alias = "isresponse")]
#[doc(alias = "invokeid")]
#[doc(alias = "domain")]
#[doc(alias = "item")]
#[doc(alias = "value")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MmsSpec<'a> {
    /// MMS service selector (`service <str>`, e.g., `"initiate"`, `"getnamelist"`, `"read"`, `"write"`, `"report"`, `"conclude"`).
    pub service: Option<&'a str>,
    /// Response flag (`isresponse` / `response`) emitting `Initiate-ResponsePDU`, `Confirmed-ResponsePDU`, or `Conclude-ResponsePDU`.
    pub is_response: bool,
    /// 32-bit MMS Confirmed-PDU `invokeID` (`invokeid <u32>`, default `1`).
    pub invoke_id: Option<u32>,
    /// MMS domain identifier for domain-specific ObjectName addressing (`domain <str>`, default `"IED1"` when needed).
    pub domain: Option<&'a str>,
    /// MMS item identifier for VMD- or domain-specific variable addressing (`item <str>`, e.g., `"LLN0$ST$Mod"`).
    pub item: Option<&'a str>,
    /// Integer data value (`value <u32>`) encoded as MMS `Data ::= integer [5]` in `read` responses, `write` requests, and `report` PDUs.
    pub value: Option<u32>,
}
