//! Diagnostics over Internet Protocol (DoIP, ISO 13400-2) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`DoipSpec`], the zero-copy AST representation of an ISO 13400-2
//! automotive Diagnostics over IP (`doip`) packet over TCP port 13400 (default) or UDP port
//! 13400. On the wire, every DoIP packet starts with an 8-byte big-endian generic header
//! (`version`, `invversion`, 16-bit `msgtype` payload type, and 32-bit payload length) covering
//! Vehicle Identification (`0x0001..=0x0004`), Routing Activation (`0x0005..=0x0006`), Alive
//! Check (`0x0007..=0x0008`), Generic NACK (`0x0000`), and UDS Diagnostic Messages and ACKs
//! (`0x8001..=0x8003`). Canonical `.frasm` syntax:
//! `doip [routingreq | routingresp | diagnostic | diagack | diagnack | vehicleid | vehicleeid | vehiclevin | announcement | alivecheckreq | alivecheckresp | nack | msgtype <str|u16>] [version <u8>] [invversion <u8>] [src <u16>] [dst <u16>] [code <u8>] [vin <str>] [eid <mac|hex>] [gid <mac|hex>]`.

/// ISO 13400-2 Diagnostics over Internet Protocol (DoIP) specification.
///
/// Syntax mapping: `doip [routingreq | routingresp | diagnostic | diagack | diagnack | vehicleid | vehicleeid | vehiclevin | announcement | alivecheckreq | alivecheckresp | nack | msgtype <str|u16>] [version <u8>] [invversion <u8>] [src <u16>] [dst <u16>] [code <u8>] [vin <str>] [eid <mac|hex>] [gid <mac|hex>]`
#[doc(alias = "doip")]
#[doc(alias = "ISO 13400")]
#[doc(alias = "ISO13400")]
#[doc(alias = "UDS")]
#[doc(alias = "13400")]
#[doc(alias = "routingreq")]
#[doc(alias = "routingresp")]
#[doc(alias = "diagnostic")]
#[doc(alias = "diagack")]
#[doc(alias = "diagnack")]
#[doc(alias = "vehicleid")]
#[doc(alias = "announcement")]
#[doc(alias = "version")]
#[doc(alias = "invversion")]
#[doc(alias = "msgtype")]
#[doc(alias = "src")]
#[doc(alias = "dst")]
#[doc(alias = "code")]
#[doc(alias = "vin")]
#[doc(alias = "eid")]
#[doc(alias = "gid")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DoipSpec<'a> {
    /// ISO 13400 protocol version byte (`version <u8>`, default `0x02`).
    pub version: Option<u8>,
    /// Bitwise inverse protocol version byte (`invversion <u8>`, default `!version`).
    pub inv_version: Option<u8>,
    /// DoIP payload type selector (`routingreq`, `routingresp`, `diagnostic`, `diagack`, `diagnack`, `vehicleid`, `vehicleeid`, `vehiclevin`, `announcement`, `alivecheckreq`, `alivecheckresp`, `nack`, or `msgtype <str|u16>`).
    pub msg_type: Option<&'a str>,
    /// 16-bit logical source/tester/entity address (`src <u16>`, default `0x0E00` or `0x00E0`).
    pub src: Option<u16>,
    /// 16-bit logical target/ECU address (`dst <u16>`, default `0x00E0` or `0x0E00`).
    pub dst: Option<u16>,
    /// 8-bit activation type, routing response code, diagnostic ACK/NACK code, further action, or generic NACK code (`code <u8>`).
    pub code: Option<u8>,
    /// 17-character ASCII Vehicle Identification Number (`vin <str>`, default `"WBA00000000000001"`).
    pub vin: Option<&'a str>,
    /// 6-byte DoIP Entity Identification (`eid <mac|hex>`, default `02:00:00:00:00:01`).
    pub eid: Option<[u8; 6]>,
    /// 6-byte DoIP Group Identification (`gid <mac|hex>`, default `00:00:00:00:00:00`).
    pub gid: Option<[u8; 6]>,
}
