//! KNXnet/IP Building Automation Protocol (ISO/IEC 14543-3 / EN 50090) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`KnxnetipSpec`], the zero-copy AST representation of an ISO/IEC 14543-3
//! KNXnet/IP (`knxnetip`) frame over UDP port 3671. On the wire, every KNXnet/IP packet begins with
//! a 6-byte header (`0x06` header length, `0x10` version 1.0, 16-bit Service Type Identifier, and
//! 16-bit big-endian Total Length), carrying discovery/management bodies (`SearchRequest`
//! `0x0201`, `ConnectRequest` `0x0205`, `ConnectResponse` `0x0206`, `TunnelingRequest` `0x0420`,
//! `TunnelingAck` `0x0421`, `RoutingIndication` `0x0530`) and Common External Message Interface
//! (`cEMI`) group value frames. Canonical `.frasm` syntax:
//! `knxnetip [connect | connack | disconnect | service <str|u16>] [channel <u8>] [seqnum <u8>] [status <u8>] [src <u16>] [dst <u16>] [read | write] [value <u32>]`.

/// ISO/IEC 14543-3 / EN 50090 KNXnet/IP building automation protocol specification.
///
/// Syntax mapping: `knxnetip [connect | connack | disconnect | service <str|u16>] [channel <u8>] [seqnum <u8>] [status <u8>] [src <u16>] [dst <u16>] [read | write] [value <u32>]`
#[doc(alias = "knxnetip")]
#[doc(alias = "KNX")]
#[doc(alias = "KNXnet/IP")]
#[doc(alias = "cEMI")]
#[doc(alias = "ISO 14543")]
#[doc(alias = "3671")]
#[doc(alias = "service")]
#[doc(alias = "connect")]
#[doc(alias = "connack")]
#[doc(alias = "disconnect")]
#[doc(alias = "channel")]
#[doc(alias = "seqnum")]
#[doc(alias = "status")]
#[doc(alias = "src")]
#[doc(alias = "dst")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "value")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KnxnetipSpec<'a> {
    /// KNXnet/IP service type name or 16-bit code (`service <str|u16>`, default `"tunnelreq"` / `0x0420`).
    pub service: Option<&'a str>,
    /// 8-bit Communication Channel ID (`channel <u8>`, default `1`).
    pub channel: Option<u8>,
    /// 8-bit Tunneling Sequence Counter (`seqnum <u8>`, default `0`).
    pub seq_num: Option<u8>,
    /// 8-bit Response or Tunneling Ack status code (`status <u8>`, default `0` = `E_NO_ERROR`).
    pub status: Option<u8>,
    /// 16-bit cEMI KNX individual source address (`src <u16>`, default `0x1101` = `1.1.1`).
    pub src: Option<u16>,
    /// 16-bit cEMI KNX group destination address (`dst <u16>`, default `0x0801` = `1/0/1`).
    pub dst: Option<u16>,
    /// cEMI APCI GroupValueRead (`true` via `read`) vs GroupValueWrite (`false` via `write`, default).
    pub is_read: bool,
    /// GroupValueWrite payload value (`value <u32>`, 6-bit inline `0..=63` or multi-byte APCI data, default `1`).
    pub value: Option<u32>,
}
