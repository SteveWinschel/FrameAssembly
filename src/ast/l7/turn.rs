//! Traversal Using Relays around NAT (TURN, RFC 8656 / RFC 5766) Layer 7 AST definitions.
//!
//! This module defines [`TurnSpec`], the zero-copy Abstract Syntax Tree (AST) specification for
//! synthesizing Traversal Using Relays around NAT (TURN) control messages and ChannelData relays
//! over UDP and TCP port 3478. On the wire, TURN uses either STUN-formatted 20-byte messages
//! (`Allocate` `0x0003`/`0x0103`/`0x0113`, `Refresh` `0x0004`/`0x0104`/`0x0114`, `Send`
//! `0x0016`, `Data` `0x0017`, `CreatePermission` `0x0008`, `ChannelBind` `0x0009`) with Magic
//! Cookie `0x2112A442` and 4-byte-aligned TLV attributes (`REQUESTED-TRANSPORT`, `LIFETIME`,
//! `CHANNEL-NUMBER`, `XOR-RELAYED-ADDRESS`, `XOR-PEER-ADDRESS`, `XOR-MAPPED-ADDRESS`,
//! `ERROR-CODE`, `SOFTWARE`), or compact 4-byte `ChannelData` headers (`0x4000..=0x7FFF`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b turn [allocate | refresh | createpermission | channelbind | channeldata | sendindication | dataindication | msgtype <str>] [request | response | error] [txid <u32>] [channel <u16>] [lifetime <u32>] [requestedtransport <udp|tcp|u8>] [xormappedaddr <ip> [<u16>]] [xorrelayedaddr <ip> [<u16>]] [xorpeeraddr <ip> [<u16>]] [errcode <u16>] [software <str>] [transport tcp]`

use core::net::IpAddr;

/// RFC 8656 Traversal Using Relays around NAT (TURN) specification.
///
/// Syntax mapping: `turn [allocate | refresh | createpermission | channelbind | channeldata | sendindication | dataindication | msgtype <str>] [request | response | error] [txid <u32>] [channel <u16>] [lifetime <u32>] [requestedtransport <udp|tcp|u8>] [xormappedaddr <ip> [<u16>]] [xorrelayedaddr <ip> [<u16>]] [xorpeeraddr <ip> [<u16>]] [errcode <u16>] [software <str>] [transport tcp]`
#[doc(alias = "turn")]
#[doc(alias = "RFC 8656")]
#[doc(alias = "RFC8656")]
#[doc(alias = "RFC 5766")]
#[doc(alias = "RFC5766")]
#[doc(alias = "3478")]
#[doc(alias = "allocate")]
#[doc(alias = "refresh")]
#[doc(alias = "createpermission")]
#[doc(alias = "channelbind")]
#[doc(alias = "channeldata")]
#[doc(alias = "sendindication")]
#[doc(alias = "dataindication")]
#[doc(alias = "lifetime")]
#[doc(alias = "requestedtransport")]
#[doc(alias = "xorrelayedaddr")]
#[doc(alias = "xorpeeraddr")]
#[doc(alias = "xormappedaddr")]
#[doc(alias = "channel")]
#[doc(alias = "txid")]
#[doc(alias = "errcode")]
#[doc(alias = "software")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TurnSpec<'a> {
    /// TURN message type or method (`allocate`, `refresh`, `createpermission`, `channelbind`, `channeldata`, `sendindication`, `dataindication`).
    pub msg_type: Option<&'a str>,
    /// Explicit STUN/TURN Request message class flag.
    pub is_request: bool,
    /// STUN/TURN Success Response message class flag.
    pub is_response: bool,
    /// STUN/TURN Error Response message class flag.
    pub is_error: bool,
    /// 32-bit prefix of the 96-bit STUN/TURN Transaction ID (`txid <u32>`).
    pub txid: Option<u32>,
    /// TURN ChannelData or ChannelBind channel number (`0x4000..=0x7FFF`).
    pub channel: Option<u16>,
    /// Allocation lifetime in seconds (`LIFETIME` attribute `0x000D`).
    pub lifetime: Option<u32>,
    /// Requested relay transport protocol number (`17` UDP or `6` TCP in `0x0019`).
    pub requested_transport: Option<u8>,
    /// Server-reflexive `XOR-MAPPED-ADDRESS` (`0x0020`) IP address.
    pub xor_mapped_addr: Option<IpAddr>,
    /// Optional `XOR-MAPPED-ADDRESS` port (`xormappedaddr <ip> [<port>]`).
    pub xor_mapped_port: Option<u16>,
    /// Allocated `XOR-RELAYED-ADDRESS` (`0x0016`) IP address.
    pub xor_relayed_addr: Option<IpAddr>,
    /// Optional `XOR-RELAYED-ADDRESS` port (`xorrelayedaddr <ip> [<port>]`).
    pub xor_relayed_port: Option<u16>,
    /// Remote `XOR-PEER-ADDRESS` (`0x0012`) IP address.
    pub xor_peer_addr: Option<IpAddr>,
    /// Optional `XOR-PEER-ADDRESS` port (`xorpeeraddr <ip> [<port>]`).
    pub xor_peer_port: Option<u16>,
    /// STUN/TURN error status code (`ERROR-CODE` attribute `0x0009`, e.g., `401`).
    pub errcode: Option<u16>,
    /// Software agent description string (`SOFTWARE` attribute `0x8022`).
    pub software: Option<&'a str>,
}
