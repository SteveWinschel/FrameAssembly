//! AUTOSAR SOME/IP and Service Discovery (SOME/IP-SD) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`SomeipSpec`], the zero-copy AST representation of an AUTOSAR
//! Scalable service-Oriented MiddlewarE over IP (`someip`) and Service Discovery (`someip-sd`)
//! message over UDP port 30490 (default) or TCP port 30490. On the wire, every SOME/IP packet
//! starts with a 16-byte big-endian header (`serviceid`, `methodid`, `length`, `clientid`,
//! `sessionid`, `protover`, `ifacever`, `msgtype`, `returncode`) followed either by RPC/event
//! payload data or a SOME/IP-SD (`0xFFFF8100`) entry and endpoint option block (`findservice`,
//! `offerservice`, `subscribe`, `subscribeack`). Canonical `.frasm` syntax:
//! `someip [findservice | offerservice | subscribe | subscribeack | request | requestnoreply | notification | response | error | msgtype <str|u8>] [serviceid <u16>] [methodid <u16>] [clientid <u16>] [sessionid <u16>] [protover <u8>] [ifacever <u8>] [returncode <u8>] [flags <u8>] [sdservice <u16>] [instanceid <u16>] [majorver <u8>] [sdttl <u32>] [minorver <u32>] [endpointip <ip>] [endpointport <u16>]`.

use core::net::IpAddr;

/// AUTOSAR SOME/IP and SOME/IP Service Discovery (SOME/IP-SD) specification.
///
/// Syntax mapping: `someip [findservice | offerservice | subscribe | subscribeack | request | requestnoreply | notification | response | error | msgtype <str|u8>] [serviceid <u16>] [methodid <u16>] [clientid <u16>] [sessionid <u16>] [protover <u8>] [ifacever <u8>] [returncode <u8>] [flags <u8>] [sdservice <u16>] [instanceid <u16>] [majorver <u8>] [sdttl <u32>] [minorver <u32>] [endpointip <ip>] [endpointport <u16>]`
#[doc(alias = "someip")]
#[doc(alias = "AUTOSAR")]
#[doc(alias = "SOME/IP")]
#[doc(alias = "SOME/IP-SD")]
#[doc(alias = "30490")]
#[doc(alias = "findservice")]
#[doc(alias = "offerservice")]
#[doc(alias = "subscribe")]
#[doc(alias = "subscribeack")]
#[doc(alias = "serviceid")]
#[doc(alias = "methodid")]
#[doc(alias = "clientid")]
#[doc(alias = "sessionid")]
#[doc(alias = "protover")]
#[doc(alias = "ifacever")]
#[doc(alias = "msgtype")]
#[doc(alias = "returncode")]
#[doc(alias = "sdservice")]
#[doc(alias = "instanceid")]
#[doc(alias = "majorver")]
#[doc(alias = "sdttl")]
#[doc(alias = "minorver")]
#[doc(alias = "endpointip")]
#[doc(alias = "endpointport")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SomeipSpec<'a> {
    /// 16-bit SOME/IP Service ID (`serviceid <u16>`, `0xFFFF` for SD or `0x0001` for RPC).
    pub service_id: Option<u16>,
    /// 16-bit SOME/IP Method or Event ID (`methodid <u16>`, `0x8100` for SD or `0x0001` for RPC).
    pub method_id: Option<u16>,
    /// 16-bit SOME/IP Client ID (`clientid <u16>`, `0` for SD or `1` for RPC).
    pub client_id: Option<u16>,
    /// 16-bit SOME/IP Session ID (`sessionid <u16>`, default `1`).
    pub session_id: Option<u16>,
    /// 8-bit SOME/IP Protocol Version (`protover <u8>`, default `1`).
    pub proto_ver: Option<u8>,
    /// 8-bit SOME/IP Interface Version (`ifacever <u8>`, default `1`).
    pub iface_ver: Option<u8>,
    /// SOME/IP message type (`request`, `requestnoreply`, `notification`, `response`, `error`, or `msgtype <str|u8>`).
    pub msg_type: Option<&'a str>,
    /// 8-bit SOME/IP Return Code (`returncode <u8>`, default `0` `E_OK`).
    pub return_code: Option<u8>,
    /// SOME/IP-SD entry selector (`findservice`, `offerservice`, `subscribe`, `subscribeack`).
    pub sd_type: Option<&'a str>,
    /// 8-bit SOME/IP-SD header Flags byte (`flags <u8>`, default `0xC0` Reboot | Unicast).
    pub sd_flags: Option<u8>,
    /// 16-bit Service ID advertised or queried inside an SD entry (`sdservice <u16>`, default `0x1234`).
    pub sd_service: Option<u16>,
    /// 16-bit Instance ID inside an SD entry (`instanceid <u16>`, `0xFFFF` for FindService or `1` otherwise).
    pub instance_id: Option<u16>,
    /// 8-bit Major Version inside an SD entry (`majorver <u8>`, default `1`).
    pub major_ver: Option<u8>,
    /// 24-bit TTL in seconds inside an SD entry (`sdttl <u32>`, `0..=0xFFFFFF`, default `3`).
    pub sd_ttl: Option<u32>,
    /// 32-bit Minor Version (or low-16-bit Eventgroup ID for Subscribe entries) (`minorver <u32>`, default `0` / `1`).
    pub minor_ver: Option<u32>,
    /// Optional IPv4 or IPv6 Endpoint Option address attached to an SD entry (`endpointip <ip>`).
    pub endpoint_ip: Option<IpAddr>,
    /// Optional L4 port number inside an SD Endpoint Option (`endpointport <u16>`, default `30509`).
    pub endpoint_port: Option<u16>,
}
