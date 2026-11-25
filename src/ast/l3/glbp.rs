//! Cisco Gateway Load Balancing Protocol (GLBP) AST definitions.
//!
//! Defines Cisco's First Hop Redundancy Protocol (FHRP) with active-active load sharing across up
//! to four Active Virtual Forwarders (AVFs), encapsulated over UDP port `3222` to IPv4 multicast
//! `224.0.0.102` (or IPv6 multicast `ff02::66`). Every GLBP packet opens with a 12-byte common
//! header (`version`, `group`, `ownerid` MAC) followed by Type-Length-Value blocks: Type `1` Hello
//! TLV (`state`, `priority`, `hellotime`, `holdtime`, `redirect`, `timeout`, `vip`), Type `2`
//! Request/Response TLV (`forwarder`, `state`, `priority`, `weight`, `vmac`), and optional Type `3`
//! Plain-Text Authentication TLV (`auth`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b glbp [hello | request | response] [version <u8>] [group <0..1023>] [ownerid <mac>] [state <u8>] [priority <u8>] [weight <u8>] [forwarder <u8>] [hellotime <u32>] [holdtime <u32>] [redirect <u16>] [timeout <u16>] [vip <ip>] [vmac <mac>] [auth "<str>"]`

use core::net::IpAddr;

/// Cisco GLBP message / TLV flavor selector.
#[doc(alias = "GlbpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlbpType {
    /// Type `1` Hello TLV (`hello`, 28-byte IPv4 / 40-byte IPv6 AVG advertisement).
    Hello,
    /// Type `2` Request TLV (`request`, 20-byte AVF assignment query with zeroed `vmac`).
    Request,
    /// Type `2` Response TLV (`response`, 20-byte AVG forwarder assignment carrying `vmac`).
    Response,
}

/// Cisco Gateway Load Balancing Protocol (GLBP) specification over UDP port `3222`.
///
/// Syntax mapping: `glbp [hello | request | response] [version <u8>] [group <0..1023>] [ownerid <mac>] [state <u8>] [priority <u8>] [weight <u8>] [forwarder <u8>] [hellotime <u32>] [holdtime <u32>] [redirect <u16>] [timeout <u16>] [vip <ip>] [vmac <mac>] [auth "<str>"]`
#[doc(alias = "glbp")]
#[doc(alias = "3222")]
#[doc(alias = "224.0.0.102")]
#[doc(alias = "FHRP")]
#[doc(alias = "group")]
#[doc(alias = "ownerid")]
#[doc(alias = "priority")]
#[doc(alias = "weight")]
#[doc(alias = "forwarder")]
#[doc(alias = "vip")]
#[doc(alias = "vmac")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlbpSpec<'a> {
    /// GLBP TLV message kind (`hello`, `request`, or `response`; default `hello`).
    pub msg_type: Option<GlbpType>,
    /// GLBP protocol version (`version <u8>`, default `1`).
    pub version: Option<u8>,
    /// GLBP standby group identifier (`group <u16>`, `0..=1023`, default `1`).
    pub group: Option<u16>,
    /// Physical router Owner ID MAC address (`ownerid <mac>`, default caller MAC).
    pub owner_id: Option<[u8; 6]>,
    /// Virtual Gateway or Virtual Forwarder state byte (`state <u8>`, default `0x20` Active).
    pub state: Option<u8>,
    /// Election priority (`priority <u8>`, default `100`).
    pub priority: Option<u8>,
    /// AVF load-balancing weighting (`weight <u8>`, default `100`).
    pub weight: Option<u8>,
    /// Virtual Forwarder index (`forwarder <u8>`, `1..=4`, default `1`).
    pub forwarder: Option<u8>,
    /// Hello interval in milliseconds (`hellotime <u32>`, default `3000`).
    pub hellotime: Option<u32>,
    /// Hold interval in milliseconds (`holdtime <u32>`, default `10000`).
    pub holdtime: Option<u32>,
    /// Redirect timer in seconds before redirecting away from a failed AVF (`redirect <u16>`, default `600`).
    pub redirect: Option<u16>,
    /// Secondary hold/forwarder timeout in seconds (`timeout <u16>`, default `14400`).
    pub timeout: Option<u16>,
    /// Shared Virtual IPv4 or IPv6 gateway address (`vip <ip>`).
    pub vip: Option<IpAddr>,
    /// Assigned Virtual MAC address (`vmac <mac>`, default `00:07:b4:00:<group>:<forwarder>` for `response`).
    pub vmac: Option<[u8; 6]>,
    /// Optional plain-text authentication string encoded as GLBP Type `3` Auth TLV (`auth "<str>"`).
    pub auth: Option<&'a str>,
}
