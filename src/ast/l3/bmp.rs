//! BGP Monitoring Protocol (BMP, RFC 7854 / RFC 8671 / RFC 9069) AST definitions.
//!
//! Defines the real-time BGP state and route-monitoring protocol specified in RFC 7854 over TCP
//! port `1790` (commonly used lab/collector port alongside `11019`). Every BMP message begins with a
//! 6-byte common header encoding the `Version` (`3`), 32-bit big-endian total `Message Length`,
//! and 8-bit `Message Type` (`0` `routemon`, `1` `statsreport`, `2` `peerdown`, `3` `peerup`, `4`
//! `initiation`, `5` `termination`). Types `0..=3` carry a 42-byte Per-Peer Header with `peertype`,
//! `flags`, `peerip`, `asn`, and `bgpid` metadata before encapsulated BGP PDUs or TLVs.
//!
//! Canonical `.frasm` syntax:
//! `a -> b bmp [routemon | statsreport | peerdown | peerup | initiation | termination] [version <u8>] [peertype <u8>] [flags <u8>] [peerip <ip>] [asn <u32>] [bgpid <ipv4>] [sysname "<str>"] [sysdesc "<str>"] [reason <u16>]`

use core::net::IpAddr;

/// RFC 7854 BGP Monitoring Protocol (BMP) message type discriminator.
#[doc(alias = "BmpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BmpType {
    /// Type `0` (`routemon`): Route Monitoring message carrying a Per-Peer Header and BGP PDU.
    RouteMonitoring,
    /// Type `1` (`statsreport`): Statistics Report message carrying counter TLVs for a peer.
    StatsReport,
    /// Type `2` (`peerdown`): Peer Down Notification signaling BGP session termination and `reason`.
    PeerDown,
    /// Type `3` (`peerup`): Peer Up Notification carrying local/remote sockets and Sent/Received BGP OPENs.
    PeerUp,
    /// Type `4` (`initiation`): Session Initiation message advertising `sysname` and `sysdesc` TLVs.
    Initiation,
    /// Type `5` (`termination`): Session Termination message carrying an optional termination `reason` TLV.
    Termination,
}

/// BGP Monitoring Protocol (RFC 7854) specification over TCP port `1790`.
///
/// Syntax mapping: `bmp [routemon | statsreport | peerdown | peerup | initiation | termination] [version <u8>] [peertype <u8>] [flags <u8>] [peerip <ip>] [asn <u32>] [bgpid <ipv4>] [sysname "<str>"] [sysdesc "<str>"] [reason <u16>]`
#[doc(alias = "bmp")]
#[doc(alias = "RFC 7854")]
#[doc(alias = "RFC7854")]
#[doc(alias = "1790")]
#[doc(alias = "routemon")]
#[doc(alias = "statsreport")]
#[doc(alias = "peerdown")]
#[doc(alias = "peerup")]
#[doc(alias = "initiation")]
#[doc(alias = "termination")]
#[doc(alias = "peertype")]
#[doc(alias = "peerip")]
#[doc(alias = "asn")]
#[doc(alias = "bgpid")]
#[doc(alias = "sysname")]
#[doc(alias = "sysdesc")]
#[doc(alias = "reason")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BmpSpec<'a> {
    /// BMP protocol version (`version <u8>`, default `3` per RFC 7854).
    pub version: Option<u8>,
    /// BMP message type (`routemon`, `statsreport`, `peerdown`, `peerup`, `initiation`, `termination`).
    pub msg_type: Option<BmpType>,
    /// Per-Peer Header peer type (`peertype <u8>`: `0` Global, `1` RD, `2` Local, `3` Loc-RIB; default `0`).
    pub peer_type: Option<u8>,
    /// Per-Peer Header flags byte (`flags <u8>`: bit 7 `V` IPv6, bit 6 `L` post-policy, bit 5 `A` 2B AS).
    pub peer_flags: Option<u8>,
    /// Monitored BGP peer IPv4 or IPv6 address (`peerip <ip>`).
    pub peer_ip: Option<IpAddr>,
    /// Monitored BGP peer 32-bit Autonomous System Number (`asn <u32>`, default `65001`).
    pub peer_asn: Option<u32>,
    /// Monitored BGP peer 32-bit BGP Identifier formatted as IPv4 (`bgpid <ipv4>`).
    pub peer_bgpid: Option<IpAddr>,
    /// Initiation `sysName` Information TLV string (`sysname "<str>"`, default `"FrameAssembly"`).
    pub sysname: Option<&'a str>,
    /// Initiation `sysDescr` Information TLV string (`sysdesc "<str>"`).
    pub sysdesc: Option<&'a str>,
    /// Termination Reason TLV code (`0..=4`), Peer Down reason code (`1..=5`), or Stats Type (`reason <u16>`).
    pub reason: Option<u16>,
}
