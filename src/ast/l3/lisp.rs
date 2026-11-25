//! Locator/ID Separation Protocol (LISP, RFC 9300 Data Plane / RFC 9301 Control Plane) AST definitions.
//!
//! Defines the LISP routing and encapsulation protocol separating Endpoint Identifiers (`eid`) from
//! Routing Locators (`rloc`) across two UDP services: LISP Data-Plane encapsulation over UDP port
//! `4341` (RFC 9300, carrying an 8-byte header with `I` Instance ID `iid` and `N` Nonce flags
//! followed by an inner IPv4/IPv6 packet) and LISP Control-Plane signaling over UDP port `4342`
//! (RFC 9301 `maprequest`, `mapreply`, `mapregister`, `mapnotify`, and `ecm` messages).
//!
//! Canonical `.frasm` syntax:
//! `a -> b lisp [data | maprequest | mapreply | mapregister | mapnotify | ecm] [flags <u8>] [iid <u24>] [nonce <u64>] [eid "<cidr>"] [rloc <ip>] [priority <u8>] [weight <u8>]`

use core::net::IpAddr;

/// RFC 9300 / RFC 9301 LISP packet plane and control message discriminator.
#[doc(alias = "LispMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LispType {
    /// RFC 9300 Data-Plane encapsulation over UDP port `4341`.
    Data,
    /// RFC 9301 Type `1` (`maprequest`): Control-plane EID-to-RLOC lookup over UDP port `4342`.
    MapRequest,
    /// RFC 9301 Type `2` (`mapreply`): Control-plane EID-to-RLOC mapping response over UDP port `4342`.
    MapReply,
    /// RFC 9301 Type `3` (`mapregister`): xTR-to-Map-Server registration over UDP port `4342`.
    MapRegister,
    /// RFC 9301 Type `4` (`mapnotify`): Map-Server registration acknowledgment over UDP port `4342`.
    MapNotify,
    /// RFC 9301 Type `8` (`ecm`): Encapsulated Control Message over UDP port `4342`.
    Ecm,
}

/// Locator/ID Separation Protocol (RFC 9300 / RFC 9301) specification over UDP ports `4341` and `4342`.
///
/// Syntax mapping: `lisp [data | maprequest | mapreply | mapregister | mapnotify | ecm] [flags <u8>] [iid <u24>] [nonce <u64>] [eid "<cidr>"] [rloc <ip>] [priority <u8>] [weight <u8>]`
#[doc(alias = "lisp")]
#[doc(alias = "RFC 9300")]
#[doc(alias = "RFC 9301")]
#[doc(alias = "4341")]
#[doc(alias = "4342")]
#[doc(alias = "maprequest")]
#[doc(alias = "mapreply")]
#[doc(alias = "mapregister")]
#[doc(alias = "mapnotify")]
#[doc(alias = "ecm")]
#[doc(alias = "iid")]
#[doc(alias = "nonce")]
#[doc(alias = "eid")]
#[doc(alias = "rloc")]
#[doc(alias = "weight")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LispSpec<'a> {
    /// LISP Data-Plane (`data`, UDP `4341`) or Control-Plane message type (UDP `4342`; default `data`).
    pub msg_type: Option<LispType>,
    /// Data-plane flags byte (`flags <u8>`) or control-plane lower 4 flag bits.
    pub flags: Option<u8>,
    /// 24-bit LISP Instance ID (`iid <0..=16_777_215>`, encoded in Data header or Control LCAF `0x4003`).
    pub iid: Option<u32>,
    /// 64-bit Control-Plane Nonce or 24-bit Data-Plane Nonce (`nonce <u64>`).
    pub nonce: Option<u64>,
    /// Endpoint Identifier prefix (`eid "<cidr>"`, default `"192.0.2.0/24"` or `"2001:db8::/32"`).
    pub eid: Option<&'a str>,
    /// Routing Locator IPv4 or IPv6 address (`rloc <ip>`, default caller source IP).
    pub rloc: Option<IpAddr>,
    /// Locator priority (`priority <u8>`, `0..=255`, default `1`).
    pub priority: Option<u8>,
    /// Locator load-balancing weight (`weight <u8>`, `0..=100`, default `100`).
    pub weight: Option<u8>,
}
