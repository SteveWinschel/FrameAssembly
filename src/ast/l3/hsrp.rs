//! Cisco Hot Standby Router Protocol (HSRP, RFC 2281) AST definitions.
//!
//! Defines the first-hop gateway redundancy control protocol specified in RFC 2281 over UDP port
//! `1985` (IPv4 multicast `224.0.0.2`) and HSRPv2 IPv6 adaptation over UDP port `2029` (IPv6
//! link-local multicast `ff02::66`). The 20-byte HSRP v1 packet header encodes an 8-bit `Version`
//! (`0` for IPv4, `2` for IPv6), an 8-bit `Op Code` (`0` Hello), an 8-bit router `State` (`state`,
//! default `16` Active), 8-bit `Hellotime` (`hellotime`, default `3`s) and `Holdtime` (`holdtime`,
//! default `10`s), 8-bit `Priority` (`priority`, default `100`), 8-bit Standby `Group` (`group`,
//! default `1`), 8-byte cleartext `Authentication Data` (`auth`, default `"cisco"`), and the Virtual IP (`vip`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b hsrp [group <u8>] [priority <u8>] [state <u8>] [hellotime <u8>] [holdtime <u8>] [auth "<str>"] [vip <ip>]`

use core::net::IpAddr;

/// Cisco Hot Standby Router Protocol (RFC 2281) specification over UDP port `1985` / `2029`.
///
/// Syntax mapping: `hsrp [group <u8>] [priority <u8>] [state <u8>] [hellotime <u8>] [holdtime <u8>] [auth "<str>"] [vip <ip>]`
#[doc(alias = "hsrp")]
#[doc(alias = "RFC 2281")]
#[doc(alias = "RFC2281")]
#[doc(alias = "1985")]
#[doc(alias = "FHRP")]
#[doc(alias = "group")]
#[doc(alias = "priority")]
#[doc(alias = "state")]
#[doc(alias = "hellotime")]
#[doc(alias = "holdtime")]
#[doc(alias = "auth")]
#[doc(alias = "vip")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HsrpSpec<'a> {
    /// 8-bit Standby Group number (`group <u8>`, default `1`).
    pub group: Option<u8>,
    /// 8-bit election Priority (`priority <u8>`, default `100`).
    pub priority: Option<u8>,
    /// 8-bit HSRP state machine code (`state <u8>`: `0` Initial, `1` Learn, `2` Listen, `4` Speak, `8` Standby, `16` Active; default `16`).
    pub state: Option<u8>,
    /// Up to 8-byte cleartext authentication password string (`auth "<str>"`, default `"cisco"`).
    pub auth: Option<&'a str>,
    /// Virtual IPv4 or IPv6 gateway address shared by the standby group (`vip <ip>`).
    pub vip: Option<IpAddr>,
    /// Hello interval in seconds between successive HSRP advertisements (`hellotime <u8>`, default `3`).
    pub hellotime: Option<u8>,
    /// Hold time in seconds before declaring the active router down (`holdtime <u8>`, default `10`).
    pub holdtime: Option<u8>,
}
