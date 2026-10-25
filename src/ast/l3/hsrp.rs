//! Cisco Hot Standby Router Protocol (HSRP, RFC 2281) AST definitions.
//!
//! Defines the first-hop gateway redundancy control protocol specified in RFC 2281 over UDP port
//! `1985` (IPv4 multicast `224.0.0.2`) and HSRPv2 IPv6 adaptation over UDP port `2029` (IPv6
//! link-local multicast `ff02::66`). The 20-byte HSRP v1 packet header encodes an 8-bit `Version`
//! (`0` for IPv4, `2` for IPv6), an 8-bit `Op Code` (`0` Hello), an 8-bit router `State` (`STATE`,
//! default `16` Active), 8-bit `Hellotime` (`HELLOTIME`, default `3`s) and `Holdtime` (`HOLDTIME`,
//! default `10`s), 8-bit `Priority` (`PRIORITY`, default `100`), 8-bit Standby `Group` (`GROUP`,
//! default `1`), 8-byte cleartext `Authentication Data` (`AUTH`, default `"cisco"`), and the Virtual IP (`VIP`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b HSRP [GROUP <u8>] [PRIORITY <u8>] [STATE <u8>] [HELLOTIME <u8>] [HOLDTIME <u8>] [AUTH "<str>"] [VIP <ip>]`

use core::net::IpAddr;

/// Cisco Hot Standby Router Protocol (RFC 2281) specification over UDP port `1985` / `2029`.
///
/// Syntax mapping: `HSRP [GROUP <u8>] [PRIORITY <u8>] [STATE <u8>] [HELLOTIME <u8>] [HOLDTIME <u8>] [AUTH "<str>"] [VIP <ip>]`
#[doc(alias = "HSRP")]
#[doc(alias = "RFC 2281")]
#[doc(alias = "RFC2281")]
#[doc(alias = "1985")]
#[doc(alias = "FHRP")]
#[doc(alias = "GROUP")]
#[doc(alias = "PRIORITY")]
#[doc(alias = "STATE")]
#[doc(alias = "HELLOTIME")]
#[doc(alias = "HOLDTIME")]
#[doc(alias = "AUTH")]
#[doc(alias = "VIP")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HsrpSpec<'a> {
    /// 8-bit Standby Group number (`GROUP <u8>`, default `1`).
    pub group: Option<u8>,
    /// 8-bit election Priority (`PRIORITY <u8>`, default `100`).
    pub priority: Option<u8>,
    /// 8-bit HSRP state machine code (`STATE <u8>`: `0` Initial, `1` Learn, `2` Listen, `4` Speak, `8` Standby, `16` Active; default `16`).
    pub state: Option<u8>,
    /// Up to 8-byte cleartext authentication password string (`AUTH "<str>"`, default `"cisco"`).
    pub auth: Option<&'a str>,
    /// Virtual IPv4 or IPv6 gateway address shared by the standby group (`VIP <ip>`).
    pub vip: Option<IpAddr>,
    /// Hello interval in seconds between successive HSRP advertisements (`HELLOTIME <u8>`, default `3`).
    pub hellotime: Option<u8>,
    /// Hold time in seconds before declaring the active router down (`HOLDTIME <u8>`, default `10`).
    pub holdtime: Option<u8>,
}
