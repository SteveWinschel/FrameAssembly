//! Cisco Discovery Protocol version 2 (CDPv2) Abstract Syntax Tree (AST) definitions.
//!
//! Defines the AST specification for Cisco Discovery Protocol version 2 (`cdp`) frames carried
//! inside IEEE 802.3 Ethernet packets with an 8-byte IEEE 802.2 LLC/SNAP header (`DSAP = 0xAA`,
//! `SSAP = 0xAA`, `Control = 0x03`, Cisco OUI `0x00000C`, Protocol ID `0x2000`) addressed by
//! default to the Cisco Discovery multicast MAC `01:00:0C:CC:CC:CC`. Each CDPv2 PDU encodes a
//! 4-byte header (`version`, `ttl`, `checksum`) followed by Type-Length-Value attributes including
//! Device ID (`0x0001`), Addresses (`0x0002`), Port ID (`0x0003`), Capabilities (`0x0004`),
//! Software Version (`0x0005`), Platform (`0x0006`), and optional Native VLAN (`0x000A`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b cdp [version <u8>] [ttl <u8>] [deviceid "<str>"] [addr <ip>] [portid "<str>"] [capabilities <u32>] [swversion "<str>"] [platform "<str>"] [nativevlan <u16>]`

use core::net::IpAddr;

/// Cisco Discovery Protocol version 2 (CDPv2 over 802.3 LLC/SNAP `0x2000`) frame specification.
///
/// Syntax mapping: `cdp [version <u8>] [ttl <u8>] [deviceid "<str>"] [addr <ip>] [portid "<str>"] [capabilities <u32>] [swversion "<str>"] [platform "<str>"] [nativevlan <u16>]`
#[doc(alias = "cdp")]
#[doc(alias = "CDPv2")]
#[doc(alias = "0x2000")]
#[doc(alias = "SNAP")]
#[doc(alias = "deviceid")]
#[doc(alias = "addr")]
#[doc(alias = "portid")]
#[doc(alias = "capabilities")]
#[doc(alias = "swversion")]
#[doc(alias = "platform")]
#[doc(alias = "nativevlan")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CdpSpec<'a> {
    /// CDP protocol version byte (`version <u8>`, default `2` for CDPv2).
    pub version: Option<u8>,
    /// Holdtime / Time-To-Live in seconds (`ttl <u8>`, default `180`).
    pub ttl: Option<u8>,
    /// Device ID TLV (`0x0001`, `deviceid "<str>"`, default `"switch1"`).
    pub device_id: Option<&'a str>,
    /// Management IPv4 or IPv6 address encoded in Addresses TLV (`0x0002`, `addr <ip>`).
    pub addr: Option<IpAddr>,
    /// Local interface Port ID TLV (`0x0003`, `portid "<str>"`, default `"GigabitEthernet0/1"`).
    pub port_id: Option<&'a str>,
    /// 32-bit device Capabilities bitmask TLV (`0x0004`, `capabilities <u32>`, default `0x0000_0028`).
    pub capabilities: Option<u32>,
    /// Software Version string TLV (`0x0005`, `swversion "<str>"`, default `"Cisco IOS Software"`).
    pub sw_version: Option<&'a str>,
    /// Hardware Platform string TLV (`0x0006`, `platform "<str>"`, default `"cisco WS-C3750"`).
    pub platform: Option<&'a str>,
    /// Optional Native VLAN ID TLV (`0x000A`, `nativevlan <0..=4095>`).
    pub native_vlan: Option<u16>,
}
