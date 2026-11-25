//! IEEE C37.118 Synchrophasor (PMU / PDC Grid Telemetry) AST definitions.
//!
//! This module defines [`SynchrophasorSpec`], the zero-copy AST representation of an IEEE
//! C37.118-2005 / C37.118.2-2011 synchrophasor frame over TCP or UDP port 4712. On the wire,
//! every frame opens with a 14-byte header consisting of the 2-byte `SYNC` word (`0xAA` followed
//! by `(frame_type << 4) | version`), 16-bit `FRAMESIZE`, 16-bit PMU/PDC `IDCODE`, 32-bit Second
//! of Century (`SOC`) UNIX timestamp, and 32-bit `FRACSEC` word, followed by type-specific Data,
//! Header, CFG-1, CFG-2, CFG-3, or Command bodies and a trailing 2-byte CRC-CCITT checksum.
//! Canonical `.frasm` syntax:
//! `synchrophasor [msgtype <str>] [version <u8>] [id <u16>] [timestamp <u32>] [fracsec <u32>] [cmd <u16|str>] [status <u16>] [station <str>] [crc <u16>]`.

/// IEEE C37.118 Synchrophasor (PMU/PDC telemetry) specification.
///
/// Syntax mapping: `synchrophasor [msgtype <str>] [version <u8>] [id <u16>] [timestamp <u32>] [fracsec <u32>] [cmd <u16|str>] [status <u16>] [station <str>] [crc <u16>]`
#[doc(alias = "synchrophasor")]
#[doc(alias = "C37.118")]
#[doc(alias = "IEEE C37.118")]
#[doc(alias = "PMU")]
#[doc(alias = "PDC")]
#[doc(alias = "4712")]
#[doc(alias = "msgtype")]
#[doc(alias = "version")]
#[doc(alias = "id")]
#[doc(alias = "timestamp")]
#[doc(alias = "fracsec")]
#[doc(alias = "cmd")]
#[doc(alias = "status")]
#[doc(alias = "station")]
#[doc(alias = "crc")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SynchrophasorSpec<'a> {
    /// IEEE C37.118 frame type (`msgtype <str>`, e.g., `"command"`, `"data"`, `"header"`, `"cfg1"`, `"cfg2"`, `"cfg3"`).
    pub msg_type: Option<&'a str>,
    /// IEEE C37.118 protocol version nibble (`version <u8>`, `1` for 2005 or `2` for 2011, default `1`).
    pub version: Option<u8>,
    /// 16-bit PMU/PDC Stream Source ID (`id <u16>`, default `1`).
    pub id_code: Option<u16>,
    /// 32-bit Second of Century (`SOC`) UNIX timestamp (`timestamp <u32>`, default `1700000000`).
    pub soc: Option<u32>,
    /// 32-bit `FRACSEC` time-quality and fractional-second word (`fracsec <u32>`, default `0`).
    pub frac_sec: Option<u32>,
    /// 16-bit Command frame instruction (`cmd <u16|str>`, e.g., `1`..=`8` or `"sendcfg2"`, default `5`).
    pub cmd: Option<u16>,
    /// 16-bit Data frame `STAT` status flags word (`status <u16>`, default `0`).
    pub status: Option<u16>,
    /// Station name `STN` for CFG-1/CFG-2 frames (`station <str>`, max 16 ASCII bytes, default `"PMU_1"`).
    pub station: Option<&'a str>,
    /// Optional 16-bit CRC-CCITT override (`crc <u16>`) for negative checksum testing.
    pub crc: Option<u16>,
}
