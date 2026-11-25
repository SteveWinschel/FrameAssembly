//! IEC 61850-9-2LE Sampled Values (SV) Layer 2 AST definitions.
//!
//! Defines the abstract syntax tree specification for IEC 61850-9-2 / 9-2LE Sampled Measured
//! Values multicast frames transmitted directly over Ethernet II (`EtherType = 0x88BA`) to the
//! IEC TC57 multicast MAC range `01:0C:CD:04:00:00..01:FF` (default `01:0C:CD:04:00:01`). Each
//! frame pairs an 8-byte SV transport header (`APPID`, `Length`, `Reserved1`, `Reserved2`) with
//! an ASN.1 BER `[APPLICATION 0]` (`0x60`) `savPdu` carrying `noASDU` and one `ASDU` (`0x30`)
//! with `svID`, optional `datSet`, `smpCnt`, `confRev`, `smpSynch`, optional `smpRate`, and
//! 64-byte `seqOfData` phasor samples.
//!
//! Canonical `.frasm` syntax:
//! `a -> b sv [appid <u16>] [svid "<str>"] [datset "<str>"] [smpcnt <u16>] [confrev <u32>] [smpsynch <0|1|2>] [smprate <u16>] [simulation]`

/// IEC 61850-9-2LE Sampled Values (EtherType `0x88BA`) multicast frame specification.
///
/// Syntax mapping: `sv [appid <u16>] [svid "<str>"] [datset "<str>"] [smpcnt <u16>] [confrev <u32>] [smpsynch <0|1|2>] [smprate <u16>] [simulation]`
#[doc(alias = "sv")]
#[doc(alias = "SMV")]
#[doc(alias = "IEC 61850-9-2")]
#[doc(alias = "0x88BA")]
#[doc(alias = "appid")]
#[doc(alias = "svid")]
#[doc(alias = "datset")]
#[doc(alias = "smpcnt")]
#[doc(alias = "confrev")]
#[doc(alias = "smpsynch")]
#[doc(alias = "smprate")]
#[doc(alias = "simulation")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SvSpec<'a> {
    /// 16-bit IEC 61850 Application Identifier (`appid <u16>`, default `0x4000`).
    pub appid: Option<u16>,
    /// Sampled Values stream identifier (`svid "<str>"`, default `"IED1MU01"`).
    pub sv_id: Option<&'a str>,
    /// Optional referenced DataSet name (`datset "<str>"`, omitted by default).
    pub dat_set: Option<&'a str>,
    /// 16-bit sample counter incrementing per sampling instant (`smpcnt <u16>`, default `0`).
    pub smp_cnt: Option<u16>,
    /// 32-bit Configuration Revision counter (`confrev <u32>`, default `1`).
    pub conf_rev: Option<u32>,
    /// Time synchronization status (`smpsynch <0..=2>`: `0` none, `1` local, `2` global default).
    pub smp_synch: Option<u8>,
    /// Optional 16-bit sampling rate (`smprate <u16>`, omitted by default).
    pub smp_rate: Option<u16>,
    /// IEC 61850-9-2 Ed2 Simulation flag (`simulation`, sets `Reserved1` bit 15 `0x8000`).
    pub simulation: bool,
}
