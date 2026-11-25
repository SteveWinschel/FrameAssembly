//! IEC 61850-8-1 Generic Object Oriented Substation Event (GOOSE) AST definitions.
//!
//! Defines the abstract syntax tree specification for IEC 61850-8-1 GOOSE substation protection
//! multicast frames transmitted directly over Ethernet II (`EtherType = 0x88B8`) to the IEEE
//! IEC TC57 multicast MAC range `01:0C:CD:01:00:00..01:FF` (default `01:0C:CD:01:00:01`). Each
//! frame contains an 8-byte GOOSE transport header (`APPID`, `Length`, `Reserved1`, `Reserved2`)
//! followed by an ASN.1 BER `[APPLICATION 1]` (`0x61`) `goosePdu` encoding `gocbRef`,
//! `timeAllowedToLive`, `datSet`, `goID`, UTC timestamp `t`, state number `stNum`, sequence
//! number `sqNum`, `simulation`, `confRev`, `ndsCom`, `numDatSetEntries`, and `allData`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b goose [appid <u16>] [gocbref "<str>"] [timetolive <u32>] [datset "<str>"] [goid "<str>"] [stnum <u32>] [sqnum <u32>] [simulation] [confrev <u32>] [ndscom] [numdatsetentries <u32>]`

/// IEC 61850-8-1 GOOSE (EtherType `0x88B8`) multicast frame specification.
///
/// Syntax mapping: `goose [appid <u16>] [gocbref "<str>"] [timetolive <u32>] [datset "<str>"] [goid "<str>"] [stnum <u32>] [sqnum <u32>] [simulation] [confrev <u32>] [ndscom] [numdatsetentries <u32>]`
#[doc(alias = "goose")]
#[doc(alias = "IEC 61850")]
#[doc(alias = "IEC61850")]
#[doc(alias = "0x88B8")]
#[doc(alias = "appid")]
#[doc(alias = "gocbref")]
#[doc(alias = "timetolive")]
#[doc(alias = "datset")]
#[doc(alias = "goid")]
#[doc(alias = "stnum")]
#[doc(alias = "sqnum")]
#[doc(alias = "simulation")]
#[doc(alias = "confrev")]
#[doc(alias = "ndscom")]
#[doc(alias = "numdatsetentries")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GooseSpec<'a> {
    /// 16-bit IEC 61850 Application Identifier (`appid <u16>`, default `0x1000`).
    pub appid: Option<u16>,
    /// GOOSE Control Block object reference (`gocbref "<str>"`, default `"IED1/LLN0$GO$gcb01"`).
    pub gocb_ref: Option<&'a str>,
    /// Time allowed to live in milliseconds (`timetolive <u32>`, default `2000`).
    pub time_to_live: Option<u32>,
    /// Referenced GOOSE DataSet name (`datset "<str>"`, default `"IED1/LLN0$ds01"`).
    pub dat_set: Option<&'a str>,
    /// Logical GOOSE identifier string (`goid "<str>"`, default `"gcb01"`).
    pub go_id: Option<&'a str>,
    /// State change counter incremented on data transition (`stnum <u32>`, default `1`).
    pub st_num: Option<u32>,
    /// Retransmission sequence counter within a state (`sqnum <u32>`, default `0`).
    pub sq_num: Option<u32>,
    /// Simulation/test indicator (`simulation`, sets BER `[7]` and Ed2 `Reserved1` bit 15).
    pub simulation: bool,
    /// Configuration revision number (`confrev <u32>`, default `1`).
    pub conf_rev: Option<u32>,
    /// Needs Commissioning flag (`ndscom`, default `false`).
    pub nds_com: bool,
    /// Number of entries in `allData` (`numdatsetentries <u32>`, default `2` on empty payload).
    pub num_entries: Option<u32>,
}
