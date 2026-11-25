//! IEC 60870-5-104 (Telecontrol Equipment and Systems over TCP/IP) AST definitions.
//!
//! This module defines [`Iec104Spec`], the zero-copy AST representation of an IEC 60870-5-104
//! substation SCADA frame over TCP port 2404. On the wire, every APDU begins with start byte
//! `0x68`, an 8-bit length octet (`4..=253`), and a 4-octet Application Protocol Control
//! Information (APCI) control field encoding numbered Information Transfer (`I`-frames), numbered
//! Supervisory (`S`-frames), or Unnumbered Control (`U`-frames: `STARTDT`, `STOPDT`, `TESTFR`).
//! `I`-frames carry an Application Service Data Unit (ASDU) containing `TypeID`, Variable
//! Structure Qualifier (`VSQ`), Cause of Transmission (`COT`), Common Address (`CA`), Information
//! Object Address (`IOA`), and typed information elements. Canonical `.frasm` syntax:
//! `iec104 [startdt | stopdt | testfr | sframe | msgtype <str>] [confirm] [txseq <u16>] [rxseq <u16>] [typeid <u8>] [cot <u8|str>] [ca <u16>] [ioa <u32>] [value <u32>] [real <f32>]`.

/// IEC 60870-5-104 Telecontrol APCI and ASDU specification.
///
/// Syntax mapping: `iec104 [startdt | stopdt | testfr | sframe | msgtype <str>] [confirm] [txseq <u16>] [rxseq <u16>] [typeid <u8>] [cot <u8|str>] [ca <u16>] [ioa <u32>] [value <u32>] [real <f32>]`
#[doc(alias = "iec104")]
#[doc(alias = "IEC 60870-5-104")]
#[doc(alias = "IEC104")]
#[doc(alias = "APCI")]
#[doc(alias = "ASDU")]
#[doc(alias = "2404")]
#[doc(alias = "startdt")]
#[doc(alias = "stopdt")]
#[doc(alias = "testfr")]
#[doc(alias = "sframe")]
#[doc(alias = "msgtype")]
#[doc(alias = "confirm")]
#[doc(alias = "txseq")]
#[doc(alias = "rxseq")]
#[doc(alias = "typeid")]
#[doc(alias = "cot")]
#[doc(alias = "ca")]
#[doc(alias = "ioa")]
#[doc(alias = "value")]
#[doc(alias = "real")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Iec104Spec<'a> {
    /// APCI frame format or U-frame control selector (`msgtype <str>`, e.g., `"iframe"`, `"sframe"`, `"startdtact"`, `"startdtcon"`, `"stopdtact"`, `"stopdtcon"`, `"testfract"`, `"testfrcon"`).
    pub msg_type: Option<&'a str>,
    /// Confirmation flag (`confirm`), toggling U-frames to `_con` or defaulting I-frame `cot` to `7` (Activation Confirmation).
    pub confirm: bool,
    /// 15-bit APCI send sequence number `N(S)` (`txseq <u16>`, `0..=32767`, default `0`).
    pub tx_seq: Option<u16>,
    /// 15-bit APCI receive sequence number `N(R)` (`rxseq <u16>`, `0..=32767`, default `0`).
    pub rx_seq: Option<u16>,
    /// 8-bit ASDU Type Identification (`typeid <u8>`, default `100` for `C_IC_NA_1`, or `13` when `real` is set).
    pub type_id: Option<u8>,
    /// 6-bit ASDU Cause of Transmission (`cot <u8|str>`, default `6` Activation for commands or `3` Spontaneous for monitoring).
    pub cot: Option<u8>,
    /// 16-bit ASDU Common Address (`ca <u16>`, default `1`).
    pub ca: Option<u16>,
    /// 24-bit ASDU Information Object Address (`ioa <u32>`, `0..=16777215`, default `0` for `typeid` `100`/`103`, else `1`).
    pub ioa: Option<u32>,
    /// Integer information object element value (`value <u32>`, e.g., QOI `20`, SIQ/DIQ/SCO/DCO, or normalized/scaled value).
    pub value: Option<u32>,
    /// IEEE 754 single-precision float bits (`real <f32>`) for `M_ME_NC_1` (`typeid 13`) short floating-point measurements.
    pub real_value: Option<u32>,
}
