//! IEEE 802.1Qbb Priority Flow Control (PFC) Abstract Syntax Tree (AST) definitions.
//!
//! Defines the AST specification for IEEE 802.1Qbb / IEEE 802.3 Annex 31D Priority-based Flow
//! Control (`pfc`) MAC Control frames transmitted over Ethernet II (`EtherType = 0x8808`) to the
//! MAC Control Pause multicast address `01:80:C2:00:00:01`. Each 60-byte PFC frame encodes MAC
//! Control OpCode `0x0101`, a 16-bit Class Enable Vector (`enable`, bits `0..=7` for IEEE 802.1p
//! priorities `0..=7`), eight 16-bit pause time quanta (`quanta` or `q0..q7`), and 26 bytes of
//! IEEE 802.3 reserved zero padding.
//!
//! Canonical `.frasm` syntax:
//! `a -> b pfc [enable <u16>] [quanta <u16>] [q0 <u16>] [q1 <u16>] [q2 <u16>] [q3 <u16>] [q4 <u16>] [q5 <u16>] [q6 <u16>] [q7 <u16>]`

/// IEEE 802.1Qbb Priority Flow Control (`pfc`, EtherType `0x8808`, OpCode `0x0101`) specification.
///
/// Syntax mapping: `pfc [enable <u16>] [quanta <u16>] [q0 <u16>] [q1 <u16>] [q2 <u16>] [q3 <u16>] [q4 <u16>] [q5 <u16>] [q6 <u16>] [q7 <u16>]`
#[doc(alias = "pfc")]
#[doc(alias = "802.1Qbb")]
#[doc(alias = "CBFC")]
#[doc(alias = "0x8808")]
#[doc(alias = "0x0101")]
#[doc(alias = "enable")]
#[doc(alias = "quanta")]
#[doc(alias = "q0")]
#[doc(alias = "q3")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PfcSpec {
    /// 16-bit Priority Enable Vector (`enable <u16>`, lower 8 bits select classes `0..=7`, default `0x00FF`).
    pub enable: Option<u16>,
    /// Uniform 16-bit pause duration in 512-bit quanta for enabled classes (`quanta <u16>`, default `0xFFFF`).
    pub quanta: Option<u16>,
    /// Optional per-class pause duration overrides for IEEE 802.1p priorities `0..=7` (`q0..q7 <u16>`).
    pub class_quanta: [Option<u16>; 8],
}
