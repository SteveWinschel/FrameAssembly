//! PROFINET IO Real-Time and Context Manager (IEC 61158-6-10) AST definitions.
//!
//! Defines the abstract syntax tree specification for Siemens and PROFIBUS/PROFINET International
//! industrial Ethernet frames. By default, `profinet` emits native Layer 2 PROFINET Real-Time
//! frames (`EtherType = 0x8892`) even when endpoints carry IP addresses, encoding the 16-bit
//! `FrameID` (`0x8000` Cyclic RT_CLASS_1 or `0xFEFC..=0xFEFF` Acyclic DCP), cyclic IO service
//! data unit, and 4-byte APDU status (`CycleCounter`, `DataStatus`, `TransferStatus`). With
//! explicit `transport udp`, it switches to UDP port `34964` carrying DCE/RPC v4 connectionless
//! `PNIO-CM` Device Control messages (`Connect`, `Release`, `Read`, `Write`, `Control`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b profinet [frameid <u16>] [cycle <u16>] [datastatus <u8>] [transferstatus <u8>] [service <str>] [xid <u32>] [request | response] [transport udp]`

/// PROFINET IO Real-Time (`0x8892`) and UDP Context Manager (`34964`) frame specification.
///
/// Syntax mapping: `profinet [frameid <u16>] [cycle <u16>] [datastatus <u8>] [transferstatus <u8>] [service <str>] [xid <u32>] [request | response] [transport udp]`
#[doc(alias = "profinet")]
#[doc(alias = "PNIO")]
#[doc(alias = "PN-RT")]
#[doc(alias = "PN-DCP")]
#[doc(alias = "IEC 61158")]
#[doc(alias = "0x8892")]
#[doc(alias = "34964")]
#[doc(alias = "frameid")]
#[doc(alias = "cycle")]
#[doc(alias = "datastatus")]
#[doc(alias = "transferstatus")]
#[doc(alias = "service")]
#[doc(alias = "xid")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfinetSpec<'a> {
    /// 16-bit PROFINET FrameID (`frameid <u16>`, default `0x8000` RT_CLASS_1 or `0xFEFD` for DCP).
    pub frame_id: Option<u16>,
    /// 16-bit Cyclic RT CycleCounter (`cycle <u16>`, default `1`) or DCE/RPC sequence number.
    pub cycle: Option<u16>,
    /// 8-bit Cyclic RT DataStatus bitmask (`datastatus <u8>`, default `0x35`: Primary, Valid, OK, Run).
    pub data_status: Option<u8>,
    /// 8-bit Cyclic RT TransferStatus code (`transferstatus <u8>`, default `0x00`).
    pub transfer_status: Option<u8>,
    /// Service mode selector (`service <str>`: `"rt"`, `"dcp"`, `"identify"`, `"get"`, `"set"`, `"connect"`, `"release"`, `"read"`, `"write"`, `"control"`).
    pub service: Option<&'a str>,
    /// 32-bit DCP transaction identifier (`xid <u32>`, default `1`).
    pub xid: Option<u32>,
    /// Selects response direction for DCP or DCE/RPC PNIO-CM frames (`response`, default `false`).
    pub is_response: bool,
}
