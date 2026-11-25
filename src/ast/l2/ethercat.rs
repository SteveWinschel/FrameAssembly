//! EtherCAT Industrial Real-Time Protocol (IEC 61158-4-12) Layer 2 AST definitions.
//!
//! Defines the abstract syntax tree specification for Beckhoff / ETG EtherCAT real-time control
//! frames. By default, `ethercat` emits native Ethernet II frames (`EtherType = 0x88A4`) even on
//! IP-configured hosts, encoding the 2-byte little-endian EtherCAT Frame Header (`Length`, `Type = 1`)
//! and a 12-byte-plus-data little-endian EtherCAT Datagram (`Cmd` such as `APRD`/`FPRD`/`BRD`/`LRD`/
//! `LRW`, `Idx`, 16-bit `ADP`, 16-bit `ADO`, 11-bit `Len`, `IRQ`, data bytes, and 16-bit Working
//! Counter `WKC`). With explicit `transport udp`, it encapsulates the EtherCAT PDU over UDP port `34980`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ethercat [cmd <str>] [nop | read | write] [idx <u8>] [adp <u16>] [ado <u16>] [addr <u32>] [offset <u16>] [irq <u16>] [wkc <u16>] [transport udp]`

/// EtherCAT (`0x88A4` default L2 / UDP `34980`) datagram frame specification.
///
/// Syntax mapping: `ethercat [cmd <str>] [nop | read | write] [idx <u8>] [adp <u16>] [ado <u16>] [addr <u32>] [offset <u16>] [irq <u16>] [wkc <u16>] [transport udp]`
#[doc(alias = "ethercat")]
#[doc(alias = "ETG")]
#[doc(alias = "IEC 61158")]
#[doc(alias = "0x88A4")]
#[doc(alias = "34980")]
#[doc(alias = "cmd")]
#[doc(alias = "idx")]
#[doc(alias = "adp")]
#[doc(alias = "ado")]
#[doc(alias = "irq")]
#[doc(alias = "wkc")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthercatSpec<'a> {
    /// EtherCAT datagram command mnemonic or code (`cmd <str>`, default `"APRD"`).
    pub cmd: Option<&'a str>,
    /// 8-bit EtherCAT datagram index (`idx <u8>`, default `0`).
    pub idx: Option<u8>,
    /// 16-bit Auto-increment or Configured Station Address (`adp <u16>`, default `0`).
    pub adp: Option<u16>,
    /// 16-bit slave physical memory Address Offset (`ado <u16>`, default `0`).
    pub ado: Option<u16>,
    /// 16-bit EtherCAT external event / IRQ request mask (`irq <u16>`, default `0`).
    pub irq: Option<u16>,
    /// 16-bit EtherCAT Working Counter (`wkc <u16>`, default `0`).
    pub wkc: Option<u16>,
}
