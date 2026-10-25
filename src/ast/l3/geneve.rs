//! Generic Network Virtualization Encapsulation (GENEVE, RFC 8926) AST definitions.
//!
//! Defines the extensible network virtualization overlay tunnel header specified in RFC 8926 and
//! encapsulated inside UDP datagrams addressed to destination port `6081`. The fixed 8-byte GENEVE
//! header contains a 2-bit `Ver` field (`0`), a 6-bit `Opt Len` count of 4-byte TLV option words,
//! control flags (`O` OAM bit, `C` Critical bit), a 16-bit IEEE EtherType `Protocol Type`
//! (`PROTOCOL_TYPE`, default `0x6558` Transparent Ethernet Bridging), a 24-bit Virtual Network
//! Identifier (`VNI`, default `4096`), and an 8-bit `Reserved` byte, optionally followed by variable
//! Type-Length-Value metadata options (`OPT_CLASS` and `OPT_TYPE`) used by OVN, Cilium, and NSX.
//!
//! Canonical `.fasm` syntax:
//! `a -> b GENEVE [VNI <u24>] [OPT_CLASS <u16>] [OPT_TYPE <u8>] [PROTOCOL_TYPE <u16>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use core::marker::PhantomData;

/// Generic Network Virtualization Encapsulation (RFC 8926) specification over UDP port `6081`.
///
/// Syntax mapping: `GENEVE [VNI <u24>] [OPT_CLASS <u16>] [OPT_TYPE <u8>] [PROTOCOL_TYPE <u16>]`
#[doc(alias = "GENEVE")]
#[doc(alias = "RFC 8926")]
#[doc(alias = "RFC8926")]
#[doc(alias = "6081")]
#[doc(alias = "VNI")]
#[doc(alias = "OPT_CLASS")]
#[doc(alias = "OPT_TYPE")]
#[doc(alias = "PROTOCOL_TYPE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeneveSpec<'a> {
    /// 24-bit Virtual Network Identifier (`VNI <0..=16777215>`, default `4096`).
    pub vni: Option<u32>,
    /// 16-bit IANA Option Class namespace for GENEVE TLV metadata (`OPT_CLASS <u16>`, e.g. `0x0102` OVN).
    pub opt_class: Option<u16>,
    /// 8-bit Option Type identifier within the specified Option Class (`OPT_TYPE <u8>`, bit 7 indicates Critical).
    pub opt_type: Option<u8>,
    /// 16-bit IEEE EtherType of the inner encapsulated frame (`PROTOCOL_TYPE <u16>`, default `0x6558` TEB).
    pub protocol_type: Option<u16>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
