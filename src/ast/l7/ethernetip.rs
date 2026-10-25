//! ODVA EtherNet/IP and Common Industrial Protocol (CIP) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`EthernetipSpec`], the zero-copy AST representation of an ODVA EtherNet/IP
//! encapsulation frame over TCP port 44818 (explicit messaging) or UDP port 2222 (implicit I/O).
//! On the wire, every EtherNet/IP packet begins with a 24-byte little-endian Encapsulation Header
//! (16-bit Command code such as `0x0063` `ListIdentity`, `0x0065` `RegisterSession`, or `0x006F`
//! `SendRRData`, 16-bit data length, 32-bit Session Handle, 32-bit Status code, 64-bit Sender
//! Context, and 32-bit Options) followed by Common Packet Format (CPF) items and a CIP request/reply
//! path (Service, Class, Instance, and Attribute). Canonical `.fasm` syntax:
//! `ETHERNETIP [CMD <str>] [SESSION_HANDLE <u32>] [STATUS <u32>] [CONTEXT <u64>] [CIP_SERVICE <u8>] [CIP_CLASS <u16>] [CIP_INSTANCE <u16>] [CIP_ATTR <u16>]`.

/// ODVA EtherNet/IP encapsulation and Common Industrial Protocol (CIP) specification.
///
/// Syntax mapping: `ETHERNETIP [CMD <str>] [SESSION_HANDLE <u32>] [STATUS <u32>] [CONTEXT <u64>] [CIP_SERVICE <u8>] [CIP_CLASS <u16>] [CIP_INSTANCE <u16>] [CIP_ATTR <u16>]`
#[doc(alias = "ETHERNETIP")]
#[doc(alias = "EtherNet/IP")]
#[doc(alias = "ODVA")]
#[doc(alias = "CIP")]
#[doc(alias = "44818")]
#[doc(alias = "CMD")]
#[doc(alias = "SESSION_HANDLE")]
#[doc(alias = "STATUS")]
#[doc(alias = "CONTEXT")]
#[doc(alias = "CIP_SERVICE")]
#[doc(alias = "CIP_CLASS")]
#[doc(alias = "CIP_INSTANCE")]
#[doc(alias = "CIP_ATTR")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthernetipSpec<'a> {
    /// EtherNet/IP encapsulation command (`CMD <str>`, e.g., `"LIST_IDENTITY"`, `"REGISTER_SESSION"`, `"SEND_RR_DATA"`, `"SEND_UNIT_DATA"`).
    pub cmd: Option<&'a str>,
    /// 32-bit encapsulation Session Handle (`SESSION_HANDLE <u32>`, default `0`).
    pub session_handle: Option<u32>,
    /// 32-bit encapsulation Status code (`STATUS <u32>`, default `0`).
    pub status: Option<u32>,
    /// 64-bit Sender Context correlation value (`CONTEXT <u64>`, default `0`).
    pub context: Option<u64>,
    /// 8-bit CIP Service code (`CIP_SERVICE <u8>`, default `0x0E` for `Get_Attribute_Single`).
    pub cip_service: Option<u8>,
    /// 16-bit CIP Object Class ID (`CIP_CLASS <u16>`, default `1` for Identity Object).
    pub cip_class: Option<u16>,
    /// 16-bit CIP Object Instance ID (`CIP_INSTANCE <u16>`, default `1`).
    pub cip_instance: Option<u16>,
    /// Optional 16-bit CIP Attribute ID (`CIP_ATTR <u16>`).
    pub cip_attr: Option<u16>,
}
