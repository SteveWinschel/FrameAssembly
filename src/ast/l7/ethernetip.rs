//! ODVA EtherNet/IP and Common Industrial Protocol (CIP) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`EthernetipSpec`], the zero-copy AST representation of an ODVA EtherNet/IP
//! encapsulation frame over TCP port 44818 (explicit messaging) or UDP port 2222 (implicit I/O).
//! On the wire, every EtherNet/IP packet begins with a 24-byte little-endian Encapsulation Header
//! (16-bit Command code such as `0x0063` `ListIdentity`, `0x0065` `RegisterSession`, or `0x006F`
//! `SendRRData`, 16-bit data length, 32-bit Session Handle, 32-bit Status code, 64-bit Sender
//! Context, and 32-bit Options) followed by Common Packet Format (CPF) items and a CIP request/reply
//! path (Service, Class, Instance, and Attribute). Canonical `.fasm` syntax:
//! `ethernetip [nop | listidentity | registersession | sendrrdata | sendunitdata | cmd <str>] [sessionhandle <u32>] [status <u32>] [context <u64>] [cipservice <u8>] [cipclass <u16>] [cipinstance <u16>] [cipattr <u16>]`.

/// ODVA EtherNet/IP encapsulation and Common Industrial Protocol (CIP) specification.
///
/// Syntax mapping: `ethernetip [nop | listidentity | registersession | sendrrdata | sendunitdata | cmd <str>] [sessionhandle <u32>] [status <u32>] [context <u64>] [cipservice <u8>] [cipclass <u16>] [cipinstance <u16>] [cipattr <u16>]`
#[doc(alias = "ethernetip")]
#[doc(alias = "EtherNet/IP")]
#[doc(alias = "ODVA")]
#[doc(alias = "CIP")]
#[doc(alias = "44818")]
#[doc(alias = "nop")]
#[doc(alias = "cmd")]
#[doc(alias = "sessionhandle")]
#[doc(alias = "status")]
#[doc(alias = "context")]
#[doc(alias = "cipservice")]
#[doc(alias = "cipclass")]
#[doc(alias = "cipinstance")]
#[doc(alias = "cipattr")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthernetipSpec<'a> {
    /// EtherNet/IP encapsulation command (`cmd <str>`, e.g., `"LIST_IDENTITY"`, `"REGISTER_SESSION"`, `"SEND_RR_DATA"`, `"SEND_UNIT_DATA"`).
    pub cmd: Option<&'a str>,
    /// 32-bit encapsulation Session Handle (`sessionhandle <u32>`, default `0`).
    pub session_handle: Option<u32>,
    /// 32-bit encapsulation Status code (`status <u32>`, default `0`).
    pub status: Option<u32>,
    /// 64-bit Sender Context correlation value (`context <u64>`, default `0`).
    pub context: Option<u64>,
    /// 8-bit CIP Service code (`cipservice <u8>`, default `0x0E` for `Get_Attribute_Single`).
    pub cip_service: Option<u8>,
    /// 16-bit CIP Object Class ID (`cipclass <u16>`, default `1` for Identity Object).
    pub cip_class: Option<u16>,
    /// 16-bit CIP Object Instance ID (`cipinstance <u16>`, default `1`).
    pub cip_instance: Option<u16>,
    /// Optional 16-bit CIP Attribute ID (`cipattr <u16>`).
    pub cip_attr: Option<u16>,
}
