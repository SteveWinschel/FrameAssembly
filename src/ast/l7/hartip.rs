//! HART-IP (Highway Addressable Remote Transducer over IP, HCF Spec 085) AST definitions.
//!
//! This module defines [`HartipSpec`], the zero-copy AST representation of a FieldComm Group
//! HART-IP industrial field-instrumentation message over UDP or TCP port 5094. On the wire,
//! every HART-IP packet opens with an 8-byte big-endian header containing `Version` (`1`),
//! `Message Type` (`0` Request, `1` Response, `2` Publish, `3` NAK), `Message ID` (`0` Session
//! Initiate, `1` Session Close, `2` Keep Alive, `3` Token-Passing PDU, `4` Direct PDU, `5`
//! Discovery), 8-bit `Status`, 16-bit `Transaction ID`, and 16-bit `Message Length`, followed by
//! session parameters or embedded HART field commands. Canonical `.frasm` syntax:
//! `hartip [init | close | keepalive | msgid <u8|str>] [version <u8>] [msgtype <u8|str>] [isresponse] [status <u8>] [txid <u16>] [mode <u8>] [holdtime <u32>] [addr <u8>] [cmd <u8>]`.

/// FieldComm Group HART-IP (HCF Spec 085) industrial protocol specification.
///
/// Syntax mapping: `hartip [init | close | keepalive | msgid <u8|str>] [version <u8>] [msgtype <u8|str>] [isresponse] [status <u8>] [txid <u16>] [mode <u8>] [holdtime <u32>] [addr <u8>] [cmd <u8>]`
#[doc(alias = "hartip")]
#[doc(alias = "HART-IP")]
#[doc(alias = "HART")]
#[doc(alias = "HCF")]
#[doc(alias = "5094")]
#[doc(alias = "init")]
#[doc(alias = "close")]
#[doc(alias = "keepalive")]
#[doc(alias = "version")]
#[doc(alias = "msgtype")]
#[doc(alias = "isresponse")]
#[doc(alias = "msgid")]
#[doc(alias = "status")]
#[doc(alias = "txid")]
#[doc(alias = "mode")]
#[doc(alias = "holdtime")]
#[doc(alias = "addr")]
#[doc(alias = "cmd")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HartipSpec<'a> {
    /// HART-IP protocol version (`version <u8>`, default `1`).
    pub version: Option<u8>,
    /// HART-IP message type selector (`msgtype <u8|str>`, e.g., `"request"`, `"response"`, `"publish"`, `"nak"`).
    pub msg_type: Option<&'a str>,
    /// Response flag (`isresponse` / `response`), selecting Message Type `1` (Response).
    pub is_response: bool,
    /// 8-bit HART-IP Message ID (`msgid <u8|str>`, `0` Initiate, `1` Close, `2` Keep Alive, `3` Pass-Through, `4` Direct, `5` Discovery).
    pub msg_id: Option<u8>,
    /// 8-bit HART-IP status code (`status <u8>`, default `0`).
    pub status: Option<u8>,
    /// 16-bit HART-IP Transaction ID / Sequence Number (`txid <u16>`, default `1`).
    pub txid: Option<u16>,
    /// Session Initiate host/master type (`mode <u8>`, `1` Primary Master or `0` Secondary Master, default `1`).
    pub master_type: Option<u8>,
    /// Session Initiate inactivity close timer in milliseconds (`holdtime <u32>`, default `60000`).
    pub inactivity_timer: Option<u32>,
    /// Embedded HART Token-Passing short polling address (`addr <u8>`, `0..=63`, implies `msgid 3`).
    pub poll_addr: Option<u8>,
    /// Embedded HART Token-Passing command number (`cmd <u8>`, implies `msgid 3`).
    pub hart_cmd: Option<u8>,
}
