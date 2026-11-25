//! Cisco Skinny Client Control Protocol (SCCP) Layer 7 AST definitions.
//!
//! This module defines [`SccpSpec`], the zero-copy Abstract Syntax Tree (AST) specification for
//! synthesizing Cisco Skinny Client Control Protocol (SCCP) VoIP terminal signaling frames over
//! TCP port 2000. On the wire, each SCCP message uses a 12-byte little-endian header (`DataLength`
//! covering Message ID plus body, `HeaderVersion` reserved/version `u32`, and 32-bit `MessageID`),
//! followed by little-endian message payloads for registration (`Register` `0x0001`, `RegisterAck`
//! `0x0081`), keepalives (`KeepAlive` `0x0000`, `KeepAliveAck` `0x0100`), call control (`OffHook`,
//! `OnHook`, `KeypadButton`, `CallState`), tones (`StartTone`, `StopTone`), and RTP media setup
//! (`OpenReceiveChannel`, `OpenReceiveChannelAck`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b sccp [register | registerack | keepalive | keepaliveack | offhook | onhook | keypadbutton | callstate | starttone | stoptone | openreceivechannel | openreceivechannelack | msgtype <str>] [version <u32>] [devicename <str>] [line <u32>] [callid <u32>] [state <u32>] [button <u32>] [tone <u32>] [addr <ip>] [mediaport <u16>]`

use core::net::IpAddr;

/// Cisco Skinny Client Control Protocol (SCCP) specification.
///
/// Syntax mapping: `sccp [register | registerack | keepalive | keepaliveack | offhook | onhook | keypadbutton | callstate | starttone | stoptone | openreceivechannel | openreceivechannelack | msgtype <str>] [version <u32>] [devicename <str>] [line <u32>] [callid <u32>] [state <u32>] [button <u32>] [tone <u32>] [addr <ip>] [mediaport <u16>]`
#[doc(alias = "sccp")]
#[doc(alias = "skinny")]
#[doc(alias = "Cisco Skinny")]
#[doc(alias = "2000")]
#[doc(alias = "register")]
#[doc(alias = "registerack")]
#[doc(alias = "keepalive")]
#[doc(alias = "keepaliveack")]
#[doc(alias = "offhook")]
#[doc(alias = "onhook")]
#[doc(alias = "keypadbutton")]
#[doc(alias = "callstate")]
#[doc(alias = "starttone")]
#[doc(alias = "stoptone")]
#[doc(alias = "openreceivechannel")]
#[doc(alias = "openreceivechannelack")]
#[doc(alias = "devicename")]
#[doc(alias = "line")]
#[doc(alias = "callid")]
#[doc(alias = "state")]
#[doc(alias = "button")]
#[doc(alias = "tone")]
#[doc(alias = "addr")]
#[doc(alias = "mediaport")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SccpSpec<'a> {
    /// Skinny message name (`register`, `registerack`, `keepalive`, `keepaliveack`, `offhook`, `onhook`, `keypadbutton`, `callstate`, `starttone`, `stoptone`, `openreceivechannel`, `openreceivechannelack`).
    pub msg_type: Option<&'a str>,
    /// Little-endian Skinny header version (`0` for Basic Skinny).
    pub header_version: Option<u32>,
    /// 16-byte null-padded Cisco endpoint device name (`devicename <str>`, e.g., `"SEP001122334455"`).
    pub device_name: Option<&'a str>,
    /// Station line instance identifier (`line <u32>`, default `1`).
    pub line: Option<u32>,
    /// Call identifier or conference ID (`callid <u32>`, default `100`).
    pub call_id: Option<u32>,
    /// Skinny call state code for `CallStateMessage` (`state <u32>`, default `1`).
    pub call_state: Option<u32>,
    /// Keypad button digit code for `KeypadButtonMessage` (`button <u32>`, default `1`).
    pub button: Option<u32>,
    /// Tone identifier for `StartToneMessage` (`tone <u32>`, default `0x21` InsideDialTone).
    pub tone: Option<u32>,
    /// IPv4 address for `RegisterMessage` or `OpenReceiveChannelAck` (`addr <ip>`).
    pub addr: Option<IpAddr>,
    /// RTP media UDP port for `OpenReceiveChannelAck` (`mediaport <u16>`, default `20000`).
    pub media_port: Option<u16>,
}
