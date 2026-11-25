//! Virtual Network Computing Remote Framebuffer Protocol (VNC / RFB 003.008, RFC 6143) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Remote Framebuffer (`vnc`) protocol frames over TCP port 5900. On the wire, the protocol uses
//! 12-byte ASCII `RFB 003.008\n` version handshakes, RFC 6143 security type lists and result
//! statuses, `ClientInit` and `ServerInit` framebuffer pixel-format negotiation messages, and
//! client/server interaction PDUs (`SetEncodings`, `FramebufferUpdateRequest`, `KeyEvent`,
//! `PointerEvent`, and `Bell`). Every field in [`VncSpec`] is optional so authors can emit
//! zero-configuration default frames or override specific RFB fields.
//!
//! Canonical `.frasm` syntax:
//! `a -> b vnc [msgtype <str>] [version <str>] [securitytype <u8>] [width <u16>] [height <u16>] [desktop <str>] [key <u32>] [flags <u8>] [xpos <u16>] [ypos <u16>]`

/// RFC 6143 Remote Framebuffer (VNC) specification.
///
/// Syntax mapping: `vnc [msgtype <str>] [version <str>] [securitytype <u8>] [width <u16>] [height <u16>] [desktop <str>] [key <u32>] [flags <u8>] [xpos <u16>] [ypos <u16>]`
#[doc(alias = "vnc")]
#[doc(alias = "RFB")]
#[doc(alias = "RFC 6143")]
#[doc(alias = "RFC6143")]
#[doc(alias = "msgtype")]
#[doc(alias = "version")]
#[doc(alias = "securitytype")]
#[doc(alias = "width")]
#[doc(alias = "height")]
#[doc(alias = "desktop")]
#[doc(alias = "key")]
#[doc(alias = "flags")]
#[doc(alias = "xpos")]
#[doc(alias = "ypos")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VncSpec<'a> {
    /// RFB message kind (`msgtype <str>`, e.g., `"version"`, `"security"`, `"serverinit"`, `"keyevent"`).
    pub msg_type: Option<&'a str>,
    /// RFB protocol version string (`version <str>`, default `"003.008"`).
    pub version: Option<&'a str>,
    /// RFB security type code (`securitytype <u8>`, e.g., `1` None, `2` VNC Auth).
    pub security_type: Option<u8>,
    /// Framebuffer width in pixels (`width <u16>`, default `1024`).
    pub width: Option<u16>,
    /// Framebuffer height in pixels (`height <u16>`, default `768`).
    pub height: Option<u16>,
    /// Desktop name reported in `ServerInit` (`desktop <str>`, default `"FrameAssembly"`).
    pub desktop: Option<&'a str>,
    /// X11 keysym code for `KeyEvent` (`key <u32>`, default `0x0061`).
    pub key: Option<u32>,
    /// Message flag byte for `ClientInit`, `KeyEvent`, `PointerEvent`, `FramebufferUpdateRequest`, or `SecurityResult` (`flags <u8>`).
    pub flags: Option<u8>,
    /// Horizontal pointer or update rectangle coordinate (`xpos <u16>`, default `0`).
    pub xpos: Option<u16>,
    /// Vertical pointer or update rectangle coordinate (`ypos <u16>`, default `0`).
    pub ypos: Option<u16>,
}
