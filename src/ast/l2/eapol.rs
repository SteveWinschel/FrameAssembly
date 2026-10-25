//! IEEE 802.1X Port-Based Network Access Control (EAPOL) AST definitions.
//!
//! Models Extensible Authentication Protocol over LAN (EAPOL, IEEE 802.1X-2020) frames
//! encapsulated directly in Ethernet II with EtherType `0x888E` and default PAE group
//! destination MAC address `01:80:C2:00:00:03`. The 4-byte EAPOL header contains an 8-bit
//! Protocol Version (`0x01` for 802.1X-2001, `0x02` for 802.1X-2004, `0x03` for 802.1X-2010),
//! an 8-bit Packet Type (`0` EAP-Packet, `1` EAPOL-Start, `2` EAPOL-Logoff, `3` EAPOL-Key),
//! and a 16-bit Packet Body Length, followed by the RFC 3748 EAP message body.
//!
//! Canonical `.fasm` syntax:
//! `a -> b EAPOL [VERSION <u8>] [TYPE <EAP_PACKET|START|LOGOFF|KEY>] [EAP_CODE <u8>] [EAP_ID <u8>] [EAP_METHOD <u8>] [IDENTITY "<str>"]`

/// IEEE 802.1X EAPOL 8-bit packet type field (`Packet Type` at offset 1 of the EAPOL header).
#[doc(alias = "802.1X")]
#[doc(alias = "EAP")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolType {
    /// EAP-Packet (`0x00`), carrying an encapsulated RFC 3748 EAP frame.
    EapPacket,
    /// EAPOL-Start (`0x01`), sent by a supplicant to initiate authentication with the PAE.
    Start,
    /// EAPOL-Logoff (`0x02`), sent by a supplicant to terminate an authenticated session.
    Logoff,
    /// EAPOL-Key (`0x03`), carrying IEEE 802.11i / WPA2 / WPA3 4-Way Handshake key material.
    Key,
}

/// IEEE 802.1X EAPOL and RFC 3748 EAP frame specification.
///
/// Syntax mapping: `EAPOL [VERSION <u8>] [TYPE <EAP_PACKET | START | LOGOFF | KEY>] [EAP_CODE <u8>] [EAP_ID <u8>] [EAP_METHOD <u8>] [IDENTITY "<str>"]`
#[doc(alias = "EAPOL")]
#[doc(alias = "802.1X")]
#[doc(alias = "RFC 3748")]
#[doc(alias = "0x888E")]
#[doc(alias = "EAP_PACKET")]
#[doc(alias = "START")]
#[doc(alias = "LOGOFF")]
#[doc(alias = "KEY")]
#[doc(alias = "EAP_CODE")]
#[doc(alias = "EAP_ID")]
#[doc(alias = "EAP_METHOD")]
#[doc(alias = "IDENTITY")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EapolSpec<'a> {
    /// IEEE 802.1X protocol version (`VERSION <u8>`, typically `1`, `2`, or `3`).
    pub version: Option<u8>,
    /// EAPOL packet type (`TYPE <EAP_PACKET | START | LOGOFF | KEY>`).
    pub packet_type: Option<EapolType>,
    /// RFC 3748 EAP Code (`EAP_CODE <u8>`: `1` Request, `2` Response, `3` Success, `4` Failure).
    pub eap_code: Option<u8>,
    /// RFC 3748 EAP Identifier (`EAP_ID <u8>`) matching requests and responses.
    pub eap_id: Option<u8>,
    /// RFC 3748 EAP Method / Type (`EAP_METHOD <u8>`: `1` Identity, `4` MD5, `13` EAP-TLS, `25` PEAP).
    pub eap_method: Option<u8>,
    /// Optional UTF-8 identity string (`IDENTITY "<str>"`) carried in EAP-Identity payloads.
    pub identity: Option<&'a str>,
}
