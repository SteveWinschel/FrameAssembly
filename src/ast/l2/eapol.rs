//! IEEE 802.1X Port-Based Network Access Control (EAPOL) AST definitions.

/// EAPOL packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolType {
    /// EAP-Packet (0)
    EapPacket,
    /// EAPOL-Start (1)
    Start,
    /// EAPOL-Logoff (2)
    Logoff,
    /// EAPOL-Key (3)
    Key,
}

/// IEEE 802.1X EAPOL specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EapolSpec<'a> {
    /// Protocol version.
    pub version: Option<u8>,
    /// EAPOL packet type.
    pub packet_type: Option<EapolType>,
    /// EAP Code (1 Request, 2 Response, 3 Success, 4 Failure).
    pub eap_code: Option<u8>,
    /// EAP Identifier.
    pub eap_id: Option<u8>,
    /// EAP Method / Type (1 Identity, etc.).
    pub eap_method: Option<u8>,
    /// Identity string.
    pub identity: Option<&'a str>,
}
