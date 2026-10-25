//! IEEE 802.1X Port-Based Network Access Control (EAPOL) and RFC 3748 EAP wire frame builder.
//!
//! Synthesizes IEEE 802.1X EAPOL frames over Ethernet II (`EtherType = 0x888E`) addressed by
//! default to the IEEE 802.1X PAE group multicast MAC `01:80:C2:00:00:03`. Constructs the
//! 4-byte EAPOL header (`Protocol Version`, `Packet Type`, 16-bit big-endian `Body Length`)
//! and, for `EAP-Packet` (`Type = 0`), serializes the nested RFC 3748 EAP header (`Code`,
//! `Identifier`, 16-bit `Length`, `Type/Method`, and optional identity or method data).
//!
//! Canonical `.fasm` syntax:
//! `a -> b EAPOL [VERSION <u8>] [TYPE <EAP_PACKET|START|LOGOFF|KEY>] [EAP_CODE <u8>] [EAP_ID <u8>] [EAP_METHOD <u8>] [IDENTITY "<str>"]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds an IEEE 802.1X EAPOL wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_eapol_frame(
    ctx: &WireContext,
    spec: &EapolSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let version = spec.version.unwrap_or(1);
    let packet_type = spec.packet_type.unwrap_or(EapolType::EapPacket);

    let (type_code, body) = match packet_type {
        EapolType::Start => (1_u8, Vec::new()),
        EapolType::Logoff => (2_u8, Vec::new()),
        EapolType::Key => (3_u8, payload.to_vec()),
        EapolType::EapPacket => {
            let code = spec.eap_code.unwrap_or(1); // 1 = Request, 2 = Response, 3 = Success, 4 = Failure
            let id = spec.eap_id.unwrap_or(1);

            if (code == 3 || code == 4) && payload.is_empty() {
                // RFC 3748 §4.2: EAP Success (3) and Failure (4) are strictly 4 octets with no Type field
                let eap = alloc::vec![code, id, 0x00, 0x04];
                (0_u8, eap)
            } else {
                let method = spec.eap_method.unwrap_or(1); // 1 = Identity
                let identity_bytes = spec.identity.map(|s| s.as_bytes()).unwrap_or(&[]);
                let eap_len = 5 + identity_bytes.len() + payload.len();

                let mut eap = Vec::with_capacity(eap_len);
                eap.push(code);
                eap.push(id);
                eap.extend_from_slice(&(eap_len as u16).to_be_bytes());
                eap.push(method);
                eap.extend_from_slice(identity_bytes);
                eap.extend_from_slice(payload);
                (0_u8, eap)
            }
        }
    };

    let mut eapol = Vec::with_capacity(4 + body.len());
    eapol.push(version);
    eapol.push(type_code);
    eapol.extend_from_slice(&(body.len() as u16).to_be_bytes());
    eapol.extend_from_slice(&body);

    let dst_mac = ctx.l2.dst_mac.unwrap_or([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);
    Ok(build_ethernet_and_l2(ctx.src_mac, dst_mac, ctx.l2, 0x888E, &eapol))
}
