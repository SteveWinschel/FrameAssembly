//! EAPOL Layer 2 protocol wire builder.

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
            let code = spec.eap_code.unwrap_or(1); // 1 = Request, 2 = Response
            let id = spec.eap_id.unwrap_or(1);
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
    };

    let mut eapol = Vec::with_capacity(4 + body.len());
    eapol.push(version);
    eapol.push(type_code);
    eapol.extend_from_slice(&(body.len() as u16).to_be_bytes());
    eapol.extend_from_slice(&body);

    let dst_mac = ctx.l2.dst_mac.unwrap_or([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);
    Ok(build_ethernet_and_l2(ctx.src_mac, dst_mac, ctx.l2, 0x888E, &eapol))
}
