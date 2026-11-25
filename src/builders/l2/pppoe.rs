//! RFC 2516 PPP over Ethernet (PPPoE) Discovery (`0x8863`) and Session (`0x8864`) wire builder.
//!
//! Synthesizes RFC 2516 PPPoE Discovery (`PADI = 0x09`, `PADO = 0x07`, `PADR = 0x19`,
//! `PADS = 0x65`, `PADT = 0xA7` over `EtherType = 0x8863`) and PPPoE Session (`Code = 0x00` over
//! `EtherType = 0x8864`) frames. Discovery frames serialize TLV tags for `Service-Name`
//! (`0x0101`), `AC-Name` (`0x0102`), `Host-Uniq` (`0x0103`), and `AC-Cookie` (`0x0104`), while
//! Session frames prepend the 16-bit PPP Protocol ID (`0xC021` LCP default) and synthetic PPP
//! payload when `payload` is omitted.
//!
//! Canonical `.frasm` syntax:
//! `a -> b pppoe [padi|pado|padr|pads|padt|session] [sessionid <u16>] [servicename "<str>"] [acname "<str>"] [hostuniq "<hex>"] [accookie "<hex>"] [pppproto <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::format;
use alloc::vec::Vec;

/// Default 8-byte PPP LCP Configure-Request (`MRU = 1492`) for bare `pppoe session`.
pub(crate) const DEFAULT_PPPOE_LCP_STUB: [u8; 8] = [0x01, 0x01, 0x00, 0x08, 0x01, 0x04, 0x05, 0xD4];

/// Default 4-byte PPP IPCP Configure-Request for `pppoe session pppproto 0x8021`.
pub(crate) const DEFAULT_PPPOE_IPCP_STUB: [u8; 4] = [0x01, 0x01, 0x00, 0x04];

/// Deterministic 20-byte IPv4 header stub (`192.0.2.1 -> 192.0.2.2`, proto `59`, valid RFC 1071 csum).
pub(crate) const DEFAULT_PPPOE_IPV4_STUB: [u8; 20] = [
    0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x3B, 0xF4, 0xA8, 192, 0, 2, 1, 192, 0,
    2, 2,
];

/// Appends a big-endian RFC 2516 PPPoE Discovery Tag (`Tag-Type: u16`, `Tag-Length: u16`, `Value`).
fn push_pppoe_tag(out: &mut Vec<u8>, tag_type: u16, value: &[u8]) -> Result<(), CompilerError> {
    let len_u16 = u16::try_from(value.len()).map_err(|_| {
        CompilerError::BackendError(format!(
            "PPPoE tag 0x{tag_type:04x} length ({} bytes) exceeds 16-bit maximum",
            value.len()
        ))
    })?;
    out.extend_from_slice(&tag_type.to_be_bytes());
    out.extend_from_slice(&len_u16.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Builds an RFC 2516 PPPoE Discovery (`0x8863`) or Session (`0x8864`) Ethernet frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if any tag or total PPPoE payload exceeds 65535 bytes.
pub fn build_pppoe_frame(
    ctx: &WireContext,
    spec: &PppoeSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let stage = spec.stage.unwrap_or(PppoeStage::Padi);
    let mut body = Vec::with_capacity(32 + payload.len());

    let (ethertype, code, default_sid) = match stage {
        PppoeStage::Padi => (0x8863_u16, 0x09_u8, 0_u16),
        PppoeStage::Pado => (0x8863_u16, 0x07_u8, 0_u16),
        PppoeStage::Padr => (0x8863_u16, 0x19_u8, 0_u16),
        PppoeStage::Pads => (0x8863_u16, 0x65_u8, 1_u16),
        PppoeStage::Padt => (0x8863_u16, 0xA7_u8, 1_u16),
        PppoeStage::Session => (0x8864_u16, 0x00_u8, 1_u16),
    };
    let sid = spec.session_id.unwrap_or(default_sid);

    if stage == PppoeStage::Session {
        let ppp_proto = spec.ppp_proto.unwrap_or(0xC021);
        body.extend_from_slice(&ppp_proto.to_be_bytes());
        if !payload.is_empty() {
            body.extend_from_slice(payload);
        } else if ppp_proto == 0xC021 {
            body.extend_from_slice(&DEFAULT_PPPOE_LCP_STUB);
        } else if ppp_proto == 0x0021 {
            body.extend_from_slice(&DEFAULT_PPPOE_IPV4_STUB);
        } else if ppp_proto == 0x8021 {
            body.extend_from_slice(&DEFAULT_PPPOE_IPCP_STUB);
        }
    } else {
        if let Some(svc) = spec.service_name {
            push_pppoe_tag(&mut body, 0x0101, svc.as_bytes())?;
        } else if stage != PppoeStage::Padt {
            push_pppoe_tag(&mut body, 0x0101, b"")?;
        }

        if let Some(ac) = spec.ac_name {
            push_pppoe_tag(&mut body, 0x0102, ac.as_bytes())?;
        } else if stage == PppoeStage::Pado {
            push_pppoe_tag(&mut body, 0x0102, b"ac01")?;
        }

        if let Some(hu) = &spec.host_uniq {
            push_pppoe_tag(&mut body, 0x0103, hu)?;
        }
        if let Some(cookie) = &spec.ac_cookie {
            push_pppoe_tag(&mut body, 0x0104, cookie)?;
        }
        body.extend_from_slice(payload);
    }

    let body_len_u16 = u16::try_from(body.len()).map_err(|_| {
        CompilerError::BackendError(format!(
            "PPPoE payload length ({} bytes) exceeds 65535-byte maximum",
            body.len()
        ))
    })?;

    let mut frame = Vec::with_capacity(6 + body.len());
    frame.push(0x11); // Ver 1, Type 1
    frame.push(code);
    frame.extend_from_slice(&sid.to_be_bytes());
    frame.extend_from_slice(&body_len_u16.to_be_bytes());
    frame.extend_from_slice(&body);

    let dst_mac = ctx.l2.dst_mac.unwrap_or_else(|| {
        if stage == PppoeStage::Padi {
            [0xFF; 6]
        } else {
            ctx.dst_mac
        }
    });
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        ethertype,
        &frame,
    ))
}
