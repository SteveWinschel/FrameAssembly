//! LDAP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 4511 LDAP directory protocol message payload.
pub fn build_ldap_payload(
    _ctx: &WireContext,
    spec: &LdapSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let msgid = spec.msgid.unwrap_or(1);
    let base_dn = spec.base_dn.unwrap_or("dc=corp,dc=local");

    let mut op_body = Vec::new();
    if spec.is_search_req {
        // SearchRequest [APPLICATION 3]
        op_body.push(0x63);
        op_body.push((base_dn.len() + 8) as u8);
        op_body.push(0x04); // BaseObject OCTET STRING
        op_body.push(base_dn.len() as u8);
        op_body.extend_from_slice(base_dn.as_bytes());
        op_body.extend_from_slice(&[0x0A, 0x01, 0x02]); // Scope: wholeSubtree
        op_body.extend_from_slice(&[0x0A, 0x01, 0x00]); // Deref: never
    } else {
        // Default: BindRequest [APPLICATION 0]
        op_body.push(0x60);
        op_body.push((base_dn.len() + 7) as u8);
        op_body.extend_from_slice(&[0x02, 0x01, 0x03]); // Version 3
        op_body.push(0x04); // Name
        op_body.push(base_dn.len() as u8);
        op_body.extend_from_slice(base_dn.as_bytes());
        op_body.extend_from_slice(&[0x80, 0x00]); // Simple Authentication (empty)
    }

    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x02, 0x01, msgid as u8]); // messageID
    msg.extend_from_slice(&op_body);

    let mut pkt = Vec::new();
    pkt.push(0x30); // SEQUENCE
    pkt.push(msg.len() as u8);
    pkt.extend_from_slice(&msg);

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
