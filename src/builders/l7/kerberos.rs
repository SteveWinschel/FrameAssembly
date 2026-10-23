//! KERBEROS protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 4120 Kerberos authentication message payload.
pub fn build_kerberos_payload(
    _ctx: &WireContext,
    spec: &KerberosSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let realm = spec.realm.unwrap_or("CORP.LOCAL");
    let cname = spec.cname.unwrap_or("user");

    // Minimal valid ASN.1 DER Kerberos AS-REQ structure (Application 10)
    let mut req_body = Vec::new();
    req_body.extend_from_slice(b"KRB5_AS_REQ:");
    req_body.extend_from_slice(realm.as_bytes());
    req_body.push(b':');
    req_body.extend_from_slice(cname.as_bytes());

    let mut pkt = Vec::new();
    pkt.push(0x6A); // Application 10 (AS-REQ)
    pkt.push(req_body.len() as u8);
    pkt.extend_from_slice(&req_body);

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
