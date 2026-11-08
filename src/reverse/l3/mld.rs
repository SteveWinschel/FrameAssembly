//! Multicast Listener Discovery (MLDv1 RFC 2710 & MLDv2 RFC 3810) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IPv6 Multicast Listener
//! Discovery (`MLD`, carried over ICMPv6 Next Header `58` with message types `130..=132` and
//! `143`). It decodes `query` (`130`), `report` (`131` and MLDv2 `143`), and `done` (`132`)
//! messages along with the target IPv6 `multicast_addr` and `max_resp_delay` into canonical `.fasm`
//! statements while preserving any trailing options or group records as residual payload.

use alloc::string::String;
use core::net::Ipv6Addr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, ipv6_at, push_if, sd};

/// Decompiles an RFC 2710 / RFC 3810 IPv6 `MLD` message (`130..=132`, `143`) into a [`ProtocolDissection`].
pub(crate) fn dissect_mld(b: &[u8]) -> ProtocolDissection {
    if b.len() < 24 {
        return sd(Protocol::Mld, String::from("mld"), b.to_vec());
    }
    let is_v2_report = b[0] == 143 && b.len() >= 28;
    let (maddr, mut t) = (
        ipv6_at(b, if is_v2_report { 12 } else { 8 }),
        String::from("mld"),
    );
    let dm = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, if b[0] == 132 { 2 } else { 1 });
    if let Some(kw) = [" query", " report", " done"].get(b[0].wrapping_sub(130) as usize) {
        t.push_str(kw);
    } else if b[0] == 143 {
        t.push_str(" report");
    }
    push_if(&mut t, "multicast_addr", maddr, dm);
    if b[0] != 143 {
        push_if(&mut t, "max_resp_delay", be_u16(b, 4), 0);
    }
    let hdr_len = if is_v2_report { 28 } else { 24 };
    sd(Protocol::Mld, t, b[hdr_len..].to_vec())
}
