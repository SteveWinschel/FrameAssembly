//! Segment Routing over IPv6 (SRv6 Segment Routing Header, RFC 8754) PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 8754 IPv6 Segment
//! Routing Headers carried under IPv6 Next Header `43` with `Routing Type = 4`. It parses
//! `Next Header`, `Hdr Ext Len`, `Segments Left` (`segleft`), `Last Entry`, `Flags` (`flags`),
//! `Tag` (`tag`), and the 128-bit Segment List (`sid`), eliding default single-SID destination
//! matches and `No Next Header` (`59`) to roundtrip cleanly.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, ipv6_at, push_if, sd};

/// Decompiles an RFC 8754 `srv6` Segment Routing Header (`ip_proto == 43`, Routing Type `4`) into [`ProtocolDissection`].
pub(crate) fn dissect_srv6(
    b: &[u8],
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if b.len() < 24 || b[2] != 4 {
        return None;
    }
    let ext_len = 8usize.saturating_add(usize::from(b[1]).saturating_mul(8));
    if ext_len < 24 || b.len() < ext_len {
        return None;
    }
    let nh = b[0];
    let seg_left = b[3];
    let last_entry = b[4];
    let flags = b[5];
    let tag = be_u16(b, 6);

    let sid_count = usize::from(last_entry).saturating_add(1);
    let sids_end = 8usize.saturating_add(sid_count.saturating_mul(16));
    if sids_end > ext_len {
        return None;
    }

    let mut sids = Vec::with_capacity(sid_count);
    for idx in 0..sid_count {
        let off = 8 + idx * 16;
        sids.push(ipv6_at(b, off));
    }

    let default_sid = match dst_ip {
        Some(IpAddr::V6(d6)) if !d6.is_unspecified() => d6,
        _ => Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2),
    };

    let mut t = String::from("srv6");
    if !(sids.len() == 1 && sids[0] == default_sid) {
        for sid in &sids {
            let _ = write!(t, " sid {sid}");
        }
    }
    push_if(&mut t, "segleft", seg_left, last_entry);
    push_if(&mut t, "flags", flags, 0);
    push_if(&mut t, "tag", tag, 0);

    let rem = b.get(ext_len..).unwrap_or(&[]);
    let res = if nh == 58
        && let (Some(IpAddr::V6(s6)), Some(first_sid)) = (src_ip, sids.first())
        && rem
            == crate::builders::l3::srv6::default_srv6_icmpv6_echo(
                s6.octets(),
                first_sid.octets(),
            )
            .as_slice()
    {
        Vec::new()
    } else {
        rem.to_vec()
    };

    let expected_nh = if res.is_empty() { 59 } else { 253 };
    push_if(&mut t, "nextheader", nh, expected_nh);

    Some(sd(Protocol::Srv6, t, res))
}
