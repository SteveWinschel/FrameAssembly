//! Internet Group Management Protocol (IGMPv1/v2/v3, RFC 1112 / 2236 / 3376) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IPv4 Internet Group
//! Management Protocol (`igmp`, IP protocol `2`) multicast group membership packets. It decodes
//! `query` (`0x11`), `v1 report` (`0x12`), `report` (`0x16`), `leave` (`0x17`), and `v3 report`
//! (`0x22`) messages along with `maxresp` and multicast `group` overrides into canonical `.fasm`
//! statements.

use alloc::string::String;
use core::net::Ipv4Addr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, ipv4_at, push_if, sd};

/// Decompiles an RFC 1112 / RFC 2236 / RFC 3376 `igmp` message (`ip_proto == 2`) into a [`ProtocolDissection`].
pub(crate) fn dissect_igmp(b: &[u8]) -> ProtocolDissection {
    if b.len() < 8 {
        return sd(Protocol::Igmp, String::from("igmp"), b.to_vec());
    }
    let (mt, mr, grp, mut t) = (b[0], b[1], ipv4_at(b, 4), String::from("igmp"));
    let (kw, dg) = match mt {
        0x11 => (" query", [224, 0, 0, 1]),
        0x12 => (" v1 report", [239, 1, 1, 1]),
        0x22 => (" v3 report", [224, 0, 0, 22]),
        0x17 => (" leave", [224, 0, 0, 2]),
        _ => (" report", [239, 1, 1, 1]),
    };
    t.push_str(kw);
    if mt == 0x11 {
        push_if(&mut t, "maxresp", mr, 100);
    }
    push_if(&mut t, "group", grp, Ipv4Addr::from(dg));
    sd(Protocol::Igmp, t, b[8..].to_vec())
}
