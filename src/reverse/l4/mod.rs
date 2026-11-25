//! Layer 4 transport protocol (`tcp`, `udp`, `sctp`) PCAP-to-`.frasm` decompilers.
//!
//! This module organizes the Layer 4 transport header dissectors for FrameAssembly's PCAP and
//! PCAPNG to `.frasm` reverse decompiler pipeline and coordinates SCTP-carried Layer 7 protocol
//! dispatch ([`dissect_sctp_packet`]):
//! - [`tcp`]: RFC 9293 TCP header slicing, sequence/acknowledgment/window extraction, and RFC 7323
//!   option parsing (`mss`, `wscale`, `sackperm`, `tsval`, `tsecr`).
//! - [`udp`]: RFC 768 UDP datagram header slicing and port extraction.
//! - [`sctp`]: RFC 9260 SCTP common header, verification tag (`vtag`), and chunk (`data`, `init`,
//!   `initack`, `sack`, `heartbeat`, `heartbeatack`, `abort`, `shutdown`, `shutdownack`,
//!   `shutdowncomplete`, `cookieecho`, `cookieack`) decompilation.

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::{L4Modifiers, Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, be_u16, be_u32};

pub(crate) mod sctp;
pub(crate) mod tcp;
pub(crate) mod udp;

/// Dissects an RFC 9260 SCTP packet (`ip_proto == 132`), dispatching `DATA` chunks across
/// [`crate::reverse::l3::dissect_l3_over_l4`] and [`crate::reverse::l7::dissect_l7`] for native
/// SCTP (`ngap` PPID `60`, `s1ap` PPID `18`), SCTP-carried L3/L7 (`diameter` PPID `46`, HTTP/2
/// PPID `62`/`63`, `ldp`), and custom-PPID L7 payloads, falling back to raw `sctp` chunks.
pub(crate) fn dissect_sctp_packet(
    b: &[u8],
    is_ipv6: bool,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    l4: &mut L4Modifiers,
    l4_payload: &mut Vec<u8>,
) -> ProtocolDissection {
    if b.len() >= 16 {
        let sp = be_u16(b, 0);
        let dp = be_u16(b, 2);
        let ct = b[12];
        let chunk_end = 12 + (be_u16(b, 14) as usize).clamp(4, b.len() - 12);
        let cb = &b[12..chunk_end];
        if ct == 0 && cb.len() >= 16 {
            let _stream = be_u16(cb, 8);
            let _ssn = be_u16(cb, 10);
            let _ppid = be_u32(cb, 12);
            let data_payload = &cb[16..];
            if !data_payload.is_empty()
                && let Some(mut d) = crate::reverse::l3::dissect_l3_over_l4(
                    TransportProto::Sctp,
                    sp,
                    dp,
                    data_payload,
                    is_ipv6,
                    src_ip,
                )
                .or_else(|| {
                    crate::reverse::l7::dissect_l7(
                        TransportProto::Sctp,
                        sp,
                        dp,
                        data_payload,
                        is_ipv6,
                        dst_ip,
                    )
                })
            {
                let native_sctp = matches!(d.protocol, Protocol::Ngap | Protocol::S1ap);
                if native_sctp {
                    d.explicit_transport = None;
                    l4.transport = None;
                } else {
                    d.explicit_transport = Some(TransportProto::Sctp);
                    l4.transport = Some(TransportProto::Sctp);
                }
                l4.src_port = Some(sp);
                l4.dst_port = Some(dp);
                l4.sctp_params = None;
                *l4_payload = data_payload.to_vec();
                return d;
            }
        }
    }
    sctp::dissect_sctp(b, l4, l4_payload)
}
