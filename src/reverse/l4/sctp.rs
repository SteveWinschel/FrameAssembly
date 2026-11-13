//! Stream Control Transmission Protocol (SCTP, RFC 9260) Layer 4 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 9260 Stream Control
//! Transmission Protocol (`sctp`, IP protocol `132`) packets in FrameAssembly. It decodes the
//! 12-byte SCTP common header (`srcport`, `dstport`, 32-bit verification tag `vtag`) and primary
//! chunk descriptor (`data`, `init`, `initack`, `sack`, `heartbeat`, `heartbeatack`, `abort`,
//! `shutdown`, `shutdownack`, `cookieecho`, `cookieack`) including `data` stream (`stream`),
//! sequence number (`ssn`), and payload protocol identifier (`ppid`).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{L4Modifiers, Protocol, SctpParams};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, push_if, sd};

/// Decompiles an RFC 9260 `sctp` packet (`ip_proto == 132`) into a [`ProtocolDissection`].
pub(crate) fn dissect_sctp(
    b: &[u8],
    l4: &mut L4Modifiers,
    l4_payload: &mut Vec<u8>,
) -> ProtocolDissection {
    if b.len() < 16 {
        return sd(Protocol::Sctp, String::from("sctp"), b.to_vec());
    }
    l4.src_port = Some(be_u16(b, 0));
    l4.dst_port = Some(be_u16(b, 2));
    let (vtag, ct) = (be_u32(b, 4), b[12]);
    let cb = &b[12..12 + (be_u16(b, 14) as usize).clamp(4, b.len() - 12)];
    let (mut t, mut params, mut res) = (String::from("sctp"), SctpParams::default(), Vec::new());

    match ct {
        0 if cb.len() >= 16 => {
            t.push_str(" data");
            let (stream, ssn, ppid) = (be_u16(cb, 8), be_u16(cb, 10), be_u32(cb, 12));
            push_if(&mut t, "stream", stream, 0);
            push_if(&mut t, "ssn", ssn, 0);
            push_if(&mut t, "ppid", ppid, 0);
            params.chunk = Some(String::from("data"));
            params.stream = (stream != 0).then_some(stream);
            params.ssn = (ssn != 0).then_some(ssn);
            params.ppid = (ppid != 0).then_some(ppid);
            res.extend_from_slice(&cb[16..]);
        }
        1 | 2 => {
            t.push_str(if ct == 1 { " init" } else { " initack" });
            params.chunk = Some(String::from(if ct == 1 { "init" } else { "initack" }));
        }
        3 => {
            t.push_str(" sack");
            params.chunk = Some(String::from("sack"));
        }
        4 | 5 | 10 => {
            let (kw, ch) = match ct {
                4 => (" heartbeat", "heartbeat"),
                5 => (" heartbeatack", "heartbeatack"),
                _ => (" cookieecho", "cookieecho"),
            };
            t.push_str(kw);
            params.chunk = Some(String::from(ch));
            res.extend_from_slice(cb.get(4..).unwrap_or(&[]));
        }
        6 | 8 | 11 => {
            let (kw, ch) = match ct {
                6 => (" abort", "abort"),
                8 => (" shutdownack", "shutdownack"),
                _ => (" cookieack", "cookieack"),
            };
            t.push_str(kw);
            params.chunk = Some(String::from(ch));
        }
        7 => {
            t.push_str(" shutdown");
            params.chunk = Some(String::from("shutdown"));
        }
        _ => res.extend_from_slice(cb.get(4..).unwrap_or(&[])),
    }
    if vtag != 0 {
        let _ = write!(t, " vtag 0x{vtag:08x}");
        params.vtag = Some(vtag);
    }
    l4.sctp_params = Some(params);
    *l4_payload = res.clone();
    sd(Protocol::Sctp, t, res)
}
