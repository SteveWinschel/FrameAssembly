//! Two-Way Active Measurement Protocol (`twamp`, RFC 5357) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 5357 `twamp` measurement and
//! control messages carried over UDP port `862` (`TWAMP-Test` Session-Sender and Session-Reflector
//! packets) and TCP port `862` (`TWAMP-Control` `greeting`, `setupresponse`, `serverstart`,
//! `requestsession`, `acceptsession`, `startsessions`, `startack`, and `stopsessions`). It
//! preserves explicit `transport tcp` when dissecting TCP control frames and elides default
//! `seqnum`, `timestamp`, `errorestimate`, `senderttl`, and `27`-byte padding values.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, be_u64, sd, sd_tp};

/// Dissects an RFC 5357 `twamp` UDP (`TWAMP-Test`) or TCP (`TWAMP-Control`) packet on port `862`.
pub(crate) fn dissect_twamp(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if src_port != 862 && dst_port != 862 {
        return None;
    }
    match transport {
        TransportProto::Tcp => dissect_twamp_control(payload),
        TransportProto::Udp => dissect_twamp_test(payload),
        TransportProto::Sctp => None,
    }
}

/// Dissects a TCP port `862` TWAMP-Control signaling message.
fn dissect_twamp_control(payload: &[u8]) -> Option<ProtocolDissection> {
    match payload.len() {
        64 if payload.get(0..12) == Some(&[0u8; 12])
            && payload.get(16..48) == Some(&[0u8; 32])
            && payload.get(52..64) == Some(&[0u8; 12]) =>
        {
            let mode = be_u32(payload, 12);
            let count = be_u32(payload, 48);
            if mode == 0 {
                return None;
            }
            let mut tokens = String::from("twamp greeting");
            if mode != 1 {
                let _ = write!(tokens, " mode {mode}");
            }
            if count != 1024 {
                let _ = write!(tokens, " count {count}");
            }
            Some(sd_tp(Protocol::Twamp, tokens, Vec::new(), TransportProto::Tcp))
        }
        164 if payload.get(4..164) == Some(&[0u8; 160]) => {
            let mode = be_u32(payload, 0);
            if mode == 0 {
                return None;
            }
            let mut tokens = String::from("twamp setupresponse");
            if mode != 1 {
                let _ = write!(tokens, " mode {mode}");
            }
            Some(sd_tp(Protocol::Twamp, tokens, Vec::new(), TransportProto::Tcp))
        }
        48 if payload.get(0..15) == Some(&[0u8; 15])
            && payload.get(16..32) == Some(&[0u8; 16])
            && payload.get(40..48) == Some(&[0u8; 8]) =>
        {
            let status = payload[15];
            let ts = be_u64(payload, 32);
            let mut tokens = String::from("twamp serverstart");
            if status != 0 {
                let _ = write!(tokens, " status {status}");
            }
            if ts != 0 {
                let _ = write!(tokens, " timestamp 0x{ts:016x}");
            }
            Some(sd_tp(Protocol::Twamp, tokens, Vec::new(), TransportProto::Tcp))
        }
        48 if payload[1] == 0 && payload.get(4..48) == Some(&[0u8; 44]) => {
            let status = payload[0];
            let port = be_u16(payload, 2);
            if port == 0 && status == 0 {
                return None;
            }
            let mut tokens = String::from("twamp acceptsession");
            if status != 0 {
                let _ = write!(tokens, " status {status}");
            }
            if port != 862 {
                let _ = write!(tokens, " port {port}");
            }
            Some(sd_tp(Protocol::Twamp, tokens, Vec::new(), TransportProto::Tcp))
        }
        112 if payload[0] == 5
            && matches!(payload[1], 0x40 | 0x60)
            && payload.get(2..12) == Some(&[0u8; 10])
            && payload.get(48..64) == Some(&[0u8; 16])
            && payload.get(76..112) == Some(&[0u8; 36]) =>
        {
            let port = be_u16(payload, 14);
            let pad = be_u32(payload, 64);
            let ts = be_u64(payload, 68);
            let mut tokens = String::from("twamp requestsession");
            if port != 862 {
                let _ = write!(tokens, " port {port}");
            }
            if pad != 27 {
                let _ = write!(tokens, " padding {pad}");
            }
            if ts != 0 {
                let _ = write!(tokens, " timestamp 0x{ts:016x}");
            }
            Some(sd_tp(Protocol::Twamp, tokens, Vec::new(), TransportProto::Tcp))
        }
        32 if payload[0] == 2 && payload.get(1..32) == Some(&[0u8; 31]) => Some(sd_tp(
            Protocol::Twamp,
            String::from("twamp startsessions"),
            Vec::new(),
            TransportProto::Tcp,
        )),
        32 if payload[0] == 3
            && payload.get(2..4) == Some(&[0, 0])
            && payload.get(8..32) == Some(&[0u8; 24]) =>
        {
            let status = payload[1];
            let count = be_u32(payload, 4);
            let mut tokens = String::from("twamp stopsessions");
            if status != 0 {
                let _ = write!(tokens, " status {status}");
            }
            if count != 1 {
                let _ = write!(tokens, " count {count}");
            }
            Some(sd_tp(Protocol::Twamp, tokens, Vec::new(), TransportProto::Tcp))
        }
        32 if payload.get(1..32) == Some(&[0u8; 31]) => {
            let status = payload[0];
            let mut tokens = String::from("twamp startack");
            if status != 0 {
                let _ = write!(tokens, " status {status}");
            }
            Some(sd_tp(Protocol::Twamp, tokens, Vec::new(), TransportProto::Tcp))
        }
        _ => None,
    }
}

/// Dissects a UDP port `862` TWAMP-Test Session-Sender or Session-Reflector packet.
fn dissect_twamp_test(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 14 {
        return None;
    }

    let is_reflector = payload.len() >= 41
        && payload.get(14..16) == Some(&[0u8; 2])
        && payload.get(38..40) == Some(&[0u8; 2])
        && payload[40] != 0
        && payload.get(36..38) != Some(&[0u8; 2])
        && be_u32(payload, 0) == be_u32(payload, 24)
        && be_u64(payload, 4) == be_u64(payload, 16)
        && be_u64(payload, 4) == be_u64(payload, 28)
        && be_u16(payload, 12) == be_u16(payload, 36);

    if is_reflector {
        let seq = be_u32(payload, 0);
        let ts = be_u64(payload, 4);
        let err_est = be_u16(payload, 12);
        let sender_ttl = payload[40];
        let tail = &payload[41..];
        let mut tokens = String::from("twamp reflector");
        if seq != 1 {
            let _ = write!(tokens, " seqnum {seq}");
        }
        if ts != 0 {
            let _ = write!(tokens, " timestamp 0x{ts:016x}");
        }
        if err_est != 0x8001 {
            let _ = write!(tokens, " errorestimate 0x{err_est:04x}");
        }
        if sender_ttl != 255 {
            let _ = write!(tokens, " senderttl {sender_ttl}");
        }
        let residual = if !tail.is_empty() && tail.len() <= usize::from(u16::MAX) && tail.iter().all(|&b| b == 0) {
            let _ = write!(tokens, " padding {}", tail.len());
            Vec::new()
        } else {
            tail.to_vec()
        };
        return Some(sd(Protocol::Twamp, tokens, residual));
    }

    let seq = be_u32(payload, 0);
    let ts = be_u64(payload, 4);
    let err_est = be_u16(payload, 12);
    let tail = &payload[14..];

    let mut tokens = String::from("twamp");
    if seq != 1 {
        let _ = write!(tokens, " seqnum {seq}");
    }
    if ts != 0 {
        let _ = write!(tokens, " timestamp 0x{ts:016x}");
    }
    if err_est != 0x8001 {
        let _ = write!(tokens, " errorestimate 0x{err_est:04x}");
    }

    let residual = if tail.len() == 27 && tail.iter().all(|&b| b == 0) {
        Vec::new()
    } else if tail.len() <= usize::from(u16::MAX) && tail.iter().all(|&b| b == 0) {
        let _ = write!(tokens, " padding {}", tail.len());
        Vec::new()
    } else {
        tail.to_vec()
    };

    Some(sd(Protocol::Twamp, tokens, residual))
}
