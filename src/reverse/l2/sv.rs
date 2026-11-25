//! IEC 61850-9-2LE Sampled Values (`sv`, EtherType `0x88BA`) Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe ASN.1 BER PCAP and PCAPNG decompiler for IEC 61850-9-2 /
//! 9-2LE Sampled Values (`sv`, EtherType `0x88BA`) frames in FrameAssembly. It validates the
//! 8-byte SV transport header (`APPID`, `Length`, `Reserved1` Ed2 simulation flag, `Reserved2`)
//! and decodes `[APPLICATION 0]` (`0x60`) `savPdu` -> `seqASDU` (`0xA2`) -> `ASDU` (`0x30`)
//! attributes (`svid`, `datset`, `smpcnt`, `confrev`, `smpsynch`, `smprate`) while eliding the
//! default 64-byte zero `seqOfData` sample array for clean roundtrip decompilation.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::l7::quote_raw_str;
use crate::reverse::{ProtocolDissection, push_hex, push_if, sd};

/// Parses a single ASN.1 BER definite-length TLV `(tag, value, rest)` without panicking.
fn parse_ber_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let b1 = input[1];
    let (len, hdr_len) = if (b1 & 0x80) == 0 {
        (usize::from(b1), 2usize)
    } else {
        let num_octets = usize::from(b1 & 0x7F);
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return None;
        }
        let mut l = 0usize;
        for &byte in input.get(2..2 + num_octets)? {
            l = (l << 8) | usize::from(byte);
        }
        (l, 2 + num_octets)
    };
    let end = hdr_len.checked_add(len)?;
    let val = input.get(hdr_len..end)?;
    let rest = input.get(end..)?;
    Some((tag, val, rest))
}

/// Decompiles an IEC 61850-9-2LE `sv` Ethernet payload (`0x88BA`) into a [`ProtocolDissection`].
pub(crate) fn dissect_sv(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 12 {
        return None;
    }
    let appid = u16::from_be_bytes([b[0], b[1]]);
    let declared_len = usize::from(u16::from_be_bytes([b[2], b[3]]));
    let res1 = u16::from_be_bytes([b[4], b[5]]);
    if declared_len < 10 || declared_len > b.len() {
        return None;
    }

    let apdu_slice = b.get(8..declared_len)?;
    let (sav_tag, mut sav_cursor, trailing) = parse_ber_tlv(apdu_slice)?;
    if sav_tag != 0x60 || !trailing.is_empty() {
        return None;
    }

    let mut seq_asdu: Option<&[u8]> = None;
    while !sav_cursor.is_empty() {
        let (tag, val, next) = parse_ber_tlv(sav_cursor)?;
        sav_cursor = next;
        if tag == 0xA2 {
            seq_asdu = Some(val);
        }
    }

    let (asdu_tag, mut asdu_cursor, _) = parse_ber_tlv(seq_asdu?)?;
    if asdu_tag != 0x30 {
        return None;
    }

    let mut sv_id: Option<&str> = None;
    let mut dat_set: Option<&str> = None;
    let mut smp_cnt: Option<u16> = None;
    let mut conf_rev: Option<u32> = None;
    let mut smp_synch: Option<u8> = None;
    let mut smp_rate: Option<u16> = None;
    let mut seq_data: Option<&[u8]> = None;

    while !asdu_cursor.is_empty() {
        let (tag, val, next) = parse_ber_tlv(asdu_cursor)?;
        asdu_cursor = next;
        match tag {
            0x80 => sv_id = Some(core::str::from_utf8(val).ok()?),
            0x81 => dat_set = Some(core::str::from_utf8(val).ok()?),
            0x82 if val.len() == 2 => smp_cnt = Some(u16::from_be_bytes([val[0], val[1]])),
            0x83 if val.len() == 4 => {
                conf_rev = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
            }
            0x85 if !val.is_empty() => smp_synch = Some(val[0]),
            0x86 if val.len() == 2 => smp_rate = Some(u16::from_be_bytes([val[0], val[1]])),
            0x87 => seq_data = Some(val),
            _ => {}
        }
    }

    let mut t = String::from("sv");
    push_hex(&mut t, "appid", u64::from(appid), 0x4000, 4);
    if let Some(id) = sv_id
        && id != "IED1MU01"
    {
        let _ = write!(t, " svid \"{}\"", quote_raw_str(id));
    }
    if let Some(ds) = dat_set {
        let _ = write!(t, " datset \"{}\"", quote_raw_str(ds));
    }
    if let Some(cnt) = smp_cnt {
        push_if(&mut t, "smpcnt", cnt, 0);
    }
    if let Some(cr) = conf_rev {
        push_if(&mut t, "confrev", cr, 1);
    }
    if let Some(synch) = smp_synch {
        push_if(&mut t, "smpsynch", synch, 2);
    }
    if let Some(rate) = smp_rate {
        let _ = write!(t, " smprate {rate}");
    }
    if (res1 & 0x8000) != 0 {
        t.push_str(" simulation");
    }

    let residual = match seq_data {
        Some(d) if d.len() == 64 && d.iter().all(|&x| x == 0) => Vec::new(),
        Some(d) => d.to_vec(),
        None => Vec::new(),
    };

    Some(sd(Protocol::Sv, t, residual))
}
