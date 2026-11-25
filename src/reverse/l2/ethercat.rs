//! EtherCAT Industrial Real-Time Protocol (IEC 61158-4-12) PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Beckhoff / ETG EtherCAT
//! frames over both native Layer 2 Ethernet (`0x88A4`) and UDP (`34980`). It validates the
//! 2-byte little-endian EtherCAT Frame Header (`Length`, `Type = 1`) and decodes the encapsulated
//! EtherCAT Datagram fields (`cmd`, `idx`, `adp`, `ado`, `irq`, `wkc`), eliding the default
//! 2-byte zero payload and preserving `transport udp` via `explicit_transport` for UDP frames.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, push_hex, push_if, sd, sd_tp};

/// Maps an 8-bit IEC 61158 EtherCAT command code to its lowercase `.frasm` mnemonic.
fn ecat_cmd_name(cmd: u8) -> Option<&'static str> {
    match cmd {
        0 => Some("nop"),
        1 => Some("aprd"),
        2 => Some("apwr"),
        3 => Some("aprw"),
        4 => Some("fprd"),
        5 => Some("fpwr"),
        6 => Some("fprw"),
        7 => Some("brd"),
        8 => Some("bwr"),
        9 => Some("brw"),
        10 => Some("lrd"),
        11 => Some("lwr"),
        12 => Some("lrw"),
        13 => Some("armw"),
        14 => Some("frmw"),
        _ => None,
    }
}

/// Decompiles an EtherCAT Layer 2 (`0x88A4`) or UDP (`34980`) payload into a [`ProtocolDissection`].
pub(crate) fn dissect_ethercat(b: &[u8], is_udp: bool) -> Option<ProtocolDissection> {
    if b.len() < 14 {
        return None;
    }
    let frame_hdr = u16::from_le_bytes([b[0], b[1]]);
    let frame_type = (frame_hdr >> 12) & 0x0F;
    let total_dgram_len = usize::from(frame_hdr & 0x07FF);
    if frame_type != 1 || total_dgram_len < 12 || 2usize.checked_add(total_dgram_len)? > b.len() {
        return None;
    }

    let dgram = b.get(2..2 + total_dgram_len)?;
    let cmd = *dgram.first()?;
    let idx = *dgram.get(1)?;
    let adp = u16::from_le_bytes([*dgram.get(2)?, *dgram.get(3)?]);
    let ado = u16::from_le_bytes([*dgram.get(4)?, *dgram.get(5)?]);
    let len_flags = u16::from_le_bytes([*dgram.get(6)?, *dgram.get(7)?]);
    let data_len = usize::from(len_flags & 0x07FF);
    let more_follows = (len_flags & 0x8000) != 0;
    let irq = u16::from_le_bytes([*dgram.get(8)?, *dgram.get(9)?]);

    let wkc_off = 10usize.checked_add(data_len)?;
    let dgram_end = wkc_off.checked_add(2)?;
    if more_follows || dgram_end != dgram.len() {
        return None;
    }
    let data = dgram.get(10..wkc_off)?;
    let wkc = u16::from_le_bytes([*dgram.get(wkc_off)?, *dgram.get(wkc_off + 1)?]);

    // Ensure no unexpected non-zero bytes follow the EtherCAT frame
    if b.get(2 + total_dgram_len..)?.iter().any(|&x| x != 0) {
        return None;
    }

    let mut t = String::from("ethercat");
    if cmd != 1 {
        if let Some(name) = ecat_cmd_name(cmd) {
            let _ = write!(t, " cmd \"{name}\"");
        } else {
            let _ = write!(t, " cmd {cmd}");
        }
    }
    push_if(&mut t, "idx", idx, 0);
    push_hex(&mut t, "adp", u64::from(adp), 0, 4);
    push_hex(&mut t, "ado", u64::from(ado), 0, 4);
    push_hex(&mut t, "irq", u64::from(irq), 0, 4);
    push_if(&mut t, "wkc", wkc, 0);

    let res = if data == [0x00, 0x00] {
        Vec::new()
    } else {
        data.to_vec()
    };

    Some(if is_udp {
        sd_tp(Protocol::Ethercat, t, res, TransportProto::Udp)
    } else {
        sd(Protocol::Ethercat, t, res)
    })
}
