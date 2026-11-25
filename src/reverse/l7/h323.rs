//! ITU-T H.323 / H.225.0 Call Signaling and RAS Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for ITU-T H.323 (`h323`) signaling
//! traffic across both TCP port `1720` (RFC 1006 TPKT + ITU-T Q.931 + X.691 Aligned PER
//! `H323-UserInformation` in IE `0x7E`) and UDP port `1719` (H.225.0 `RasMessage` PDUs `grq`,
//! `gcf`, `rrq`, `rcf`, `drq`, and `dcf`). It safely validates TPKT/Q.931 lengths and PER bit
//! boundaries, elides default fields, preserves non-default transports, and extracts embedded
//! `user-data` or trailing payload octets.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, sd_tp};

use super::quote_raw_str;

/// ITU-T H.225.0 v4 protocolIdentifier OID `0.0.8.2250.0.4`.
const H225_OID: [u8; 6] = [0x00, 0x08, 0x91, 0x4A, 0x00, 0x04];

/// Fixed 16-byte default H.225.0 ConferenceIdentifier.
const DEFAULT_CONF_ID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

/// Bounds-checked ITU-T X.691 Basic Aligned PER bit reader.
struct PerReader<'a> {
    /// Input PER octet slice.
    buf: &'a [u8],
    /// Current byte index into `buf`.
    byte_idx: usize,
    /// Current bit index inside `buf[byte_idx]` (`0..8`, MSB-first).
    bit_idx: u8,
}

impl<'a> PerReader<'a> {
    /// Creates a new Aligned PER reader starting at bit 0 of byte 0.
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    /// Reads a single bit, returning `None` if exhausted.
    fn read_bit(&mut self) -> Option<u8> {
        let byte = *self.buf.get(self.byte_idx)?;
        let bit = (byte >> (7 - self.bit_idx)) & 1;
        self.bit_idx += 1;
        if self.bit_idx == 8 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }
        Some(bit)
    }

    /// Reads `count` bits (`<= 32`) MSB-first.
    fn read_bits(&mut self, count: u8) -> Option<u32> {
        let mut out = 0u32;
        for _ in 0..count {
            out = (out << 1) | u32::from(self.read_bit()?);
        }
        Some(out)
    }

    /// Advances to the next octet boundary when mid-byte.
    fn align(&mut self) {
        if self.bit_idx != 0 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }
    }

    /// Reads an octet-aligned byte.
    fn read_octet(&mut self) -> Option<u8> {
        self.align();
        let b = *self.buf.get(self.byte_idx)?;
        self.byte_idx += 1;
        Some(b)
    }

    /// Reads `len` octet-aligned bytes.
    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        self.align();
        let end = self.byte_idx.checked_add(len)?;
        let slice = self.buf.get(self.byte_idx..end)?;
        self.byte_idx = end;
        Some(slice)
    }

    /// Reads a constrained whole number within `lb..=ub`.
    fn read_constrained_int(&mut self, lb: u32, ub: u32) -> Option<u32> {
        let range = ub.checked_sub(lb)?.checked_add(1)?;
        let offset = if range <= 1 {
            0
        } else if range <= 255 {
            let bits = (32 - (range - 1).leading_zeros()) as u8;
            self.read_bits(bits)?
        } else if range == 256 {
            u32::from(self.read_octet()?)
        } else if range <= 65536 {
            let b = self.read_bytes(2)?;
            u32::from(u16::from_be_bytes([b[0], b[1]]))
        } else {
            return None;
        };
        if offset >= range {
            return None;
        }
        Some(lb + offset)
    }

    /// Reads an Aligned PER OID and verifies it matches [`H225_OID`].
    fn expect_h225_oid(&mut self) -> Option<()> {
        let len = usize::from(self.read_octet()?);
        let oid = self.read_bytes(len)?;
        (oid == H225_OID).then_some(())
    }

    /// Consumes a minimal terminal `EndpointType` structure.
    fn read_endpoint_type(&mut self) -> Option<()> {
        if self.read_bit()? != 0 || self.read_bits(6)? != 0b000001 {
            return None;
        }
        if self.read_bit()? != 0 || self.read_bit()? != 0 {
            return None;
        }
        if self.read_bit()? != 0 || self.read_bit()? != 0 {
            return None;
        }
        Some(())
    }

    /// Consumes an H.221 `VendorIdentifier`.
    fn read_vendor_id(&mut self) -> Option<()> {
        if self.read_bit()? != 0 || self.read_bits(2)? != 0 || self.read_bit()? != 0 {
            return None;
        }
        let _ = self.read_constrained_int(0, 255)?;
        let _ = self.read_constrained_int(0, 255)?;
        let _ = self.read_constrained_int(0, 65535)?;
        Some(())
    }

    /// Reads an IPv4 `TransportAddress` `(IpAddr, port)`.
    fn read_transport_addr_ipv4(&mut self) -> Option<(IpAddr, u16)> {
        if self.read_bit()? != 0 || self.read_bits(3)? != 0 {
            return None;
        }
        let ip_b = self.read_bytes(4)?;
        let port = self.read_constrained_int(0, 65535)? as u16;
        Some((IpAddr::V4(Ipv4Addr::new(ip_b[0], ip_b[1], ip_b[2], ip_b[3])), port))
    }

    /// Returns the total number of bytes consumed (aligning partial trailing bits).
    fn consumed_bytes(&self) -> usize {
        if self.bit_idx == 0 {
            self.byte_idx
        } else {
            self.byte_idx + 1
        }
    }
}

/// Dissects H.225.0 Call Signaling User-User PER payload, returning `Some(user_data)`.
fn dissect_h225_cs_uuie(uuie: &[u8], expected_choice: u32) -> Option<Vec<u8>> {
    let mut r = PerReader::new(uuie);
    if r.read_bit()? != 0 {
        return None;
    }
    let has_user_data = r.read_bit()? == 1;
    if r.read_bit()? != 0 || r.read_bit()? != 0 || r.read_bit()? != 0 {
        return None;
    }
    let choice = r.read_bits(3)?;
    if choice != expected_choice {
        return None;
    }
    match choice {
        0 => {
            if r.read_bit()? != 0 || r.read_bits(7)? != 0 {
                return None;
            }
            r.expect_h225_oid()?;
            r.read_endpoint_type()?;
            if r.read_bit()? != 0 || r.read_bytes(16)? != DEFAULT_CONF_ID {
                return None;
            }
            if r.read_bit()? != 0 || r.read_bits(2)? != 0 {
                return None;
            }
            if r.read_bit()? != 0 || r.read_bits(2)? != 0 {
                return None;
            }
        }
        1 | 3 => {
            if r.read_bit()? != 0 || r.read_bit()? != 0 {
                return None;
            }
            r.expect_h225_oid()?;
            r.read_endpoint_type()?;
        }
        2 => {
            if r.read_bit()? != 0 || r.read_bit()? != 0 {
                return None;
            }
            r.expect_h225_oid()?;
            r.read_endpoint_type()?;
            if r.read_bytes(16)? != DEFAULT_CONF_ID {
                return None;
            }
        }
        4 | 5 => {
            if r.read_bit()? != 0 || r.read_bit()? != 0 {
                return None;
            }
            r.expect_h225_oid()?;
        }
        _ => return None,
    }
    let user_data = if has_user_data {
        let disc = r.read_constrained_int(0, 255)?;
        if disc != 5 {
            return None;
        }
        let ud_len = usize::try_from(r.read_constrained_int(0, 130)? + 1).ok()?;
        r.read_bytes(ud_len)?.to_vec()
    } else {
        Vec::new()
    };
    if r.consumed_bytes() != uuie.len() {
        return None;
    }
    Some(user_data)
}

/// Dissected H.225.0 RAS summary tuple `(keyword, seq_num, ras_addr, call_ref, default_port)`.
type H225RasSummary = (&'static str, u16, Option<(IpAddr, u16)>, Option<u16>, u16);

/// Dissects an H.225.0 RAS PER message on UDP `1719` (or explicit RAS transport).
fn dissect_h225_ras(
    transport: TransportProto,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    let mut r = PerReader::new(payload);
    if r.read_bit()? != 0 {
        return None;
    }
    let choice = r.read_bits(5)?;
    let (kw, seq_num, addr_opt, call_ref_opt, def_port): H225RasSummary = match choice {
        0 => {
            if r.read_bit()? != 0 || r.read_bits(4)? != 0 {
                return None;
            }
            let seq = r.read_constrained_int(1, 65535)? as u16;
            r.expect_h225_oid()?;
            let addr = r.read_transport_addr_ipv4()?;
            r.read_endpoint_type()?;
            ("grq", seq, Some(addr), None, 1719)
        }
        1 => {
            if r.read_bit()? != 0 || r.read_bits(2)? != 0 {
                return None;
            }
            let seq = r.read_constrained_int(1, 65535)? as u16;
            r.expect_h225_oid()?;
            let addr = r.read_transport_addr_ipv4()?;
            ("gcf", seq, Some(addr), None, 1719)
        }
        3 => {
            if r.read_bit()? != 0 || r.read_bits(3)? != 0 {
                return None;
            }
            let seq = r.read_constrained_int(1, 65535)? as u16;
            r.expect_h225_oid()?;
            if r.read_bit()? != 0 || r.read_octet()? != 1 {
                return None;
            }
            let _cs_addr = r.read_transport_addr_ipv4()?;
            if r.read_octet()? != 1 {
                return None;
            }
            let ras_addr = r.read_transport_addr_ipv4()?;
            r.read_endpoint_type()?;
            r.read_vendor_id()?;
            ("rrq", seq, Some(ras_addr), None, 1719)
        }
        4 => {
            if r.read_bit()? != 0 || r.read_bits(3)? != 0 {
                return None;
            }
            let seq = r.read_constrained_int(1, 65535)? as u16;
            r.expect_h225_oid()?;
            if r.read_octet()? != 1 {
                return None;
            }
            let addr = r.read_transport_addr_ipv4()?;
            if r.read_constrained_int(0, 127)? != 0 || r.read_bytes(2)? != [0x00, b'1'] {
                return None;
            }
            ("rcf", seq, Some(addr), None, 1720)
        }
        15 => {
            if r.read_bit()? != 0 || r.read_bit()? != 0 {
                return None;
            }
            let seq = r.read_constrained_int(1, 65535)? as u16;
            if r.read_constrained_int(0, 127)? != 0 || r.read_bytes(2)? != [0x00, b'1'] {
                return None;
            }
            if r.read_bytes(16)? != DEFAULT_CONF_ID {
                return None;
            }
            let crv = r.read_constrained_int(0, 65535)? as u16;
            if r.read_bit()? != 0 || r.read_bits(2)? != 0 {
                return None;
            }
            ("drq", seq, None, Some(crv), 1719)
        }
        16 => {
            if r.read_bit()? != 0 || r.read_bit()? != 0 {
                return None;
            }
            let seq = r.read_constrained_int(1, 65535)? as u16;
            ("dcf", seq, None, None, 1719)
        }
        _ => return None,
    };

    let consumed = r.consumed_bytes();
    let residual = payload.get(consumed..)?.to_vec();
    let mut tokens = format!("h323 {kw}");
    if seq_num != 1 {
        let _ = write!(tokens, " seqnum {seq_num}");
    }
    if let Some((ip, port)) = addr_opt {
        let is_def = ip == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)) && port == def_port;
        if !is_def {
            if port == def_port {
                let _ = write!(tokens, " rasaddr {ip}");
            } else {
                let _ = write!(tokens, " rasaddr {ip} {port}");
            }
        }
    }
    if let Some(crv) = call_ref_opt
        && crv != 1
    {
        let _ = write!(tokens, " callref {crv}");
    }

    let explicit_transport = match transport {
        TransportProto::Udp => Some(TransportProto::Udp),
        tp => Some(tp),
    };
    Some(sd_tp(Protocol::H323, tokens, residual, explicit_transport))
}

/// Dissects an ITU-T H.323 Call Signaling (TCP `1720` TPKT+Q.931+H.225.0) or RAS (UDP `1719`) packet.
pub(crate) fn dissect_h323(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() >= 14 && payload[0] == 0x03 && payload[1] == 0x00 {
        let tpkt_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
        if tpkt_len >= 14
            && tpkt_len <= payload.len()
            && payload.get(4..6) == Some(&[0x08, 0x02])
            && let Some((kw, expected_choice)) = match payload[8] {
                0x05 => Some(("setup", 0u32)),
                0x02 => Some(("callproceeding", 1)),
                0x07 => Some(("connect", 2)),
                0x01 => Some(("alerting", 3)),
                0x7B => Some(("information", 4)),
                0x5A => Some(("releasecomplete", 5)),
                _ => None,
            }
        {
            let call_ref = u16::from_be_bytes([payload[6], payload[7]]);
            let q931_ies = payload.get(9..tpkt_len)?;
            let mut pos = 0usize;
            let (mut calling, mut called, mut cause, mut user_data_opt) =
                (None, None, None, None);

            while pos < q931_ies.len() {
                let ie_id = *q931_ies.get(pos)?;
                if ie_id == 0x7E {
                    let uu_len = usize::from(u16::from_be_bytes([
                        *q931_ies.get(pos + 1)?,
                        *q931_ies.get(pos + 2)?,
                    ]));
                    if pos + 3 + uu_len != q931_ies.len() || uu_len < 1 || *q931_ies.get(pos + 3)? != 0x05 {
                        return None;
                    }
                    let uuie = q931_ies.get(pos + 4..pos + 3 + uu_len)?;
                    user_data_opt = Some(dissect_h225_cs_uuie(uuie, expected_choice)?);
                    break;
                }
                let ie_len = usize::from(*q931_ies.get(pos + 1)?);
                let ie_val = q931_ies.get(pos + 2..pos.checked_add(2)?.checked_add(ie_len)?)?;
                match ie_id {
                    0x04 if ie_val == [0x88, 0x93, 0xA5] => {}
                    0x08 if ie_len == 2 && ie_val[0] == 0x80 => {
                        cause = Some(ie_val[1] & 0x7F);
                    }
                    0x6C if ie_len >= 1 && ie_val[0] == 0x80 => {
                        calling = Some(core::str::from_utf8(&ie_val[1..]).ok()?);
                    }
                    0x70 if ie_len >= 1 && ie_val[0] == 0x80 => {
                        called = Some(core::str::from_utf8(&ie_val[1..]).ok()?);
                    }
                    _ => return None,
                }
                pos += 2 + ie_len;
            }

            let user_data = user_data_opt?;
            let trailing = payload.get(tpkt_len..)?;
            if !user_data.is_empty() && !trailing.is_empty() {
                return None;
            }
            let residual = if !user_data.is_empty() {
                user_data
            } else {
                trailing.to_vec()
            };

            let mut tokens = String::from("h323");
            if kw != "setup" {
                let _ = write!(tokens, " {kw}");
            }
            if call_ref != 1 {
                let _ = write!(tokens, " callref {call_ref}");
            }
            if let Some(c) = cause
                && !(kw == "releasecomplete" && c == 16)
            {
                let _ = write!(tokens, " cause {c}");
            }
            if let Some(cg) = calling {
                let _ = write!(tokens, " callingparty \"{}\"", quote_raw_str(cg));
            }
            if let Some(cd) = called {
                let _ = write!(tokens, " calledparty \"{}\"", quote_raw_str(cd));
            }
            let explicit_transport = match transport {
                TransportProto::Tcp => None,
                tp => Some(tp),
            };
            return Some(sd_tp(Protocol::H323, tokens, residual, explicit_transport));
        }
    }

    if src_port == 1719 || dst_port == 1719 || transport == TransportProto::Udp {
        return dissect_h225_ras(transport, payload);
    }
    None
}
