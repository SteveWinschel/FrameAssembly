//! ITU-T H.323 / H.225.0 Call Signaling and RAS Layer 7 wire packet builder.
//!
//! This module implements [`build_h323_payload`], which synthesizes deterministic ITU-T H.323
//! multimedia signaling frames across TCP port 1720 and UDP port 1719. Call Signaling defaults
//! to TCP port 1720 with an RFC 1006 TPKT header (`0x03 0x00 len`), an ITU-T Q.931 message
//! header (`0x08 0x02 call_ref msg_type`), optional Q.931 Information Elements (`0x04` Bearer
//! Capability, `0x08` Cause, `0x6C` Calling Party, `0x70` Called Party), and User-User IE
//! (`0x7E` + `0x05`) wrapping X.691 Aligned PER `H323-UserInformation`. RAS messages switch to
//! UDP port 1719 emitting Aligned PER `RasMessage` PDUs (`GRQ`, `GCF`, `RRQ`, `RCF`, `DRQ`, `DCF`).

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::*;
use crate::builders::WireContext;

/// ITU-T H.225.0 v4 protocolIdentifier OID `0.0.8.2250.0.4` BER content octets.
const H225_OID: [u8; 6] = [0x00, 0x08, 0x91, 0x4A, 0x00, 0x04];

/// Fixed 16-byte H.225.0 ConferenceIdentifier default.
const DEFAULT_CONF_ID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

/// Bit-level ITU-T X.691 Basic Aligned PER encoder.
struct PerWriter {
    /// Accumulated output byte buffer.
    buf: Vec<u8>,
    /// Next bit position within the active octet (`0..8`, MSB-first).
    bitpos: u8,
}

impl PerWriter {
    /// Creates an empty Aligned PER bit writer.
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(48),
            bitpos: 0,
        }
    }

    /// Writes a single bit (`0` or `1`) at the current bit offset.
    fn write_bit(&mut self, bit: u8) {
        if self.bitpos == 0 {
            self.buf.push(0);
        }
        if (bit & 1) != 0
            && let Some(last) = self.buf.last_mut()
        {
            *last |= 1 << (7 - self.bitpos);
        }
        self.bitpos = (self.bitpos + 1) % 8;
    }

    /// Writes the lowest `count` bits of `val` in MSB-first order.
    fn write_bits(&mut self, val: u32, count: u8) {
        let mut i = count;
        while i > 0 {
            i -= 1;
            self.write_bit(((val >> i) & 1) as u8);
        }
    }

    /// Advances to the next octet boundary if not already byte-aligned.
    fn align(&mut self) {
        self.bitpos = 0;
    }

    /// Writes an octet-aligned byte.
    fn write_octet(&mut self, byte: u8) {
        self.align();
        self.buf.push(byte);
    }

    /// Writes an octet-aligned byte slice.
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.align();
        self.buf.extend_from_slice(bytes);
    }

    /// Writes a constrained whole number `(val - lb)` within `lb..=ub` in X.691 Aligned PER.
    fn write_constrained_int(&mut self, val: u32, lb: u32, ub: u32) {
        let range = ub.saturating_sub(lb).saturating_add(1);
        let offset = val.saturating_sub(lb).min(range.saturating_sub(1));
        if range <= 1 {
            return;
        }
        if range <= 255 {
            let bits = (32 - (range - 1).leading_zeros()) as u8;
            self.write_bits(offset, bits);
        } else if range == 256 {
            self.write_octet(offset as u8);
        } else if range <= 65536 {
            self.align();
            self.buf.extend_from_slice(&(offset as u16).to_be_bytes());
        }
    }

    /// Writes an X.691 Aligned PER `OBJECT IDENTIFIER` with 1-byte length prefix.
    fn write_oid(&mut self, oid_bytes: &[u8]) {
        self.write_octet(oid_bytes.len() as u8);
        self.buf.extend_from_slice(oid_bytes);
    }

    /// Finalizes the PER byte buffer (padding to at least one byte if empty).
    fn finish(mut self) -> Vec<u8> {
        if self.buf.is_empty() {
            self.buf.push(0);
        }
        self.buf
    }
}

/// Encodes an H.225.0 `EndpointType` marking a basic terminal endpoint.
fn write_endpoint_type(w: &mut PerWriter) {
    w.write_bit(0); // EndpointType ext = 0
    w.write_bits(0b000001, 6); // terminal present, other optional descriptors absent
    w.write_bit(0); // mc = FALSE
    w.write_bit(0); // undefinedNode = FALSE
    w.write_bit(0); // TerminalInfo ext = 0
    w.write_bit(0); // nonStandardData = 0
}

/// Encodes an H.225.0 `VendorIdentifier` (`H221NonStandard` T.35 USA code).
fn write_vendor_id(w: &mut PerWriter) {
    w.write_bit(0); // VendorIdentifier ext = 0
    w.write_bits(0, 2); // productId, versionId absent
    w.write_bit(0); // H221NonStandard ext = 0
    w.write_constrained_int(181, 0, 255);
    w.write_constrained_int(0, 0, 255);
    w.write_constrained_int(18, 0, 65535);
}

/// Encodes an H.225.0 `TransportAddress` (`ipAddress` IPv4 + 16-bit port).
fn write_transport_addr_ipv4(w: &mut PerWriter, ip: [u8; 4], port: u16) {
    w.write_bit(0); // TransportAddress ext = 0
    w.write_bits(0, 3); // choice 0: ipAddress
    w.write_bytes(&ip);
    w.write_constrained_int(u32::from(port), 0, 65535);
}

/// Encodes an H.225.0 Call Signaling `H323-UserInformation` UUIE in X.691 Aligned PER.
fn build_h225_cs_uuie(msg_choice: u32, user_data: Option<&[u8]>) -> Vec<u8> {
    let mut w = PerWriter::new();
    w.write_bit(0); // H323-UserInformation ext = 0
    w.write_bit(u8::from(user_data.is_some())); // user-data optional presence bit
    w.write_bit(0); // H323-UU-PDU ext = 0
    w.write_bit(0); // nonStandardData = 0
    w.write_bit(0); // h323-message-body CHOICE ext = 0
    w.write_bits(msg_choice, 3);
    match msg_choice {
        0 => {
            // Setup-UUIE
            w.write_bit(0);
            w.write_bits(0, 7);
            w.write_oid(&H225_OID);
            write_endpoint_type(&mut w);
            w.write_bit(0); // activeMC = FALSE
            w.write_bytes(&DEFAULT_CONF_ID);
            w.write_bit(0);
            w.write_bits(0, 2); // conferenceGoal = create
            w.write_bit(0);
            w.write_bits(0, 2); // callType = pointToPoint
        }
        1 | 3 => {
            // CallProceeding-UUIE / Alerting-UUIE
            w.write_bit(0);
            w.write_bit(0);
            w.write_oid(&H225_OID);
            write_endpoint_type(&mut w);
        }
        2 => {
            // Connect-UUIE
            w.write_bit(0);
            w.write_bit(0);
            w.write_oid(&H225_OID);
            write_endpoint_type(&mut w);
            w.write_bytes(&DEFAULT_CONF_ID);
        }
        _ => {
            // Information-UUIE (4) / ReleaseComplete-UUIE (5)
            w.write_bit(0);
            w.write_bit(0);
            w.write_oid(&H225_OID);
        }
    }
    if let Some(ud) = user_data {
        let len = ud.len().clamp(1, 131);
        w.write_constrained_int(5, 0, 255); // Q.931 user-specific protocol discriminator
        w.write_constrained_int((len - 1) as u32, 0, 130);
        w.write_bytes(&ud[..len]);
    }
    w.finish()
}

/// Encodes an H.225.0 RAS `RasMessage` PDU in X.691 Aligned PER.
fn build_h225_ras_per(
    kind: &str,
    seq_num: u16,
    ip: [u8; 4],
    ras_port: u16,
    call_ref: u16,
) -> Vec<u8> {
    let mut w = PerWriter::new();
    w.write_bit(0); // RasMessage ext = 0
    match kind {
        "GCF" => {
            w.write_bits(1, 5);
            w.write_bit(0);
            w.write_bits(0, 2);
            w.write_constrained_int(u32::from(seq_num), 1, 65535);
            w.write_oid(&H225_OID);
            write_transport_addr_ipv4(&mut w, ip, ras_port);
        }
        "RRQ" => {
            w.write_bits(3, 5);
            w.write_bit(0);
            w.write_bits(0, 3);
            w.write_constrained_int(u32::from(seq_num), 1, 65535);
            w.write_oid(&H225_OID);
            w.write_bit(0); // discoveryComplete
            w.write_octet(1);
            write_transport_addr_ipv4(&mut w, ip, 1720);
            w.write_octet(1);
            write_transport_addr_ipv4(&mut w, ip, ras_port);
            write_endpoint_type(&mut w);
            write_vendor_id(&mut w);
        }
        "RCF" => {
            w.write_bits(4, 5);
            w.write_bit(0);
            w.write_bits(0, 3);
            w.write_constrained_int(u32::from(seq_num), 1, 65535);
            w.write_oid(&H225_OID);
            w.write_octet(1);
            write_transport_addr_ipv4(&mut w, ip, ras_port);
            w.write_constrained_int(0, 0, 127); // endpointIdentifier length = 1 BMP char
            w.write_bytes(&[0x00, b'1']);
        }
        "DRQ" => {
            w.write_bits(15, 5);
            w.write_bit(0);
            w.write_bit(0);
            w.write_constrained_int(u32::from(seq_num), 1, 65535);
            w.write_constrained_int(0, 0, 127);
            w.write_bytes(&[0x00, b'1']);
            w.write_bytes(&DEFAULT_CONF_ID);
            w.write_constrained_int(u32::from(call_ref), 0, 65535);
            w.write_bit(0);
            w.write_bits(0, 2); // forcedDrop
        }
        "DCF" => {
            w.write_bits(16, 5);
            w.write_bit(0);
            w.write_bit(0);
            w.write_constrained_int(u32::from(seq_num), 1, 65535);
        }
        _ => {
            // GRQ (0) default
            w.write_bits(0, 5);
            w.write_bit(0);
            w.write_bits(0, 4);
            w.write_constrained_int(u32::from(seq_num), 1, 65535);
            w.write_oid(&H225_OID);
            write_transport_addr_ipv4(&mut w, ip, ras_port);
            write_endpoint_type(&mut w);
        }
    }
    w.finish()
}

/// Returns `true` when `spec` or `transport` selects H.225.0 RAS over UDP port `1719`.
pub fn is_h323_ras(spec: &H323Spec, transport: Option<TransportProto>) -> bool {
    if let Some(m) = spec.msg_type {
        let norm = m.to_ascii_uppercase().replace(['_', '-'], "");
        return matches!(
            norm.as_str(),
            "GRQ" | "GCF" | "RRQ" | "RCF" | "DRQ" | "DCF" | "RAS"
        );
    }
    transport == Some(TransportProto::Udp)
}

/// Builds an ITU-T H.323 Call Signaling (TPKT + Q.931 + H.225.0 CS) or RAS payload and returns `(bytes, default_port)`.
///
/// Syntax mapping: `h323 [setup | callproceeding | alerting | connect | releasecomplete | grq | gcf | rrq | rcf | drq | dcf | msgtype <str>] [callref <u16>] [callingparty <str>] [calledparty <str>] [cause <u8>] [seqnum <u16>] [rasaddr <ip> [<u16>]] [transport udp]`
#[doc(alias = "H323")]
#[doc(alias = "H225")]
#[doc(alias = "Q931")]
#[doc(alias = "RAS")]
pub fn build_h323_payload(
    ctx: &WireContext,
    spec: &H323Spec,
    payload_bytes: &[u8],
) -> (Vec<u8>, u16) {
    if is_h323_ras(spec, ctx.transport) {
        let norm = spec
            .msg_type
            .unwrap_or("GRQ")
            .to_ascii_uppercase()
            .replace(['_', '-'], "");
        let ras_kind = match norm.as_str() {
            "GCF" | "RRQ" | "RCF" | "DRQ" | "DCF" => norm.as_str(),
            _ => "GRQ",
        };
        let seq_num = spec.seq_num.unwrap_or(1).max(1);
        let ip = match spec.ras_addr {
            Some(IpAddr::V4(v4)) => v4.octets(),
            _ => Ipv4Addr::new(192, 0, 2, 1).octets(),
        };
        let default_ras_port = if ras_kind == "RCF" { 1720 } else { 1719 };
        let ras_port = spec.ras_port.unwrap_or(default_ras_port);
        let call_ref = spec.call_ref.unwrap_or(1);
        let mut pkt = build_h225_ras_per(ras_kind, seq_num, ip, ras_port, call_ref);
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }
        return (pkt, 1719);
    }

    let norm = spec
        .msg_type
        .unwrap_or("SETUP")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let (q931_mtype, uuie_choice): (u8, u32) = match norm.as_str() {
        "CALLPROCEEDING" | "PROC" => (0x02, 1),
        "CONNECT" => (0x07, 2),
        "ALERTING" => (0x01, 3),
        "INFORMATION" => (0x7B, 4),
        "RELEASECOMPLETE" | "REL" => (0x5A, 5),
        _ => (0x05, 0),
    };
    let call_ref = spec.call_ref.unwrap_or(1);

    let mut q931 = Vec::with_capacity(64);
    q931.push(0x08); // Q.931 Protocol Discriminator
    q931.push(0x02); // 2-byte Call Reference Value
    q931.extend_from_slice(&call_ref.to_be_bytes());
    q931.push(q931_mtype);

    if q931_mtype == 0x05 {
        q931.extend_from_slice(&[0x04, 0x03, 0x88, 0x93, 0xA5]); // Bearer Capability
    }
    if let Some(cause) = spec.cause {
        q931.extend_from_slice(&[0x08, 0x02, 0x80, 0x80 | (cause & 0x7F)]);
    } else if q931_mtype == 0x5A {
        q931.extend_from_slice(&[0x08, 0x02, 0x80, 0x90]); // Normal call clearing (16)
    }
    if let Some(calling) = spec.calling_party {
        let digits = &calling.as_bytes()[..calling.len().min(250)];
        q931.push(0x6C);
        q931.push((1 + digits.len()) as u8);
        q931.push(0x80);
        q931.extend_from_slice(digits);
    }
    if let Some(called) = spec.called_party {
        let digits = &called.as_bytes()[..called.len().min(250)];
        q931.push(0x70);
        q931.push((1 + digits.len()) as u8);
        q931.push(0x80);
        q931.extend_from_slice(digits);
    }

    let (ud_opt, trailing): (Option<&[u8]>, &[u8]) =
        if !payload_bytes.is_empty() && payload_bytes.len() <= 131 {
            (Some(payload_bytes), &[])
        } else {
            (None, payload_bytes)
        };
    let uuie = build_h225_cs_uuie(uuie_choice, ud_opt);
    let uu_len = (1 + uuie.len()).min(usize::from(u16::MAX)) as u16;
    q931.push(0x7E);
    q931.extend_from_slice(&uu_len.to_be_bytes());
    q931.push(0x05);
    q931.extend_from_slice(&uuie);

    let tpkt_len = (4 + q931.len()).min(usize::from(u16::MAX)) as u16;
    let mut pkt = Vec::with_capacity(usize::from(tpkt_len) + trailing.len());
    pkt.push(0x03);
    pkt.push(0x00);
    pkt.extend_from_slice(&tpkt_len.to_be_bytes());
    pkt.extend_from_slice(&q931);
    if !trailing.is_empty() {
        pkt.extend_from_slice(trailing);
    }
    (pkt, 1720)
}
