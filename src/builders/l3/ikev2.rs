//! Internet Key Exchange Protocol Version 2 (IKEv2, RFC 7296) Layer 3 wire builder.
//!
//! Serializes an [`Ikev2Spec`] into a 28-byte RFC 7296 IKEv2 header (plus optional payload octets)
//! encapsulated over UDP destination port `500`. The wire builder writes the 64-bit big-endian
//! `Initiator SPI` (`initiatorspi`, default `0x0102030405060708`), 64-bit big-endian `Responder SPI`
//! (`responderspi`, default `0`), 8-bit `Next Payload` (`nextheader`, default `0`), Version byte
//! `0x20` (v2.0), 8-bit `Exchange Type` (`34` `sainit`, `35` `auth`, `36` `createchildsa`, `37`
//! `informational`), 8-bit `Flags` (`0x08` Initiator), 32-bit `Message ID` (`msgid`), and 32-bit `Length`.
//!
//! Canonical `.fasm` syntax:
//! `a -> b ikev2 [exchange <sainit|auth|createchildsa|informational>] [initiatorspi <u64>] [responderspi <u64>] [msgid <u32>] [flags <u8>] [nextheader <u8>]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 7296 IKEv2 payload and returns `(bytes, 500)` for UDP encapsulation.
pub fn build_ikev2_payload(spec: &Ikev2Spec, payload: &[u8]) -> (Vec<u8>, u16) {
    let init_spi = spec.initiator_spi.unwrap_or(0x0102_0304_0506_0708);
    let resp_spi = spec.responder_spi.unwrap_or(0);
    let exchange = match spec.exchange.unwrap_or(IkeExchange::SaInit) {
        IkeExchange::SaInit => 34,
        IkeExchange::Auth => 35,
        IkeExchange::CreateChildSa => 36,
        IkeExchange::Informational => 37,
    };
    let flags = spec.flags.unwrap_or(0x08); // Initiator
    let msgid = spec.msgid.unwrap_or(0);
    let total_len = (28 + payload.len()) as u32;

    let mut ike = Vec::with_capacity(28 + payload.len());
    ike.extend_from_slice(&init_spi.to_be_bytes());
    ike.extend_from_slice(&resp_spi.to_be_bytes());
    ike.push(spec.next_payload.unwrap_or(0));
    ike.push(0x20); // Version 2.0
    ike.push(exchange);
    ike.push(flags);
    ike.extend_from_slice(&msgid.to_be_bytes());
    ike.extend_from_slice(&total_len.to_be_bytes());
    ike.extend_from_slice(payload);

    (ike, 500)
}
