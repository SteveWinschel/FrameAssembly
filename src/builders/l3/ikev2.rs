//! Internet Key Exchange Protocol Version 2 (IKEv2, RFC 7296) Layer 3 wire builder.
//!
//! Serializes an [`Ikev2Spec`] into an RFC 7296 IKEv2 message encapsulated over UDP destination port
//! `500`. The 28-byte header writes the 64-bit big-endian `Initiator SPI` (`initiatorspi`, default
//! `0x0102030405060708`), 64-bit `Responder SPI` (`responderspi`, default `0`), 8-bit `Next Payload`,
//! Version `0x20` (v2.0), `Exchange Type` (`34` `sainit`, `35` `auth`, `36` `createchildsa`, `37`
//! `informational`), `Flags` (`0x08` Initiator / `0x20` Response), `Message ID`, and `Length`,
//! synthesizing deterministic `SAi1+KEi+Ni` / `SAr1+KEr+Nr` or `SK` payloads when omitted.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ikev2 [exchange <sainit|auth|createchildsa|informational>] [initiatorspi <u64>] [responderspi <u64>] [msgid <u32>] [flags <u8>] [nextheader <u8>]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds deterministic non-zero RFC 7296 default payloads for `IKE_SA_INIT` (`SAi1+KEi+Ni` /
/// `SAr1+KEr+Nr`) and encrypted IKE exchanges (`SK` payload) when no raw payload is supplied.
pub(crate) fn default_ikev2_payload(exchange: IkeExchange, is_response: bool) -> (u8, Vec<u8>) {
    let mut body = Vec::new();
    match exchange {
        IkeExchange::SaInit => {
            // 1. Security Association Payload (Type 33): Next Payload = 34 (KE), Length = 48
            body.extend_from_slice(&[34, 0, 0, 48]);
            // Proposal #1 (44 bytes): last=0, proto=1 (IKE), spi_size=0, num_transforms=4
            body.extend_from_slice(&[0, 0, 0, 44, 1, 1, 0, 4]);
            // Transform 1: ENCR_AES_CBC (12) + Key Length 128 bits (0x800E, 0x0080)
            body.extend_from_slice(&[3, 0, 0, 12, 1, 0, 0, 12, 0x80, 0x0E, 0x00, 0x80]);
            // Transform 2: PRF_HMAC_SHA2_256 (5)
            body.extend_from_slice(&[3, 0, 0, 8, 2, 0, 0, 5]);
            // Transform 3: AUTH_HMAC_SHA2_256_128 (12)
            body.extend_from_slice(&[3, 0, 0, 8, 3, 0, 0, 12]);
            // Transform 4: DH Group 14 (2048-bit MODP)
            body.extend_from_slice(&[0, 0, 0, 8, 4, 0, 0, 14]);

            // 2. Key Exchange Payload (Type 34): Next Payload = 40 (Nonce), Length = 264 (8 + 256B DH14)
            body.extend_from_slice(&[40, 0, 1, 8, 0, 14, 0, 0]);
            let ke_seed = if is_response { 0x6B_u8 } else { 0x5A_u8 };
            for idx in 0..256usize {
                body.push(ke_seed.wrapping_add((idx as u8).wrapping_mul(29)) | 1);
            }

            // 3. Nonce Payload (Type 40): Next Payload = 0 (None), Length = 36 (4 + 32B Nonce)
            body.extend_from_slice(&[0, 0, 0, 36]);
            let n_seed = if is_response { 0x9D_u8 } else { 0x7C_u8 };
            for idx in 0..32usize {
                body.push(n_seed.wrapping_add((idx as u8).wrapping_mul(19)) | 1);
            }
            (33, body)
        }
        IkeExchange::Auth | IkeExchange::CreateChildSa | IkeExchange::Informational => {
            // Encrypted and Authenticated Payload (SK = 46, RFC 7296 §3.14): 4B hdr + 8B IV + 16B ciphertext + 12B ICV = 40B
            body.extend_from_slice(&[0, 0, 0, 40]);
            let base = if is_response { 0xC3_u8 } else { 0xA1_u8 };
            for idx in 0..36usize {
                body.push(base.wrapping_add((idx as u8).wrapping_mul(13)) | 1);
            }
            (46, body)
        }
    }
}

/// Builds an RFC 7296 IKEv2 payload and returns `(bytes, 500)` for UDP encapsulation.
pub fn build_ikev2_payload(spec: &Ikev2Spec, payload: &[u8]) -> (Vec<u8>, u16) {
    let init_spi = spec.initiator_spi.unwrap_or(0x0102_0304_0506_0708);
    let resp_spi = spec.responder_spi.unwrap_or(0);
    let ex_enum = spec.exchange.unwrap_or(IkeExchange::SaInit);
    let exchange = match ex_enum {
        IkeExchange::SaInit => 34,
        IkeExchange::Auth => 35,
        IkeExchange::CreateChildSa => 36,
        IkeExchange::Informational => 37,
    };
    let flags = spec.flags.unwrap_or(0x08); // Initiator
    let msgid = spec.msgid.unwrap_or(0);

    let (next_payload, body): (u8, Vec<u8>) = if payload.is_empty() && spec.next_payload.is_none() {
        default_ikev2_payload(ex_enum, (flags & 0x20) != 0)
    } else {
        (spec.next_payload.unwrap_or(0), payload.to_vec())
    };
    let total_len = u32::try_from(28 + body.len()).unwrap_or(u32::MAX);

    let mut ike = Vec::with_capacity(28 + body.len());
    ike.extend_from_slice(&init_spi.to_be_bytes());
    ike.extend_from_slice(&resp_spi.to_be_bytes());
    ike.push(next_payload);
    ike.push(0x20); // Version 2.0
    ike.push(exchange);
    ike.push(flags);
    ike.extend_from_slice(&msgid.to_be_bytes());
    ike.extend_from_slice(&total_len.to_be_bytes());
    ike.extend_from_slice(&body);

    (ike, 500)
}
