//! Simple Network Management Protocol v1, v2c, and v3 (SNMP, RFC 1157 / RFC 3416 / RFC 3414) wire builders.
//!
//! This module provides ASN.1 BER packet encoders and cryptographic key-localization/privacy
//! engines for SNMPv1 (RFC 1157), community-based SNMPv2c (RFC 1901 / RFC 3416), and User-Based
//! Security Model SNMPv3 (RFC 3412 / RFC 3414 / RFC 3826 / RFC 7860) over UDP ports 161 and 162.
//! Submodule [`builder`] handles SMIv1/SMIv2 VarBind and PDU serialization, while [`crypto`]
//! implements USM password-to-key localization, HMAC truncation, DES-CBC, and AES-128-CFB.

pub mod builder;
pub mod crypto;

#[doc(inline)]
pub use builder::*;
#[doc(inline)]
pub use crypto::*;
