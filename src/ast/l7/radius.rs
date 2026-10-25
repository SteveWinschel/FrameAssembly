//! Remote Authentication Dial-In User Service (RADIUS) (RFC 2865 (Authentication) / RFC 2866 (Accounting) / RFC 5176 (CoA)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Remote Authentication Dial-In User Service (RADIUS) packets over UDP port 1812 (Authentication) and UDP port 1813 (Accounting). On the wire, the protocol uses a 20-byte fixed RADIUS header (8-bit Code: 1 Access-Request, 2 Access-Accept, 3 Access-Reject, 4 Accounting-Request, 5 Accounting-Response, 11 Access-Challenge; 8-bit Identifier; 16-bit big-endian Length; 16-byte Request/Response Authenticator) followed by TLV Attribute-Value Pairs (AVPs: Type 1 User-Name, Type 4 NAS-IP-Address, Type 6 Service-Type, Type 8 Framed-IP-Address).
//! Every field in [`RadiusSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b RADIUS [ACCESS_REQUEST | ACCESS_ACCEPT | ACCESS_REJECT | ACCESS_CHALLENGE | ACCOUNTING_REQUEST | ACCOUNTING_RESPONSE | CODE <str>] [ID <u8>] [USER <str>] [NAS_IP <ip>] [SERVICE_TYPE <u32>] [FRAMED_IP <ip>]`

use core::net::IpAddr;
/// RFC 2865 RADIUS authentication & accounting specification.
///
/// Syntax mapping: `RADIUS [ACCESS_REQUEST | ACCESS_ACCEPT | ACCESS_REJECT | ACCESS_CHALLENGE | ACCOUNTING_REQUEST | ACCOUNTING_RESPONSE | CODE <str>] [ID <u8>] [USER <str>] [NAS_IP <ip>] [SERVICE_TYPE <u32>] [FRAMED_IP <ip>]`
#[doc(alias = "RADIUS")]
#[doc(alias = "RFC 2865")]
#[doc(alias = "RFC2865")]
#[doc(alias = "RFC 2866")]
#[doc(alias = "RFC2866")]
#[doc(alias = "ACCESS_REQUEST")]
#[doc(alias = "ACCESS_ACCEPT")]
#[doc(alias = "ACCESS_REJECT")]
#[doc(alias = "ACCESS_CHALLENGE")]
#[doc(alias = "ACCOUNTING_REQUEST")]
#[doc(alias = "ACCOUNTING_RESPONSE")]
#[doc(alias = "CODE")]
#[doc(alias = "ID")]
#[doc(alias = "USER")]
#[doc(alias = "NAS_IP")]
#[doc(alias = "SERVICE_TYPE")]
#[doc(alias = "FRAMED_IP")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RadiusSpec<'a> {
    /// Packet code (e.g. ACCESS_REQUEST, ACCESS_ACCEPT).
    pub code: Option<&'a str>,
    /// Identifier byte.
    pub id: Option<u8>,
    /// User name attribute string.
    pub user: Option<&'a str>,
    /// NAS IP address.
    pub nas_ip: Option<IpAddr>,
    /// Service Type numeric code.
    pub service_type: Option<u32>,
    /// Framed IP address.
    pub framed_ip: Option<IpAddr>,
}
