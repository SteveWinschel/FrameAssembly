//! Kerberos Network Authentication Service v5 (RFC 4120) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`KerberosSpec`], the zero-copy AST representation of an RFC 4120 Kerberos
//! Version 5 authentication message over UDP or TCP port 88. On the wire, Kerberos v5 encodes
//! ASN.1 DER application-tagged PDUs including Authentication Service requests/replies (`AS-REQ`
//! tag `0x6A`, `AS-REP` tag `0x6B`), Ticket-Granting Service exchanges (`TGS-REQ` tag `0x6C`,
//! `TGS-REP` tag `0x6D`), and error messages (`KRB-ERROR` tag `0x7E`) carrying realm strings,
//! client/service principal names, and RFC 3961/8009 encryption types. Canonical `.fasm` syntax:
//! `KERBEROS [AS_REQ | AS_REP | TGS_REQ | TGS_REP | KRB_ERROR] [REALM <str>] [CNAME <str>] [SNAME <str>] [ETYPE <i32>]`.

/// RFC 4120 Kerberos v5 Authentication Service and Ticket-Granting Service specification.
///
/// Syntax mapping: `KERBEROS [AS_REQ | AS_REP | TGS_REQ | TGS_REP | KRB_ERROR] [REALM <str>] [CNAME <str>] [SNAME <str>] [ETYPE <i32>]`
#[doc(alias = "KERBEROS")]
#[doc(alias = "KRB5")]
#[doc(alias = "RFC 4120")]
#[doc(alias = "RFC4120")]
#[doc(alias = "RFC 3961")]
#[doc(alias = "AS_REQ")]
#[doc(alias = "AS_REP")]
#[doc(alias = "TGS_REQ")]
#[doc(alias = "TGS_REP")]
#[doc(alias = "KRB_ERROR")]
#[doc(alias = "REALM")]
#[doc(alias = "CNAME")]
#[doc(alias = "SNAME")]
#[doc(alias = "ETYPE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KerberosSpec<'a> {
    /// Authentication Service Request flag (`AS_REQ`, msg-type 10).
    pub is_as_req: bool,
    /// Authentication Service Reply flag (`AS_REP`, msg-type 11).
    pub is_as_rep: bool,
    /// Ticket-Granting Service Request flag (`TGS_REQ`, msg-type 12).
    pub is_tgs_req: bool,
    /// Ticket-Granting Service Reply flag (`TGS_REP`, msg-type 13).
    pub is_tgs_rep: bool,
    /// Kerberos Error message flag (`KRB_ERROR`, msg-type 30).
    pub is_krb_error: bool,
    /// Kerberos realm string (`REALM <str>`, default `"EXAMPLE.COM"`).
    pub realm: Option<&'a str>,
    /// Client principal name string (`CNAME <str>`, default `"alice"`).
    pub cname: Option<&'a str>,
    /// Server or service principal name string (`SNAME <str>`, default `"krbtgt"`).
    pub sname: Option<&'a str>,
    /// RFC 3961 / RFC 8009 encryption type code (`ETYPE <i32>`, default `18` for AES256-CTS-HMAC-SHA1-96).
    pub etype: Option<i32>,
}
