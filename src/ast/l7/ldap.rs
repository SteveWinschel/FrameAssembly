//! Lightweight Directory Access Protocol v3 (LDAP, RFC 4511) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`LdapSpec`], the zero-copy AST representation of an RFC 4511 Lightweight
//! Directory Access Protocol v3 (`LDAPMessage`) envelope over TCP or UDP port 389 (or TCP 636 for
//! LDAPS). On the wire, an `LDAPMessage` is an ASN.1 BER `SEQUENCE` (tag `0x30`) containing an
//! integer `messageid` followed by a protocol operation choice (`BindRequest` `0x60`,
//! `BindResponse` `0x61`, `SearchRequest` `0x63`, `SearchResultEntry` `0x64`,
//! `SearchResultDone` `0x65`, or `UnbindRequest` `0x42`). Canonical FrameAssembly `.frasm` syntax:
//! `ldap [msgid <i32>] [bindreq | bindres | searchreq | searchentry | searchdone | unbindreq] [basedn <str>] [filter <str>] [resultcode <u32>]`.

/// RFC 4511 Lightweight Directory Access Protocol v3 (LDAP) specification.
///
/// Syntax mapping: `ldap [msgid <i32>] [bindreq | bindres | searchreq | searchentry | searchdone | unbindreq] [basedn <str>] [filter <str>] [resultcode <u32>]`
#[doc(alias = "ldap")]
#[doc(alias = "RFC 4511")]
#[doc(alias = "RFC4511")]
#[doc(alias = "389")]
#[doc(alias = "msgid")]
#[doc(alias = "bindreq")]
#[doc(alias = "bindres")]
#[doc(alias = "searchreq")]
#[doc(alias = "searchentry")]
#[doc(alias = "searchdone")]
#[doc(alias = "unbindreq")]
#[doc(alias = "basedn")]
#[doc(alias = "filter")]
#[doc(alias = "resultcode")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LdapSpec<'a> {
    /// LDAP message identifier (`msgid <i32>`, default `1`).
    pub msgid: Option<i32>,
    /// BindRequest operation flag (`bindreq`, BER tag `0x60`).
    pub is_bind_req: bool,
    /// BindResponse operation flag (`bindres`, BER tag `0x61`).
    pub is_bind_res: bool,
    /// SearchRequest operation flag (`searchreq`, BER tag `0x63`).
    pub is_search_req: bool,
    /// SearchResultEntry operation flag (`searchentry`, BER tag `0x64`).
    pub is_search_entry: bool,
    /// SearchResultDone operation flag (`searchdone`, BER tag `0x65`).
    pub is_search_done: bool,
    /// UnbindRequest operation flag (`unbindreq`, BER tag `0x42`).
    pub is_unbind_req: bool,
    /// Distinguished Name for bind or search base (`basedn <str>`).
    pub base_dn: Option<&'a str>,
    /// Search filter expression (`filter <str>`).
    pub filter: Option<&'a str>,
    /// LDAPResult status code (`resultcode <u32>`, e.g., `0` for `success`, `49` for `invalidCredentials`).
    pub result_code: Option<u32>,
}
