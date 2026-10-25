//! Lightweight Directory Access Protocol v3 (LDAP, RFC 4511) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`LdapSpec`], the zero-copy AST representation of an RFC 4511 Lightweight
//! Directory Access Protocol v3 (`LDAPMessage`) envelope over TCP or UDP port 389 (or TCP 636 for
//! LDAPS). On the wire, an `LDAPMessage` is an ASN.1 BER `SEQUENCE` (tag `0x30`) containing an
//! integer `messageID` followed by a protocol operation choice (`BindRequest` `0x60`,
//! `BindResponse` `0x61`, `SearchRequest` `0x63`, `SearchResultEntry` `0x64`,
//! `SearchResultDone` `0x65`, or `UnbindRequest` `0x42`). Canonical FrameAssembly `.fasm` syntax:
//! `LDAP [MSGID <i32>] [BIND_REQ | BIND_RES | SEARCH_REQ | SEARCH_ENTRY | SEARCH_DONE | UNBIND_REQ] [BASE_DN <str>] [FILTER <str>] [RESULT_CODE <u32>]`.

/// RFC 4511 Lightweight Directory Access Protocol v3 (LDAP) specification.
///
/// Syntax mapping: `LDAP [MSGID <i32>] [BIND_REQ | BIND_RES | SEARCH_REQ | SEARCH_ENTRY | SEARCH_DONE | UNBIND_REQ] [BASE_DN <str>] [FILTER <str>] [RESULT_CODE <u32>]`
#[doc(alias = "LDAP")]
#[doc(alias = "RFC 4511")]
#[doc(alias = "RFC4511")]
#[doc(alias = "389")]
#[doc(alias = "MSGID")]
#[doc(alias = "BIND_REQ")]
#[doc(alias = "BIND_RES")]
#[doc(alias = "SEARCH_REQ")]
#[doc(alias = "SEARCH_ENTRY")]
#[doc(alias = "SEARCH_DONE")]
#[doc(alias = "UNBIND_REQ")]
#[doc(alias = "BASE_DN")]
#[doc(alias = "FILTER")]
#[doc(alias = "RESULT_CODE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LdapSpec<'a> {
    /// LDAP message identifier (`MSGID <i32>`, default `1`).
    pub msgid: Option<i32>,
    /// BindRequest operation flag (`BIND_REQ`, BER tag `0x60`).
    pub is_bind_req: bool,
    /// BindResponse operation flag (`BIND_RES`, BER tag `0x61`).
    pub is_bind_res: bool,
    /// SearchRequest operation flag (`SEARCH_REQ`, BER tag `0x63`).
    pub is_search_req: bool,
    /// SearchResultEntry operation flag (`SEARCH_ENTRY`, BER tag `0x64`).
    pub is_search_entry: bool,
    /// SearchResultDone operation flag (`SEARCH_DONE`, BER tag `0x65`).
    pub is_search_done: bool,
    /// UnbindRequest operation flag (`UNBIND_REQ`, BER tag `0x42`).
    pub is_unbind_req: bool,
    /// Distinguished Name for bind or search base (`BASE_DN <str>`).
    pub base_dn: Option<&'a str>,
    /// Search filter expression (`FILTER <str>`).
    pub filter: Option<&'a str>,
    /// LDAPResult status code (`RESULT_CODE <u32>`, e.g., `0` for `success`, `49` for `invalidCredentials`).
    pub result_code: Option<u32>,
}
