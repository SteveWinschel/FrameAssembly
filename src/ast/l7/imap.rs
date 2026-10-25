//! Internet Message Access Protocol v4rev1/v4rev2 (IMAP, RFC 3501 / RFC 9051) AST definitions.
//!
//! This module defines [`ImapSpec`], the zero-copy AST representation of an RFC 3501 / RFC 9051
//! Internet Message Access Protocol (IMAP) client command or server response over TCP port 143
//! (or 993 for IMAPS). On the wire, IMAP frames consist of CRLF-terminated ASCII lines beginning
//! with an alphanumeric client command tag (e.g., `A001`), an untagged server token (`*`), or a
//! command continuation request (`+`), followed by command verbs (`LOGIN`, `SELECT`, `FETCH`,
//! `UID`, `SEARCH`, `STORE`, `IDLE`, `LOGOUT`) or tagged completion statuses (`OK`, `NO`, `BAD`).
//! Canonical FrameAssembly `.fasm` syntax models IMAP traffic with
//! `IMAP [TAG <str>] [CMD <str>] [ARG <str>] [STATUS <str>] [RESPONSE <str>]`.

/// RFC 3501 / RFC 9051 Internet Message Access Protocol (IMAP4rev1/v4rev2) specification.
///
/// Syntax mapping: `IMAP [TAG <str>] [CMD <str>] [ARG <str>] [STATUS <str>] [RESPONSE <str>]`
#[doc(alias = "IMAP")]
#[doc(alias = "RFC 9051")]
#[doc(alias = "RFC9051")]
#[doc(alias = "RFC 3501")]
#[doc(alias = "RFC3501")]
#[doc(alias = "TAG")]
#[doc(alias = "CMD")]
#[doc(alias = "ARG")]
#[doc(alias = "STATUS")]
#[doc(alias = "RESPONSE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImapSpec<'a> {
    /// Alphanumeric command tag or `*` / `+` marker (`TAG <str>`, default `"A001"`).
    pub tag: Option<&'a str>,
    /// IMAP client command verb (`CMD <str>`, e.g., `"LOGIN"`, `"SELECT"`, `"FETCH"`).
    pub cmd: Option<&'a str>,
    /// IMAP command argument string (`ARG <str>`, e.g., `"INBOX"`, `"1:* (FLAGS)"`).
    pub arg: Option<&'a str>,
    /// Server completion status token (`STATUS <str>`, e.g., `"OK"`, `"NO"`, `"BAD"`).
    pub status: Option<&'a str>,
    /// Server response text or untagged status payload (`RESPONSE <str>`).
    pub response: Option<&'a str>,
}
