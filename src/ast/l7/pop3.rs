//! Post Office Protocol Version 3 (POP3, RFC 1939) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`Pop3Spec`], the zero-copy AST representation of an RFC 1939 Post Office
//! Protocol Version 3 (POP3) command or server response over TCP port 110 (or 995 for POP3S).
//! On the wire, POP3 operates across Authorization (`user`, `PASS`, `APOP`, `auth`), Transaction
//! (`STAT`, `LIST`, `UIDL`, `RETR`, `TOP`, `DELE`, `NOOP`, `RSET`), and Update (`quit`) states
//! using CRLF-terminated ASCII commands and `+ok` or `-err` status indicators followed by optional
//! dot-stuffed multi-line bodies. Canonical FrameAssembly `.fasm` syntax expresses POP3 packets via
//! `pop3 [cmd <str>] [arg <str>] [ok | err] [response <str>]`.

/// RFC 1939 Post Office Protocol Version 3 (POP3) command or response specification.
///
/// Syntax mapping: `pop3 [cmd <str>] [arg <str>] [ok] [err] [response <str>]`
#[doc(alias = "pop3")]
#[doc(alias = "RFC 1939")]
#[doc(alias = "RFC1939")]
#[doc(alias = "cmd")]
#[doc(alias = "arg")]
#[doc(alias = "ok")]
#[doc(alias = "err")]
#[doc(alias = "response")]
#[doc(alias = "110")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pop3Spec<'a> {
    /// Positive server indicator flag (`ok`, emitting `+ok`).
    pub is_ok: bool,
    /// Negative server indicator flag (`err`, emitting `-err`).
    pub is_err: bool,
    /// POP3 client command verb (`cmd <str>`, e.g., `"USER"`, `"STAT"`, `"RETR"`, `"QUIT"`).
    pub cmd: Option<&'a str>,
    /// POP3 command argument string (`arg <str>`).
    pub arg: Option<&'a str>,
    /// POP3 server response banner or status text (`response <str>`).
    pub response: Option<&'a str>,
}
