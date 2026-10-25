//! Post Office Protocol Version 3 (POP3, RFC 1939) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`Pop3Spec`], the zero-copy AST representation of an RFC 1939 Post Office
//! Protocol Version 3 (POP3) command or server response over TCP port 110 (or 995 for POP3S).
//! On the wire, POP3 operates across Authorization (`USER`, `PASS`, `APOP`, `AUTH`), Transaction
//! (`STAT`, `LIST`, `UIDL`, `RETR`, `TOP`, `DELE`, `NOOP`, `RSET`), and Update (`QUIT`) states
//! using CRLF-terminated ASCII commands and `+OK` or `-ERR` status indicators followed by optional
//! dot-stuffed multi-line bodies. Canonical FrameAssembly `.fasm` syntax expresses POP3 packets via
//! `POP3 [CMD <str>] [ARG <str>] [OK | ERR] [RESPONSE <str>]`.

/// RFC 1939 Post Office Protocol Version 3 (POP3) command or response specification.
///
/// Syntax mapping: `POP3 [CMD <str>] [ARG <str>] [OK] [ERR] [RESPONSE <str>]`
#[doc(alias = "POP3")]
#[doc(alias = "RFC 1939")]
#[doc(alias = "RFC1939")]
#[doc(alias = "CMD")]
#[doc(alias = "ARG")]
#[doc(alias = "OK")]
#[doc(alias = "ERR")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "110")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pop3Spec<'a> {
    /// Positive server indicator flag (`OK`, emitting `+OK`).
    pub is_ok: bool,
    /// Negative server indicator flag (`ERR`, emitting `-ERR`).
    pub is_err: bool,
    /// POP3 client command verb (`CMD <str>`, e.g., `"USER"`, `"STAT"`, `"RETR"`, `"QUIT"`).
    pub cmd: Option<&'a str>,
    /// POP3 command argument string (`ARG <str>`).
    pub arg: Option<&'a str>,
    /// POP3 server response banner or status text (`RESPONSE <str>`).
    pub response: Option<&'a str>,
}
