//! Simple Mail Transfer Protocol (SMTP, RFC 5321) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`SmtpSpec`], the zero-copy AST representation of an RFC 5321 Simple Mail
//! Transfer Protocol (SMTP) command or server reply over TCP ports 25 (MTA relay), 465 (SMTPS),
//! and 587 (MSA message submission, RFC 6409). On the wire, SMTP exchanges CRLF-terminated ASCII
//! command lines (`ehlo`, `helo`, `MAIL from:<...>`, `RCPT to:<...>`, `data`, `STARTTLS`, `auth`,
//! `quit`) and 3-digit status replies (`220`, `250`, `354`, `221`, `550`) followed by optional
//! RFC 5322 message bodies. Canonical FrameAssembly `.frasm` syntax models SMTP frames using
//! `smtp [ehlo [domain]] [helo [domain]] [mailfrom <addr>] [rcptto <addr>] [data] [quit] [cmd <verb>] [param <arg>] [code <u16>] [reply <text>] [body <data>]`.

/// RFC 5321 Simple Mail Transfer Protocol (SMTP) command or reply specification.
///
/// Syntax mapping: `smtp [ehlo [str]] [helo [str]] [mailfrom <str>] [rcptto <str>] [data] [quit] [cmd <str>] [param <str>] [code <u16>] [reply <str>] [body <str>]`
#[doc(alias = "smtp")]
#[doc(alias = "RFC 5321")]
#[doc(alias = "RFC5321")]
#[doc(alias = "RFC 5322")]
#[doc(alias = "ehlo")]
#[doc(alias = "helo")]
#[doc(alias = "mailfrom")]
#[doc(alias = "rcptto")]
#[doc(alias = "data")]
#[doc(alias = "quit")]
#[doc(alias = "cmd")]
#[doc(alias = "param")]
#[doc(alias = "code")]
#[doc(alias = "reply")]
#[doc(alias = "body")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmtpSpec<'a> {
    /// SMTP command verb (`cmd <str>`, `ehlo`, `helo`, `mailfrom`, `rcptto`, `data`, `quit`).
    pub cmd: Option<&'a str>,
    /// SMTP command parameter or envelope address (`param <str>`).
    pub param: Option<&'a str>,
    /// 3-digit SMTP server reply status code (`code <u16>`, e.g., `220`, `250`, `354`, `550`).
    pub code: Option<u16>,
    /// SMTP server reply text message (`reply <str>`).
    pub reply: Option<&'a str>,
    /// RFC 5322 email message body payload transmitted during `data` (`body <str>`).
    pub body: Option<&'a str>,
}
