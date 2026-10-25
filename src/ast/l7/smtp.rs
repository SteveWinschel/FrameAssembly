//! Simple Mail Transfer Protocol (SMTP, RFC 5321) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`SmtpSpec`], the zero-copy AST representation of an RFC 5321 Simple Mail
//! Transfer Protocol (SMTP) command or server reply over TCP ports 25 (MTA relay), 465 (SMTPS),
//! and 587 (MSA message submission, RFC 6409). On the wire, SMTP exchanges CRLF-terminated ASCII
//! command lines (`EHLO`, `HELO`, `MAIL FROM:<...>`, `RCPT TO:<...>`, `DATA`, `STARTTLS`, `AUTH`,
//! `QUIT`) and 3-digit status replies (`220`, `250`, `354`, `221`, `550`) followed by optional
//! RFC 5322 message bodies. Canonical FrameAssembly `.fasm` syntax models SMTP frames using
//! `SMTP [EHLO [domain]] [HELO [domain]] [MAIL_FROM <addr>] [RCPT_TO <addr>] [DATA] [QUIT] [CMD <verb>] [PARAM <arg>] [CODE <u16>] [REPLY <text>] [BODY <data>]`.

/// RFC 5321 Simple Mail Transfer Protocol (SMTP) command or reply specification.
///
/// Syntax mapping: `SMTP [EHLO [str]] [HELO [str]] [MAIL_FROM <str>] [RCPT_TO <str>] [DATA] [QUIT] [CMD <str>] [PARAM <str>] [CODE <u16>] [REPLY <str>] [BODY <str>]`
#[doc(alias = "SMTP")]
#[doc(alias = "RFC 5321")]
#[doc(alias = "RFC5321")]
#[doc(alias = "RFC 5322")]
#[doc(alias = "EHLO")]
#[doc(alias = "HELO")]
#[doc(alias = "MAIL_FROM")]
#[doc(alias = "RCPT_TO")]
#[doc(alias = "DATA")]
#[doc(alias = "QUIT")]
#[doc(alias = "CMD")]
#[doc(alias = "PARAM")]
#[doc(alias = "CODE")]
#[doc(alias = "REPLY")]
#[doc(alias = "BODY")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmtpSpec<'a> {
    /// SMTP command verb (`CMD <str>`, `EHLO`, `HELO`, `MAIL_FROM`, `RCPT_TO`, `DATA`, `QUIT`).
    pub cmd: Option<&'a str>,
    /// SMTP command parameter or envelope address (`PARAM <str>`).
    pub param: Option<&'a str>,
    /// 3-digit SMTP server reply status code (`CODE <u16>`, e.g., `220`, `250`, `354`, `550`).
    pub code: Option<u16>,
    /// SMTP server reply text message (`REPLY <str>`).
    pub reply: Option<&'a str>,
    /// RFC 5322 email message body payload transmitted during `DATA` (`BODY <str>`).
    pub body: Option<&'a str>,
}
