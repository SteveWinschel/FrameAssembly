//! Media Gateway Control Protocol (MGCP, RFC 3435) Layer 7 AST definitions.
//!
//! This module defines [`MgcpSpec`], the zero-copy Abstract Syntax Tree (AST) specification for
//! synthesizing RFC 3435 Media Gateway Control Protocol (MGCP) signaling messages over UDP ports
//! 2427 (Media Gateway) and 2727 (Call Agent). On the wire, MGCP requests start with a
//! `<Verb> <TransactionID> <EndpointID> MGCP 1.0\r\n` command line (`CRCX`, `MDCX`, `DLCX`,
//! `RQNT`, `NTFY`, `AUEP`, `AUCX`, `RSIP`), while responses start with `<Status> <TransactionID>
//! <Commentary>\r\n`, followed by single-letter parameter lines (`C:`, `I:`, `L:`, `M:`) and an
//! optional CRLF-separated SDP media body.
//!
//! Canonical `.frasm` syntax:
//! `a -> b mgcp [crcx | mdcx | dlcx | rqnt | ntfy | auep | aucx | rsip | method <str>] [txid <u32>] [endpoint <str>] [status <u16>] [reason <str>] [callid <str>] [connid <str>] [localopts <str>] [mode <str>] [body <str>] [transport tcp]`

/// RFC 3435 Media Gateway Control Protocol (MGCP) specification.
///
/// Syntax mapping: `mgcp [crcx | mdcx | dlcx | rqnt | ntfy | auep | aucx | rsip | method <str>] [txid <u32>] [endpoint <str>] [status <u16>] [reason <str>] [callid <str>] [connid <str>] [localopts <str>] [mode <str>] [body <str>] [transport tcp]`
#[doc(alias = "mgcp")]
#[doc(alias = "RFC 3435")]
#[doc(alias = "RFC3435")]
#[doc(alias = "2427")]
#[doc(alias = "2727")]
#[doc(alias = "crcx")]
#[doc(alias = "mdcx")]
#[doc(alias = "dlcx")]
#[doc(alias = "rqnt")]
#[doc(alias = "ntfy")]
#[doc(alias = "auep")]
#[doc(alias = "aucx")]
#[doc(alias = "rsip")]
#[doc(alias = "method")]
#[doc(alias = "txid")]
#[doc(alias = "endpoint")]
#[doc(alias = "status")]
#[doc(alias = "reason")]
#[doc(alias = "callid")]
#[doc(alias = "connid")]
#[doc(alias = "localopts")]
#[doc(alias = "mode")]
#[doc(alias = "body")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MgcpSpec<'a> {
    /// MGCP command verb (`crcx`, `mdcx`, `dlcx`, `rqnt`, `ntfy`, `auep`, `aucx`, `rsip`).
    pub method: Option<&'a str>,
    /// MGCP transaction ID (`txid <u32>`, default `1`).
    pub txid: Option<u32>,
    /// Target MGCP endpoint name (`endpoint <str>`, default `"aaln/1@gw1.example.com"`).
    pub endpoint: Option<&'a str>,
    /// MGCP numeric response code (`status <u16>`, e.g., `200`, `250`, `400`).
    pub status: Option<u16>,
    /// MGCP response commentary text (`reason <str>`, default `"OK"` for `200`).
    pub reason: Option<&'a str>,
    /// MGCP Call-Id (`C:` parameter, `callid <str>`).
    pub call_id: Option<&'a str>,
    /// MGCP Connection-Id (`I:` parameter, `connid <str>`).
    pub conn_id: Option<&'a str>,
    /// MGCP LocalConnectionOptions (`L:` parameter, `localopts <str>`).
    pub local_opts: Option<&'a str>,
    /// MGCP ConnectionMode (`M:` parameter, `mode <str>`, e.g., `"sendrecv"`).
    pub mode: Option<&'a str>,
    /// Optional SDP session description body (`body <str>`).
    pub body: Option<&'a str>,
}
