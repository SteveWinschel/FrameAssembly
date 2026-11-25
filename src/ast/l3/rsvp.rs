//! Resource Reservation Protocol (RSVP / RSVP-TE, RFC 2205 / RFC 3209) AST definitions.
//!
//! Defines [`RsvpSpec`] and [`RsvpType`] for Resource Reservation Protocol and RSVP Traffic
//! Engineering control messages carried directly over IP protocol `46` (`0x2E`). Covers `path`,
//! `resv`, `patherr`, `resverr`, `pathtear`, `resvtear`, `resvconf`, and RFC 3209 `hello`
//! messages along with `tunnelid`, `lspid`, MPLS `label`, `refresh` period, session `srcip` /
//! `dstip` endpoints, and `ERROR_SPEC` `errcode`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b rsvp [path | resv | patherr | resverr | pathtear | resvtear | resvconf | hello] [tunnelid <u16>] [lspid <u16>] [label <u32>] [refresh <u32>] [srcip <ip>] [dstip <ip>] [errcode <u8>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 2205 / RFC 3209 RSVP message type code.
#[doc(alias = "RsvpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsvpType {
    /// Type `1` (`path`): Downstream path state setup and sender characterization.
    Path,
    /// Type `2` (`resv`): Upstream reservation request carrying label and flow descriptors.
    Resv,
    /// Type `3` (`patherr`): Upstream Path error notification.
    PathErr,
    /// Type `4` (`resverr`): Downstream Reservation error notification.
    ResvErr,
    /// Type `5` (`pathtear`): Downstream explicit Path state teardown.
    PathTear,
    /// Type `6` (`resvtear`): Upstream explicit Reservation state teardown.
    ResvTear,
    /// Type `7` (`resvconf`): Downstream Reservation confirmation.
    ResvConf,
    /// Type `20` (`hello`): RFC 3209 RSVP-TE node failure detection hello message.
    Hello,
}

/// Resource Reservation Protocol (RSVP / RSVP-TE, RFC 2205 / RFC 3209) over IP protocol `46`.
///
/// Syntax mapping: `rsvp [path | resv | patherr | resverr | pathtear | resvtear | resvconf | hello] [tunnelid <u16>] [lspid <u16>] [label <u32>] [refresh <u32>] [srcip <ip>] [dstip <ip>] [errcode <u8>]`
#[doc(alias = "rsvp")]
#[doc(alias = "RSVP-TE")]
#[doc(alias = "RFC 2205")]
#[doc(alias = "RFC2205")]
#[doc(alias = "RFC 3209")]
#[doc(alias = "RFC3209")]
#[doc(alias = "path")]
#[doc(alias = "resv")]
#[doc(alias = "patherr")]
#[doc(alias = "resverr")]
#[doc(alias = "pathtear")]
#[doc(alias = "resvtear")]
#[doc(alias = "resvconf")]
#[doc(alias = "hello")]
#[doc(alias = "tunnelid")]
#[doc(alias = "lspid")]
#[doc(alias = "label")]
#[doc(alias = "refresh")]
#[doc(alias = "srcip")]
#[doc(alias = "dstip")]
#[doc(alias = "errcode")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RsvpSpec<'a> {
    /// RSVP message type (`path` default).
    pub msg_type: Option<RsvpType>,
    /// 16-bit RSVP-TE Tunnel ID (`tunnelid <u16>`, switches `SESSION` to LSP_TUNNEL C-Type `7`/`8`).
    pub tunnel_id: Option<u16>,
    /// 16-bit RSVP-TE LSP ID (`lspid <u16>`, switches `SENDER_TEMPLATE` / `FILTER_SPEC` to C-Type `7`/`8`).
    pub lsp_id: Option<u16>,
    /// 20-bit MPLS Label encoded in `LABEL` object Class `16` (`label <u32>`).
    pub label: Option<u32>,
    /// 32-bit `TIME_VALUES` refresh period in milliseconds (`refresh <u32>`, default `30000`).
    pub refresh: Option<u32>,
    /// Session/Sender source IP override (`srcip <ip>`, defaults to `ctx.src_ip`).
    pub src_ip: Option<IpAddr>,
    /// Session destination IP override (`dstip <ip>`, defaults to `ctx.dst_ip`).
    pub dst_ip: Option<IpAddr>,
    /// 8-bit `ERROR_SPEC` error code (`errcode <u8>`, default `2` Policy Control Failure).
    pub err_code: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
