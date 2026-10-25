//! sFlow Version 5 Sampled Network Telemetry (sFlow.org Version 5 Specification / RFC 3176) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! sFlow Version 5 Sampled Network Telemetry packets over UDP port 6343. On the wire, the protocol uses a 28-byte (IPv4) or 40-byte (IPv6) sFlow v5 datagram header containing 32-bit datagram_version = 5, 32-bit address_type (1 = IPv4, 2 = IPv6), Agent IP address, 32-bit sub_agent_id, 32-bit sequence_number, 32-bit sys_uptime in milliseconds, and 32-bit num_samples count followed by XDR-encoded flow sample and counter sample records.
//! Every field in [`SflowSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SFLOW [AGENT_IP <ip>] [SUB_AGENT_ID <u32>] [SEQ <u32>] [UPTIME <u32>] [SAMPLES <u32>]`

use core::marker::PhantomData;
use core::net::IpAddr;
/// sFlow v5 network monitoring datagram specification.
///
/// Syntax mapping: `SFLOW [AGENT_IP <ip>] [SUB_AGENT_ID <u32>] [SEQ <u32>] [UPTIME <u32>] [SAMPLES <u32>]`
#[doc(alias = "SFLOW")]
#[doc(alias = "RFC 3176")]
#[doc(alias = "RFC3176")]
#[doc(alias = "SFLOWV5")]
#[doc(alias = "AGENT_IP")]
#[doc(alias = "SUB_AGENT_ID")]
#[doc(alias = "SEQ")]
#[doc(alias = "UPTIME")]
#[doc(alias = "SAMPLES")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SflowSpec<'a> {
    /// Agent IP address.
    pub agent_ip: Option<IpAddr>,
    /// Sub-agent identifier.
    pub sub_agent_id: Option<u32>,
    /// Sequence number.
    pub seq: Option<u32>,
    /// System uptime in milliseconds.
    pub uptime: Option<u32>,
    /// Number of samples.
    pub samples: Option<u32>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
