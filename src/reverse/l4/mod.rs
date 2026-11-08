//! Layer 4 transport protocol (`TCP`, `UDP`, `SCTP`) PCAP-to-`.fasm` decompilers.
//!
//! This module organizes the Layer 4 transport header dissectors for FrameAssembly's PCAP and
//! PCAPNG to `.fasm` reverse decompiler pipeline:
//! - [`tcp`]: RFC 9293 TCP header slicing, sequence/acknowledgment/window extraction, and RFC 7323
//!   option parsing (`MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`, `TSECR`).
//! - [`udp`]: RFC 768 UDP datagram header slicing and port extraction.
//! - [`sctp`]: RFC 9260 SCTP common header, verification tag (`vtag`), and multi-chunk (`DATA`,
//!   `INIT`, `INIT_ACK`, `SACK`, `HEARTBEAT`, `HEARTBEAT_ACK`, `ABORT`, `SHUTDOWN`, `COOKIE_ECHO`,
//!   `COOKIE_ACK`) decompilation.

pub(crate) mod sctp;
pub(crate) mod tcp;
pub(crate) mod udp;
