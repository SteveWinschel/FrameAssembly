//! Layer 4 transport protocol (`tcp`, `udp`, `sctp`) PCAP-to-`.fasm` decompilers.
//!
//! This module organizes the Layer 4 transport header dissectors for FrameAssembly's PCAP and
//! PCAPNG to `.fasm` reverse decompiler pipeline:
//! - [`tcp`]: RFC 9293 TCP header slicing, sequence/acknowledgment/window extraction, and RFC 7323
//!   option parsing (`mss`, `wscale`, `sackperm`, `tsval`, `tsecr`).
//! - [`udp`]: RFC 768 UDP datagram header slicing and port extraction.
//! - [`sctp`]: RFC 9260 SCTP common header, verification tag (`vtag`), and multi-chunk (`data`,
//!   `init`, `initack`, `sack`, `heartbeat`, `heartbeatack`, `abort`, `shutdown`, `shutdownack`,
//!   `cookieecho`, `cookieack`) decompilation.

pub(crate) mod sctp;
pub(crate) mod tcp;
pub(crate) mod udp;
