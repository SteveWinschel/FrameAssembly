//! Layer 4 Transport protocol wire builders and Castagnoli CRC32c engine.
//!
//! This module provides binary wire synthesizers for Layer 4 transport segments encapsulated
//! inside IPv4 (`0x0800`) and IPv6 (`0x86DD`) packets:
//! - **SCTP** (`proto = 132`, RFC 9260 / RFC 4960) Common Header, multi-chunk assembly, and
//!   hardware-equivalent reflected Castagnoli CRC32c (`0x82F63B78`) checksum computation
//! - **TCP** (`proto = 6`, RFC 9293 / RFC 7323) segment and option framing
//! - **UDP** (`proto = 17`, RFC 768) connectionless datagram framing

pub mod sctp;
pub mod tcp;
pub mod udp;

#[doc(inline)]
pub use sctp::*;
#[doc(inline)]
pub use tcp::*;
#[doc(inline)]
pub use udp::*;

