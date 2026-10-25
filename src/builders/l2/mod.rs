//! Layer 2 Data Link and Carrier Ethernet protocol wire builders.
//!
//! This module contains the binary packet synthesizers for IEEE 802 and IETF Layer 2/2.5
//! protocols, assembling Ethernet II (`DIX`) and IEEE 802.3 LLC frames with optional
//! IEEE 802.1Q VLAN (`0x8100`), IEEE 802.1ad QinQ (`0x88A8`), and RFC 3032 MPLS (`0x8847`)
//! shim headers. Supported builders include ARP (`0x0806`), EAPOL (`0x888E`), LACP (`0x8809`),
//! LLDP (`0x88CC`), MPLS (`0x8847`), QinQ (`0x88A8`), STP/RSTP (`0x424203`), and VLAN (`0x8100`).

pub mod arp;
pub mod eapol;
pub mod lacp;
pub mod lldp;
pub mod mpls;
pub mod qinq;
pub mod stp;
pub mod vlan;

#[doc(inline)]
pub use arp::*;
#[doc(inline)]
pub use eapol::*;
#[doc(inline)]
pub use lacp::*;
#[doc(inline)]
pub use lldp::*;
#[doc(inline)]
pub use mpls::*;
#[doc(inline)]
pub use qinq::*;
#[doc(inline)]
pub use stp::*;
#[doc(inline)]
pub use vlan::*;
