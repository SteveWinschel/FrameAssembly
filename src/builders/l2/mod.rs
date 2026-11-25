//! Layer 2 Data Link and Carrier Ethernet protocol wire builders.
//!
//! This module contains the binary packet synthesizers for IEEE 802, IETF, and industrial
//! Layer 2/2.5 protocols, assembling Ethernet II (`DIX`) and IEEE 802.3 LLC frames with optional
//! IEEE 802.1Q VLAN (`0x8100`), IEEE 802.1ad QinQ (`0x88A8`), and RFC 3032 MPLS (`0x8847`)
//! shim headers. Supported builders include ARP (`0x0806`), CDP (`0x2000` / 802.3 LLC), EAPOL
//! (`0x888E`), EtherCAT (`0x88A4` / UDP `34980`), GOOSE (`0x88B8`), IS-IS (`0xFEFE03` / 802.3
//! LLC), LACP (`0x8809`), LLDP (`0x88CC`), MACsec (`0x88E5`), MPLS (`0x8847`), NSH (`0x894F`),
//! PFC (`0x8808`), PPPoE (`0x8863` / `0x8864`), PROFINET (`0x8892` / UDP `34964`), QinQ (`0x88A8`),
//! STP/RSTP (`0x424203`), SV (`0x88BA`), and VLAN (`0x8100`).

pub mod arp;
pub mod cdp;
pub mod eapol;
pub mod ethercat;
pub mod goose;
pub mod isis;
pub mod lacp;
pub mod lldp;
pub mod macsec;
pub mod mpls;
pub mod nsh;
pub mod pfc;
pub mod pppoe;
pub mod profinet;
pub mod qinq;
pub mod stp;
pub mod sv;
pub mod vlan;

#[doc(inline)]
pub use arp::*;
#[doc(inline)]
pub use cdp::*;
#[doc(inline)]
pub use eapol::*;
#[doc(inline)]
pub use ethercat::*;
#[doc(inline)]
pub use goose::*;
#[doc(inline)]
pub use isis::*;
#[doc(inline)]
pub use lacp::*;
#[doc(inline)]
pub use lldp::*;
#[doc(inline)]
pub use macsec::*;
#[doc(inline)]
pub use mpls::*;
#[doc(inline)]
pub use nsh::*;
#[doc(inline)]
pub use pfc::*;
#[doc(inline)]
pub use pppoe::*;
#[doc(inline)]
pub use profinet::*;
#[doc(inline)]
pub use qinq::*;
#[doc(inline)]
pub use stp::*;
#[doc(inline)]
pub use sv::*;
#[doc(inline)]
pub use vlan::*;
