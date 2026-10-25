//! Layer 3 Network, Routing, Tunneling, Redundancy, and Security protocol wire builders.
//!
//! This module contains the deterministic wire-format packet encoders for all twenty Layer 3
//! network, overlay tunneling, first-hop redundancy, dynamic routing, and cryptographic VPN
//! protocols supported by the FrameAssembly compiler backend:
//! - **AH** (`build_ipsec_ah_payload`, RFC 4302 over IP protocol `51`)
//! - **BFD** (`build_bfd_payload`, RFC 5880 over UDP port `3784`)
//! - **BGP** (`build_bgp_payload`, RFC 4271 over TCP port `179`)
//! - **ESP / IPsec** (`build_ipsec_esp_payload`, RFC 4303 over IP protocol `50`)
//! - **GENEVE** (`build_geneve_payload`, RFC 8926 over UDP port `6081`)
//! - **GRE** (`build_gre_payload`, RFC 2784 / RFC 2890 over IP protocol `47`)
//! - **HSRP** (`build_hsrp_payload`, RFC 2281 over UDP port `1985` / `2029`)
//! - **ICMP / ICMPv6** (`build_icmp_payload`, RFC 792 / RFC 4443 over IP protocol `1` / `58`)
//! - **IGMP** (`build_igmp_payload`, RFC 2236 / RFC 3376 over IP protocol `2`)
//! - **IKEv2** (`build_ikev2_payload`, RFC 7296 over UDP port `500`)
//! - **MLD** (`build_mld_payload`, RFC 2710 / RFC 3810 over ICMPv6 `58`)
//! - **NDP** (`build_ndp_payload`, RFC 4861 over ICMPv6 `58`)
//! - **OpenFlow** (`build_openflow_payload`, ONF OpenFlow v1.3+ over TCP port `6653`)
//! - **OSPF** (`build_ospf_payload`, RFC 2328 / RFC 5340 over IP protocol `89`)
//! - **PIM** (`build_pim_payload`, RFC 7761 over IP protocol `103`)
//! - **RIP** (`build_rip_payload`, RFC 2453 / RFC 2080 over UDP port `520` / `521`)
//! - **VRRP** (`build_vrrp_payload`, RFC 5798 over IP protocol `112`)
//! - **VXLAN** (`build_vxlan_payload`, RFC 7348 over UDP port `4789`)
//! - **WireGuard** (`build_wireguard_payload`, Noise_IK VPN over UDP port `51820`)

pub mod ah;
pub mod bfd;
pub mod bgp;
pub mod esp;
pub mod geneve;
pub mod gre;
pub mod hsrp;
pub mod icmp;
pub mod igmp;
pub mod ikev2;
pub mod ipsec;
pub mod mld;
pub mod ndp;
pub mod openflow;
pub mod ospf;
pub mod pim;
pub mod rip;
pub mod vrrp;
pub mod vxlan;
pub mod wireguard;

#[doc(inline)]
pub use bfd::*;
#[doc(inline)]
pub use bgp::*;
#[doc(inline)]
pub use geneve::*;
#[doc(inline)]
pub use gre::*;
#[doc(inline)]
pub use hsrp::*;
#[doc(inline)]
pub use icmp::*;
#[doc(inline)]
pub use igmp::*;
#[doc(inline)]
pub use ikev2::*;
#[doc(inline)]
pub use ipsec::*;
#[doc(inline)]
pub use mld::*;
#[doc(inline)]
pub use ndp::*;
#[doc(inline)]
pub use openflow::*;
#[doc(inline)]
pub use ospf::*;
#[doc(inline)]
pub use pim::*;
#[doc(inline)]
pub use rip::*;
#[doc(inline)]
pub use vrrp::*;
#[doc(inline)]
pub use vxlan::*;
#[doc(inline)]
pub use wireguard::*;
