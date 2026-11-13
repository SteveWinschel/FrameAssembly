//! Multi-Layer Wire Packet Builders for the FrameAssembly Compiler.
//!
//! This module hierarchy implements deterministic wire-format packet synthesis across all 81 native
//! protocols spanning OSI Layer 2 ([`l2`]: `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`,
//! and `mpls`), Layer 3 ([`l3`]: `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`,
//! `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, and
//! `openflow`), Layer 4 ([`l4`]: `tcp`, `udp`, and `sctp`), and Layer 7 ([`l7`]: 50 infrastructure,
//! web, cloud, mail, directory, storage, database, messaging, industrial OT/ICS, and
//! `snmp1`/`snmp2`/`snmp3` protocols).

use crate::ast::{L2Modifiers, L3Modifiers, L4Modifiers, TransportProto};
use core::net::IpAddr;

/// Wire synthesis context holding resolved endpoint addresses, transport ports, and layer modifiers.
#[derive(Debug, Clone)]
pub struct WireContext<'a> {
    /// Resolved source IPv4 or IPv6 address.
    pub src_ip: IpAddr,
    /// Resolved destination IPv4 or IPv6 address.
    pub dst_ip: IpAddr,
    /// Resolved 6-byte source IEEE 802.3 MAC address.
    pub src_mac: [u8; 6],
    /// Resolved 6-byte destination IEEE 802.3 MAC address.
    pub dst_mac: [u8; 6],
    /// Optional explicit transport protocol override (`tcp` or `udp`).
    pub transport: Option<TransportProto>,
    /// Resolved 16-bit source transport port (`srcport`).
    pub src_port: u16,
    /// Resolved 16-bit destination transport port (`dstport`).
    pub dst_port: u16,
    /// Optional explicit 32-bit TCP sequence number (`seq`).
    pub seq: Option<u32>,
    /// Optional explicit 32-bit TCP acknowledgment number (`acknum`).
    pub ack: Option<u32>,
    /// Borrowed Layer 2 VLAN, QinQ, and MPLS modifiers.
    pub l2: &'a L2Modifiers,
    /// Borrowed Layer 3 TTL, DSCP, ECN, IPv4 fragment, and IPv6 flow-label modifiers.
    pub l3: &'a L3Modifiers,
    /// Borrowed Layer 4 TCP/UDP port, flag, window, and option modifiers.
    pub l4: &'a L4Modifiers,
}

pub mod l2;
pub mod l3;
pub mod l4;
pub mod l7;

/// Backwards-compatible alias for Layer 3 network and tunneling builders ([`l3`]).
#[doc(inline)]
pub use l3 as l3_tunnel;
/// Backwards-compatible alias for Layer 4 transport builders ([`l4`]).
#[doc(inline)]
pub use l4 as transport;
/// Backwards-compatible alias for Layer 7 infrastructure builders ([`l7`]).
#[doc(inline)]
pub use l7 as l7_infra;
/// Backwards-compatible alias for Layer 7 application builders ([`l7`]).
#[doc(inline)]
pub use l7 as l7_app;
/// Backwards-compatible alias for Layer 7 industrial OT/ICS builders ([`l7`]).
#[doc(inline)]
pub use l7 as l7_ot;
/// Backwards-compatible re-export of SNMPv1/v2c/v3 builders ([`l7::snmp`]).
#[doc(inline)]
pub use l7::snmp;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::l7::{
        Dnp3Spec, DnsSpec, EthernetipSpec, MemcachedSpec, ModbusSpec, OpcuaSpec, PtpSpec,
        RadiusSpec, RedisSpec, S7commSpec, SmbSpec,
    };
    use core::net::{IpAddr, Ipv4Addr};

    /// Constructs a default [`WireContext`] fixture for unit-testing L7 wire builders.
    fn sample_ctx<'a>(
        l2: &'a L2Modifiers,
        l3: &'a L3Modifiers,
        l4: &'a L4Modifiers,
    ) -> WireContext<'a> {
        WireContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            transport: None,
            src_port: 50000,
            dst_port: 502,
            seq: None,
            ack: None,
            l2,
            l3,
            l4,
        }
    }

    /// Verifies that v3.0.0 lowercase de-underscored enum inputs and uppercase/underscored inputs
    /// produce identical wire bytes while preserving exact user casing on wire string literals.
    #[test]
    fn test_v2_enum_normalization_and_literal_case_preservation() {
        let (l2, l3, l4) = (
            L2Modifiers::default(),
            L3Modifiers::default(),
            L4Modifiers::default(),
        );
        let ctx = sample_ctx(&l2, &l3, &l4);

        // Modbus function names
        let mb_v2 = l7::build_modbus_payload(
            &ctx,
            &ModbusSpec {
                func: Some("readholdingregisters"),
                count: Some(4),
                ..Default::default()
            },
            &[],
        );
        let mb_legacy = l7::build_modbus_payload(
            &ctx,
            &ModbusSpec {
                func: Some("READ_HOLDING_REGISTERS"),
                count: Some(4),
                ..Default::default()
            },
            &[],
        );
        assert_eq!(mb_v2, mb_legacy);

        // DNS qtype normalization + mixed-case qname preservation
        let dns_v2 = l7::build_dns_payload(
            &ctx,
            &DnsSpec {
                is_query: true,
                qname: Some("Api.Example.COM"),
                qtype: Some("aaaa"),
                ..Default::default()
            },
            &[],
            false,
        );
        let dns_upper = l7::build_dns_payload(
            &ctx,
            &DnsSpec {
                is_query: true,
                qname: Some("Api.Example.COM"),
                qtype: Some("AAAA"),
                ..Default::default()
            },
            &[],
            false,
        );
        assert_eq!(dns_v2, dns_upper);
        assert!(
            dns_v2
                .windows(b"Api".len())
                .any(|w| w == b"Api")
                && dns_v2
                    .windows(b"COM".len())
                    .any(|w| w == b"COM"),
            "DNS qname must preserve exact user casing on the wire"
        );

        // RADIUS code normalization
        assert_eq!(
            l7::build_radius_payload(
                &ctx,
                &RadiusSpec {
                    code: Some("accountingrequest"),
                    ..Default::default()
                },
                &[],
            ),
            l7::build_radius_payload(
                &ctx,
                &RadiusSpec {
                    code: Some("ACCOUNTING-REQUEST"),
                    ..Default::default()
                },
                &[],
            )
        );

        // PTP msgtype normalization
        assert_eq!(
            l7::build_ptp_payload(
                &ctx,
                &PtpSpec {
                    msg_type: Some("followup"),
                    ..Default::default()
                },
                &[],
            ),
            l7::build_ptp_payload(
                &ctx,
                &PtpSpec {
                    msg_type: Some("FOLLOW_UP"),
                    ..Default::default()
                },
                &[],
            )
        );

        // SMB command normalization + mixed-case UNC share preservation
        let smb_v2 = l7::build_smb_payload(
            &ctx,
            &SmbSpec {
                command: Some("treeconnect"),
                share: Some(r"\\Srv01\CorpData"),
                ..Default::default()
            },
            &[],
        );
        let smb_upper = l7::build_smb_payload(
            &ctx,
            &SmbSpec {
                command: Some("TREE_CONNECT"),
                share: Some(r"\\Srv01\CorpData"),
                ..Default::default()
            },
            &[],
        );
        assert_eq!(smb_v2, smb_upper);

        // OPC UA msgtype + chunktype normalization + mixed-case endpoint URL preservation
        let opc_v2 = l7::build_opcua_payload(
            &ctx,
            &OpcuaSpec {
                msg_type: Some("hel"),
                chunk_type: Some('c'),
                endpoint_url: Some("opc.tcp://PlcNode01:4840/UA"),
                ..Default::default()
            },
            &[],
        );
        assert_eq!(&opc_v2[0..4], b"HELC");
        assert!(
            opc_v2
                .windows(b"PlcNode01".len())
                .any(|w| w == b"PlcNode01")
        );

        // Memcached flushall -> wire "flush_all\r\n" and Redis "-" error reply prefix
        let mc_flush = l7::build_memcached_payload(
            &ctx,
            &MemcachedSpec {
                cmd: Some("flushall"),
                ..Default::default()
            },
            &[],
        );
        assert_eq!(mc_flush, b"flush_all\r\n");

        let redis_err = l7::build_redis_payload(
            &ctx,
            &RedisSpec {
                reply_type: Some("-"),
                value: Some("ERR wrongtype"),
                ..Default::default()
            },
            &[],
        );
        assert_eq!(redis_err, b"-ERR wrongtype\r\n");

        // DNP3, EtherNet/IP, and S7comm enum normalization
        assert_eq!(
            l7::build_dnp3_payload(
                &ctx,
                &Dnp3Spec {
                    func: Some("directoperate"),
                    ..Default::default()
                },
                &[],
            ),
            l7::build_dnp3_payload(
                &ctx,
                &Dnp3Spec {
                    func: Some("DIRECT_OPERATE"),
                    ..Default::default()
                },
                &[],
            )
        );
        assert_eq!(
            l7::build_ethernetip_payload(
                &ctx,
                &EthernetipSpec {
                    cmd: Some("registersession"),
                    ..Default::default()
                },
                &[],
            ),
            l7::build_ethernetip_payload(
                &ctx,
                &EthernetipSpec {
                    cmd: Some("REGISTER_SESSION"),
                    ..Default::default()
                },
                &[],
            )
        );
        assert_eq!(
            l7::build_s7comm_payload(
                &ctx,
                &S7commSpec {
                    rosctr: Some("ackdata"),
                    func: Some("setupcomm"),
                    ..Default::default()
                },
                &[],
            ),
            l7::build_s7comm_payload(
                &ctx,
                &S7commSpec {
                    rosctr: Some("ACK_DATA"),
                    func: Some("SETUP_COMM"),
                    ..Default::default()
                },
                &[],
            )
        );
    }
}
