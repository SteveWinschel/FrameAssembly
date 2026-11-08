//! Deterministic host topology discovery and directional endpoint resolution for `frameassembly reverse`.
//!
//! This module implements Stage 3 of the FrameAssembly reverse decompiler pipeline. Given a slice
//! of [`DissectedPacket`] frames, [`build_topology`] discovers all unique network endpoints in
//! deterministic order of first appearance, assigns sequential `host_1`, `host_2`, ... identifiers,
//! tracks dominant unicast MAC addresses per IP endpoint, pairs broadcast/multicast/unspecified
//! frames with same-family peer hosts without polluting the `host` table with multicast/broadcast
//! addresses, locks directional arrows (`->` vs `<-`) per unordered host pair, and computes
//! minimal `srcmac`/`dstmac` statement overrides where wire MACs diverge from FrameAssembly's
//! [`derive_mac`] and protocol builders.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;

use crate::ast::{Direction, Protocol};

use super::DissectedPacket;

/// A single network endpoint discovered from the packet capture and emitted as a `host` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscoveredHost {
    /// Canonical lowercase identifier (`"host_1"`, `"host_2"`, ...).
    pub name: String,
    /// Unicast IPv4 or IPv6 address for IP-capable hosts, or `None` for pure-L2 MAC-only hosts.
    pub ip: Option<IpAddr>,
    /// Dominant unicast MAC address observed on Ethernet, or `None` for L3-only captures.
    pub mac: Option<[u8; 6]>,
}

/// Resolved caller/callee host indices, statement direction, and explicit MAC overrides for a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedFrameEndpoints {
    /// Index into [`CaptureTopology::hosts`] for the left-hand (`caller`) endpoint.
    pub caller_idx: usize,
    /// Index into [`CaptureTopology::hosts`] for the right-hand (`callee`) endpoint.
    pub callee_idx: usize,
    /// Frame direction relative to `caller_idx` and `callee_idx` (`->` or `<-`).
    pub dir: Direction,
    /// Explicit `srcmac` modifier when the wire source MAC differs from compiler synthesis.
    pub emit_src_mac: Option<[u8; 6]>,
    /// Explicit `dstmac` modifier when the wire destination MAC differs from compiler synthesis.
    pub emit_dst_mac: Option<[u8; 6]>,
}

/// Complete host table and per-frame endpoint resolution produced by [`build_topology`].
#[derive(Debug, Clone)]
pub(crate) struct CaptureTopology {
    /// Ordered list of discovered `host_1`, `host_2`, ... definitions.
    pub hosts: Vec<DiscoveredHost>,
    /// Per-packet resolved endpoints (1-to-1 with the input `packets` slice).
    pub frame_endpoints: Vec<ResolvedFrameEndpoints>,
}

/// Tracks MAC address observations and L3-only flags for a discovered IP host.
#[derive(Debug)]
struct IpHostAccumulator {
    /// Weighted counts of observed unicast MAC addresses `(mac, weight)`.
    mac_weights: Vec<([u8; 6], u32)>,
    /// Whether every packet involving this IP host came from an L3-only linktype.
    all_l3_only: bool,
}

impl Default for IpHostAccumulator {
    fn default() -> Self {
        Self {
            mac_weights: Vec::new(),
            all_l3_only: true,
        }
    }
}

impl IpHostAccumulator {
    /// Records an observed MAC address and linktype flag with the given weight.
    fn record(&mut self, mac: [u8; 6], is_l3_only: bool, weight: u32) {
        if !is_l3_only {
            self.all_l3_only = false;
            if is_unicast_mac(mac) {
                if let Some(entry) = self.mac_weights.iter_mut().find(|(m, _)| *m == mac) {
                    entry.1 = entry.1.saturating_add(weight);
                } else {
                    self.mac_weights.push((mac, weight));
                }
            }
        }
    }

    /// Returns the dominant unicast MAC address (breaking ties by first appearance), or `None` if L3-only.
    fn dominant_mac(&self) -> Option<[u8; 6]> {
        if self.all_l3_only {
            return None;
        }
        self.mac_weights
            .iter()
            .max_by_key(|(_, w)| *w)
            .map(|(m, _)| *m)
    }
}

/// Returns `true` if `ip` is a routable/link-local unicast IPv4 or IPv6 host address
/// (excluding unspecified `0.0.0.0`/`::`, broadcast `255.255.255.255`, and multicast `224.0.0.0/4`/`ff00::/8`).
pub(crate) fn is_unicast_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_multicast(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

/// Returns `true` if `mac` is a non-zero individual (unicast) IEEE 802 MAC address
/// (bit 0 of byte 0 is `0`, excluding broadcast `ff:ff:ff:ff:ff:ff` and multicast `01:80:c2:*`, `01:00:5e:*`, `33:33:*`).
pub(crate) fn is_unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0, 0, 0, 0, 0, 0] && (mac[0] & 0x01) == 0
}

/// Mirrors `src/backend/mod.rs::derive_mac` to predict the Ethernet MAC address that FrameAssembly
/// will synthesize for an endpoint when `stmt_mac` is `None`.
pub(crate) fn derive_mac(
    host_mac: Option<[u8; 6]>,
    stmt_mac: Option<[u8; 6]>,
    ip: Option<IpAddr>,
    is_caller: bool,
) -> [u8; 6] {
    if let Some(mac) = stmt_mac {
        return mac;
    }
    if let Some(mac) = host_mac {
        return mac;
    }
    match ip {
        Some(IpAddr::V6(v6)) => {
            let octets = v6.octets();
            if octets[0] == 0xFF {
                [0x33, 0x33, octets[12], octets[13], octets[14], octets[15]]
            } else if is_caller {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            }
        }
        Some(IpAddr::V4(v4)) => {
            let octets = v4.octets();
            if (224..=239).contains(&octets[0]) {
                [0x01, 0x00, 0x5E, octets[1] & 0x7F, octets[2], octets[3]]
            } else if is_caller {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            }
        }
        None => {
            if is_caller {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            } else {
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
            }
        }
    }
}

/// Predicts the `(src_mac, dst_mac)` that FrameAssembly's forward compiler will emit for `pkt`
/// when `srcmac` and `dstmac` modifiers are omitted.
fn predict_synthesized_macs(
    pkt: &DissectedPacket,
    caller_host: &DiscoveredHost,
    callee_host: &DiscoveredHost,
    dir: Direction,
) -> ([u8; 6], [u8; 6]) {
    let (src_host, dst_host, is_forward) = match dir {
        Direction::LeftToRight => (caller_host, callee_host, true),
        Direction::RightToLeft => (callee_host, caller_host, false),
    };

    let synth_src = derive_mac(src_host.mac, None, src_host.ip, is_forward);
    let synth_dst = match pkt.dissection.protocol {
        Protocol::Lldp => [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e],
        Protocol::Stp => [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00],
        Protocol::Lacp => [0x01, 0x80, 0xc2, 0x00, 0x00, 0x02],
        Protocol::Eapol => [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03],
        Protocol::Arp => {
            let is_reply = pkt
                .dissection
                .tokens
                .split_whitespace()
                .any(|tok| tok == "reply");
            if is_reply {
                derive_mac(dst_host.mac, None, dst_host.ip, !is_forward)
            } else {
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
            }
        }
        Protocol::Ndp
        | Protocol::Igmp
        | Protocol::Mld
        | Protocol::Ospf
        | Protocol::Rip
        | Protocol::Vrrp
        | Protocol::Hsrp
        | Protocol::Pim
        | Protocol::Mdns => derive_mac(None, None, pkt.dst_ip, false),
        Protocol::Ssdp => {
            let is_notify = pkt
                .dissection
                .tokens
                .split_whitespace()
                .any(|tok| tok == "notify");
            let is_msearch = !pkt
                .dissection
                .tokens
                .split_whitespace()
                .any(|tok| tok == "response");
            if is_notify || is_msearch {
                derive_mac(None, None, pkt.dst_ip, false)
            } else {
                derive_mac(dst_host.mac, None, dst_host.ip, !is_forward)
            }
        }
        _ => derive_mac(dst_host.mac, None, dst_host.ip, !is_forward),
    };

    (synth_src, synth_dst)
}

/// Discovers network hosts and resolves per-packet directional endpoints across `packets`.
pub(crate) fn build_topology(packets: &[DissectedPacket]) -> CaptureTopology {
    if packets.is_empty() {
        return CaptureTopology {
            hosts: Vec::new(),
            frame_endpoints: Vec::new(),
        };
    }

    let mut hosts: Vec<DiscoveredHost> = Vec::new();
    let mut ip_to_host: HashMap<IpAddr, usize> = HashMap::new();
    let mut ip_accumulators: HashMap<usize, IpHostAccumulator> = HashMap::new();
    let mut mac_to_l2_host: HashMap<[u8; 6], usize> = HashMap::new();

    // Pass 1: Discover all unicast IP hosts and pure-L2 MAC-only hosts in order of first appearance.
    for pkt in packets {
        let is_ip_domain = pkt.has_ip_header || pkt.dissection.protocol == Protocol::Arp;
        if is_ip_domain {
            if let Some(sip) = pkt.src_ip
                && is_unicast_ip(sip)
            {
                let idx = *ip_to_host.entry(sip).or_insert_with(|| {
                    let new_idx = hosts.len();
                    hosts.push(DiscoveredHost {
                        name: format!("host_{}", new_idx + 1),
                        ip: Some(sip),
                        mac: None,
                    });
                    new_idx
                });
                ip_accumulators
                    .entry(idx)
                    .or_default()
                    .record(pkt.src_mac, pkt.is_l3_only, 2);
            }
            if let Some(dip) = pkt.dst_ip
                && is_unicast_ip(dip)
            {
                let idx = *ip_to_host.entry(dip).or_insert_with(|| {
                    let new_idx = hosts.len();
                    hosts.push(DiscoveredHost {
                        name: format!("host_{}", new_idx + 1),
                        ip: Some(dip),
                        mac: None,
                    });
                    new_idx
                });
                ip_accumulators
                    .entry(idx)
                    .or_default()
                    .record(pkt.dst_mac, pkt.is_l3_only, 1);
            }
        } else {
            if is_unicast_mac(pkt.src_mac) {
                mac_to_l2_host.entry(pkt.src_mac).or_insert_with(|| {
                    let new_idx = hosts.len();
                    hosts.push(DiscoveredHost {
                        name: format!("host_{}", new_idx + 1),
                        ip: None,
                        mac: Some(pkt.src_mac),
                    });
                    new_idx
                });
            }
            if is_unicast_mac(pkt.dst_mac) {
                mac_to_l2_host.entry(pkt.dst_mac).or_insert_with(|| {
                    let new_idx = hosts.len();
                    hosts.push(DiscoveredHost {
                        name: format!("host_{}", new_idx + 1),
                        ip: None,
                        mac: Some(pkt.dst_mac),
                    });
                    new_idx
                });
            }
        }
    }

    // Finalize dominant unicast MACs for discovered IP hosts.
    for (idx, acc) in &ip_accumulators {
        if let Some(host) = hosts.get_mut(*idx) {
            host.mac = acc.dominant_mac();
        }
    }

    // Pass 2: Resolve `(src_idx, dst_idx)` for each packet, creating fallback peer hosts only when
    // broadcast/multicast/unspecified frames lack a second same-family peer in `hosts`.
    let mut pair_initiators: HashMap<(usize, usize), (usize, usize)> = HashMap::new();
    let mut frame_endpoints = Vec::with_capacity(packets.len());

    for pkt in packets {
        let is_ip_domain = pkt.has_ip_header || pkt.dissection.protocol == Protocol::Arp;
        let (src_idx, dst_idx) = if is_ip_domain {
            let is_v6 = matches!(pkt.src_ip, Some(IpAddr::V6(_)))
                || matches!(pkt.dst_ip, Some(IpAddr::V6(_)));
            let s_opt = pkt
                .src_ip
                .filter(|&ip| is_unicast_ip(ip))
                .and_then(|ip| ip_to_host.get(&ip).copied());
            let d_opt = pkt
                .dst_ip
                .filter(|&ip| is_unicast_ip(ip))
                .and_then(|ip| ip_to_host.get(&ip).copied());

            match (s_opt, d_opt) {
                (Some(s), Some(d)) if s != d => (s, d),
                (Some(s), _) => {
                    let d = find_or_create_ip_peer(
                        &mut hosts,
                        &mut ip_to_host,
                        Some(s),
                        is_v6,
                        pkt.dst_mac,
                        pkt.is_l3_only,
                    );
                    (s, d)
                }
                (None, Some(d)) => {
                    let s = find_or_create_ip_peer(
                        &mut hosts,
                        &mut ip_to_host,
                        Some(d),
                        is_v6,
                        pkt.src_mac,
                        pkt.is_l3_only,
                    );
                    (s, d)
                }
                (None, None) => {
                    let s = find_or_create_ip_peer(
                        &mut hosts,
                        &mut ip_to_host,
                        None,
                        is_v6,
                        pkt.src_mac,
                        pkt.is_l3_only,
                    );
                    let d = find_or_create_ip_peer(
                        &mut hosts,
                        &mut ip_to_host,
                        Some(s),
                        is_v6,
                        pkt.dst_mac,
                        pkt.is_l3_only,
                    );
                    (s, d)
                }
            }
        } else {
            let s_opt = is_unicast_mac(pkt.src_mac)
                .then(|| mac_to_l2_host.get(&pkt.src_mac).copied())
                .flatten();
            let d_opt = is_unicast_mac(pkt.dst_mac)
                .then(|| mac_to_l2_host.get(&pkt.dst_mac).copied())
                .flatten();

            match (s_opt, d_opt) {
                (Some(s), Some(d)) if s != d => (s, d),
                (Some(s), _) => {
                    let d = find_or_create_l2_peer(&mut hosts, &mut mac_to_l2_host, Some(s));
                    (s, d)
                }
                (None, Some(d)) => {
                    let s = find_or_create_l2_peer(&mut hosts, &mut mac_to_l2_host, Some(d));
                    (s, d)
                }
                (None, None) => {
                    let s = find_or_create_l2_peer(&mut hosts, &mut mac_to_l2_host, None);
                    let d = find_or_create_l2_peer(&mut hosts, &mut mac_to_l2_host, Some(s));
                    (s, d)
                }
            }
        };

        let unordered_key = if src_idx <= dst_idx {
            (src_idx, dst_idx)
        } else {
            (dst_idx, src_idx)
        };
        let &mut (caller_idx, callee_idx) = pair_initiators
            .entry(unordered_key)
            .or_insert((src_idx, dst_idx));
        let dir = if src_idx == caller_idx {
            Direction::LeftToRight
        } else {
            Direction::RightToLeft
        };

        let (synth_src, synth_dst) =
            predict_synthesized_macs(pkt, &hosts[caller_idx], &hosts[callee_idx], dir);
        let emit_src_mac = (pkt.src_mac != synth_src).then_some(pkt.src_mac);
        let emit_dst_mac = (pkt.dst_mac != synth_dst).then_some(pkt.dst_mac);

        frame_endpoints.push(ResolvedFrameEndpoints {
            caller_idx,
            callee_idx,
            dir,
            emit_src_mac,
            emit_dst_mac,
        });
    }

    CaptureTopology {
        hosts,
        frame_endpoints,
    }
}

/// Finds an existing IP host of the matching address family (`is_v6`) distinct from `exclude_idx`,
/// or synthesizes a new peer IP host when fewer than two hosts of that family exist in the capture.
fn find_or_create_ip_peer(
    hosts: &mut Vec<DiscoveredHost>,
    ip_to_host: &mut HashMap<IpAddr, usize>,
    exclude_idx: Option<usize>,
    is_v6: bool,
    observed_mac: [u8; 6],
    is_l3_only: bool,
) -> usize {
    // 1. Prefer an existing same-family host whose MAC matches `observed_mac` (when unicast).
    if is_unicast_mac(observed_mac)
        && let Some((idx, _)) = hosts.iter().enumerate().find(|(i, h)| {
            Some(*i) != exclude_idx
                && h.ip.is_some_and(|ip| ip.is_ipv6() == is_v6)
                && h.mac == Some(observed_mac)
        })
    {
        return idx;
    }

    // 2. Otherwise pick the first existing same-family host distinct from `exclude_idx`.
    if let Some((idx, _)) = hosts
        .iter()
        .enumerate()
        .find(|(i, h)| Some(*i) != exclude_idx && h.ip.is_some_and(|ip| ip.is_ipv6() == is_v6))
    {
        return idx;
    }

    // 3. No peer host of this IP family exists yet; synthesize a deterministic RFC 5737 / RFC 3849 peer.
    let mut candidate_idx = 254u16;
    let new_ip = loop {
        let ip = if is_v6 {
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, candidate_idx))
        } else {
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, (candidate_idx & 0xff) as u8))
        };
        if !ip_to_host.contains_key(&ip) {
            break ip;
        }
        candidate_idx = candidate_idx.wrapping_sub(1).max(1);
    };

    let new_idx = hosts.len();
    let mac = if is_l3_only {
        None
    } else if is_unicast_mac(observed_mac) {
        Some(observed_mac)
    } else if exclude_idx.is_none() {
        Some([0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
    } else {
        Some([0x00, 0x00, 0x00, 0x00, 0x00, 0x02])
    };
    hosts.push(DiscoveredHost {
        name: format!("host_{}", new_idx + 1),
        ip: Some(new_ip),
        mac,
    });
    ip_to_host.insert(new_ip, new_idx);
    new_idx
}

/// Finds an existing pure-L2 MAC-only host distinct from `exclude_idx`, or synthesizes one.
fn find_or_create_l2_peer(
    hosts: &mut Vec<DiscoveredHost>,
    mac_to_l2_host: &mut HashMap<[u8; 6], usize>,
    exclude_idx: Option<usize>,
) -> usize {
    if let Some((idx, _)) = hosts
        .iter()
        .enumerate()
        .find(|(i, h)| Some(*i) != exclude_idx && h.ip.is_none())
    {
        return idx;
    }

    let mut suffix = if exclude_idx.is_none() { 1u8 } else { 2u8 };
    let mac = loop {
        let candidate = [0x00, 0x00, 0x00, 0x00, 0x00, suffix];
        if !mac_to_l2_host.contains_key(&candidate)
            && !hosts.iter().any(|h| h.mac == Some(candidate))
        {
            break candidate;
        }
        suffix = suffix.wrapping_add(1).max(1);
    };

    let new_idx = hosts.len();
    hosts.push(DiscoveredHost {
        name: format!("host_{}", new_idx + 1),
        ip: None,
        mac: Some(mac),
    });
    mac_to_l2_host.insert(mac, new_idx);
    new_idx
}
