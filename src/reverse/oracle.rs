//! Self-checking in-memory compiler oracle for the FrameAssembly reverse decompiler pipeline.
//!
//! Every candidate `.frasm` statement synthesized by the protocol dissectors and shadow emitter is
//! verified by [`verify_with_oracle`]. The oracle constructs a minimal self-contained `.frasm`
//! program in memory, runs [`crate::parser::parse_program`] and [`crate::backend::compile_program`],
//! and compares the resulting Ethernet frame bytes against the normalized capture frame. Any
//! high-level statement whose compiled wire bytes match the capture frame is preserved (attaching
//! trailing `payload` or `hexpayload` bytes when needed), while candidates that fail to compile or
//! fail to reproduce the wire frame byte-for-byte step down cleanly to raw L4 (`tcp`/`udp`) or L2
//! (`vlan`/`qinq`/`mpls`) statements without emitting noisy diagnostic comments.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::collections::HashMap;

use logos::Logos;

use crate::ast::{Direction, MplsSpec, Protocol, TcpFlag};
use crate::lexer::Token;

use super::topology::{DiscoveredHost, ResolvedFrameEndpoints, derive_host_mac};
use super::{DissectedPacket, format_mac_lower, format_payload_modifier};

/// Maximum number of unique single-statement compilations retained in [`OracleCache`].
const MAX_ORACLE_CACHE_ENTRIES: usize = 4096;

/// Bounded per-capture cache of compiled oracle wire frames keyed by `(caller_decl, callee_decl, dir, stmt_body)`.
#[derive(Debug, Default)]
pub(crate) struct OracleCache {
    /// Cached compiled wire bytes (`None` if compilation failed for that key).
    compiled: HashMap<(String, String, u8, String), Option<Vec<u8>>>,
}

/// Result of verifying a candidate `.frasm` statement through the in-memory compiler oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedStatement {
    /// Final verified statement body (excluding the `<caller> ->|<- <callee> ` prefix).
    pub statement_body: String,
}

/// Compares synthesized wire bytes against `pkt.raw_eth_frame` using strict 100% raw-frame byte
/// equality on Ethernet captures (accounting for trailing 4-byte IEEE 802.3 FCS stripped during
/// normalization) and L2-MAC-independent byte equality (`bytes[12..]`) on L3-only linktypes.
fn frames_match(synth_bytes: &[u8], pkt: &DissectedPacket) -> bool {
    if pkt.is_l3_only {
        return synth_bytes.get(12..) == pkt.raw_eth_frame.get(12..);
    }
    if !pkt.is_l3_only && (pkt.l2.fcs || pkt.l2.bad_fcs) {
        if synth_bytes == pkt.raw_eth_frame {
            return true;
        }
        let body_len = pkt.raw_eth_frame.len();
        if synth_bytes.len() == body_len.saturating_add(4)
            && synth_bytes[..body_len] == pkt.raw_eth_frame[..]
        {
            let crc = crate::packet::ieee8023_crc32(&synth_bytes[..body_len]);
            let expected = if pkt.l2.bad_fcs {
                crc ^ 0xFFFF_FFFF
            } else {
                crc
            };
            return synth_bytes[body_len..] == expected.to_le_bytes();
        }
        return false;
    }
    synth_bytes == pkt.raw_eth_frame
}

/// Verifies a candidate `.frasm` statement against `pkt` with an isolated one-shot cache.
#[allow(dead_code)]
pub(crate) fn verify_with_oracle(
    pkt: &DissectedPacket,
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    ep: &ResolvedFrameEndpoints,
    candidate_stmt_body: &str,
) -> VerifiedStatement {
    let mut cache = OracleCache::default();
    verify_with_oracle_cached(pkt, caller, callee, ep, candidate_stmt_body, &mut cache)
}

/// Verifies a candidate `.frasm` statement against the original [`DissectedPacket`] using the
/// in-memory FrameAssembly parser and compiler in `O(1)` amortized work per frame (`O(N)` total).
pub(crate) fn verify_with_oracle_cached(
    pkt: &DissectedPacket,
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    ep: &ResolvedFrameEndpoints,
    candidate_stmt_body: &str,
    cache: &mut OracleCache,
) -> VerifiedStatement {
    let trimmed = candidate_stmt_body.trim();
    let callee_prefix = format!("{} ", callee.name);
    let best_candidate = trimmed
        .strip_prefix(&callee_prefix)
        .unwrap_or(trimmed)
        .trim()
        .to_string();

    let (oracle_caller, oracle_callee) = resolve_oracle_hosts(caller, callee, ep, pkt.is_l3_only);

    // 1. Hydrate elided L4 fields once and compile cleanly via the bounded oracle cache.
    let hydrated = hydrate_elided_l4_fields(&best_candidate, pkt);
    let mut candidate_compiled_opt: Option<bool> = None;

    if let Some(synth_bytes) =
        compile_cached(&oracle_caller, &oracle_callee, ep.dir, &hydrated, cache)
    {
        if hydrated == best_candidate {
            candidate_compiled_opt = Some(true);
            if frames_match(&synth_bytes, pkt) {
                return VerifiedStatement {
                    statement_body: best_candidate,
                };
            }
        } else if frames_match(&synth_bytes, pkt)
            && statement_parses(&oracle_caller, &oracle_callee, ep.dir, &best_candidate)
        {
            return VerifiedStatement {
                statement_body: best_candidate,
            };
        }

        // If residual_payload was empty and pkt.raw_eth_frame has extra trailing bytes,
        // try appending `payload "..."` / `hexpayload "..."` with a single hydrated compile.
        let synth_body_len = if !pkt.is_l3_only && (pkt.l2.fcs || pkt.l2.bad_fcs) {
            synth_bytes.len().saturating_sub(4)
        } else {
            synth_bytes.len()
        };
        if pkt.dissection.residual_payload.is_empty()
            && synth_body_len < pkt.raw_eth_frame.len()
            && !has_payload_token(&best_candidate)
        {
            let extra_bytes = &pkt.raw_eth_frame[synth_body_len..];
            let payload_mod = format_payload_modifier(extra_bytes);
            if !payload_mod.is_empty() {
                let with_payload = insert_before_wait(&best_candidate, &payload_mod);
                let hydrated_with_payload = hydrate_elided_l4_fields(&with_payload, pkt);
                if let Some(synth2) = compile_cached(
                    &oracle_caller,
                    &oracle_callee,
                    ep.dir,
                    &hydrated_with_payload,
                    cache,
                ) && frames_match(&synth2, pkt)
                    && (hydrated_with_payload == with_payload
                        || statement_parses(&oracle_caller, &oracle_callee, ep.dir, &with_payload))
                {
                    return VerifiedStatement {
                        statement_body: with_payload,
                    };
                }
            }
        }
    } else if hydrated != best_candidate {
        let direct_ok = if let Some(direct_bytes) =
            compile_cached(&oracle_caller, &oracle_callee, ep.dir, &best_candidate, cache)
        {
            candidate_compiled_opt = Some(true);
            frames_match(&direct_bytes, pkt)
        } else {
            candidate_compiled_opt = Some(false);
            false
        };
        if direct_ok {
            return VerifiedStatement {
                statement_body: best_candidate,
            };
        }
    } else {
        candidate_compiled_opt = Some(false);
    }

    // 2. Step down to raw L4 (`tcp` or `udp`) or raw L2 (`vlan`/`qinq`/`mpls`) statement.
    let wait_suffix = extract_wait_suffix(&best_candidate);
    if let Some(raw_stepdown) =
        build_stepdown_statement(pkt, caller, callee, ep, wait_suffix.as_deref())
    {
        let stepdown_body = hydrate_elided_l4_fields(&raw_stepdown, pkt);
        let is_unicast_l4 = pkt.has_ip_header
            && matches!(pkt.ip_proto, Some(6 | 17))
            && pkt.src_ip.is_some_and(super::topology::is_unicast_ip)
            && pkt.dst_ip.is_some_and(super::topology::is_unicast_ip);
        let stepdown_bytes_opt = compile_cached(
            &oracle_caller,
            &oracle_callee,
            ep.dir,
            &stepdown_body,
            cache,
        )
        .or_else(|| {
            (stepdown_body != raw_stepdown).then(|| {
                compile_cached(&oracle_caller, &oracle_callee, ep.dir, &raw_stepdown, cache)
            })?
        });
        if let Some(stepdown_bytes) = stepdown_bytes_opt {
            let matches = frames_match(&stepdown_bytes, pkt);
            let candidate_ok = *candidate_compiled_opt.get_or_insert_with(|| {
                compile_cached(&oracle_caller, &oracle_callee, ep.dir, &best_candidate, cache)
                    .is_some()
            });
            if matches || !candidate_ok || is_unicast_l4 {
                return VerifiedStatement {
                    statement_body: stepdown_body,
                };
            }
        }
    }

    let candidate_compiled = *candidate_compiled_opt.get_or_insert_with(|| {
        compile_cached(&oracle_caller, &oracle_callee, ep.dir, &best_candidate, cache).is_some()
    });
    if candidate_compiled {
        return VerifiedStatement {
            statement_body: best_candidate,
        };
    }

    // 3. Ultimate emergency fallback guaranteed to compile for any host pair.
    let emergency = build_emergency_fallback(pkt, caller, callee, wait_suffix.as_deref());
    VerifiedStatement {
        statement_body: emergency,
    }
}

/// Ensures isolated 2-host oracle runs preserve multi-host deterministic MAC synthesis (`host3+` -> `:03+`).
fn resolve_oracle_hosts(
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    ep: &ResolvedFrameEndpoints,
    is_l3_only: bool,
) -> (DiscoveredHost, DiscoveredHost) {
    let mut c = caller.clone();
    let mut s = callee.clone();
    if !is_l3_only {
        if c.mac.is_none() {
            c.mac = Some(derive_host_mac(None, None, c.ip, ep.caller_idx));
        }
        if s.mac.is_none() {
            s.mac = Some(derive_host_mac(None, None, s.ip, ep.callee_idx));
        }
    }
    (c, s)
}

/// Returns the canonical lowercase direction arrow (`"->"` or `"<-"`).
fn direction_arrow(dir: Direction) -> &'static str {
    match dir {
        Direction::LeftToRight => "->",
        Direction::RightToLeft => "<-",
    }
}

/// Formats a single `host <name> { ... }` declaration for the oracle test program.
fn format_host_decl(host: &DiscoveredHost) -> String {
    let mut fields = Vec::new();
    if let Some(ip) = host.ip {
        fields.push(format!("ip {ip}"));
    }
    if let Some(mac) = host.mac {
        fields.push(format!("mac {}", format_mac_lower(mac)));
    }
    if fields.is_empty() {
        fields.push(String::from("mac 00:00:00:00:00:01"));
    }
    format!("host {} {{ {} }}", host.name, fields.join(" "))
}

/// Parses a single isolated statement without wire synthesis to confirm syntactic validity.
fn statement_parses(
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    dir: Direction,
    stmt_body: &str,
) -> bool {
    let hosts = if caller.name == callee.name {
        format_host_decl(caller)
    } else {
        format!("{}\n{}", format_host_decl(caller), format_host_decl(callee))
    };
    let arrow = direction_arrow(dir);
    let src = format!(
        "{hosts}\ncompile {{\n    {} {arrow} {} {stmt_body}\n}}\n",
        caller.name, callee.name
    );
    crate::parser::parse_program(&src).is_ok()
}

/// Compiles a single statement using a bounded in-memory [`OracleCache`] to avoid redundant reparsing.
fn compile_cached(
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    dir: Direction,
    stmt_body: &str,
    cache: &mut OracleCache,
) -> Option<Vec<u8>> {
    let dir_tag = match dir {
        Direction::LeftToRight => 0u8,
        Direction::RightToLeft => 1u8,
    };
    let key = (
        format_host_decl(caller),
        format_host_decl(callee),
        dir_tag,
        stmt_body.to_string(),
    );
    if let Some(cached) = cache.compiled.get(&key) {
        return cached.clone();
    }
    let res = compile_single_statement(caller, callee, dir, stmt_body);
    if cache.compiled.len() < MAX_ORACLE_CACHE_ENTRIES {
        cache.compiled.insert(key, res.clone());
    }
    res
}

/// Parses and compiles a minimal 1-statement `.frasm` program in memory, returning the
/// synthesized Ethernet II frame bytes if successful.
pub(crate) fn compile_single_statement(
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    dir: Direction,
    stmt_body: &str,
) -> Option<Vec<u8>> {
    let hosts = if caller.name == callee.name {
        format_host_decl(caller)
    } else {
        format!("{}\n{}", format_host_decl(caller), format_host_decl(callee))
    };
    let arrow = direction_arrow(dir);
    let src = format!(
        "{hosts}\ncompile {{\n    {} {arrow} {} {stmt_body}\n}}\n",
        caller.name, callee.name
    );
    let program = crate::parser::parse_program(&src).ok()?;
    let frames = crate::backend::compile_program(&program).ok()?;
    frames.into_iter().next().map(|(data, _)| data)
}

/// Checks whether `stmt_body` already contains a `payload` or `hexpayload` token.
fn has_payload_token(stmt_body: &str) -> bool {
    Token::lexer(stmt_body)
        .flatten()
        .any(|tok| matches!(tok, Token::Payload | Token::HexPayload))
}

/// Extracts a trailing `wait <n><unit>` modifier from `stmt_body` if present.
fn extract_wait_suffix(stmt_body: &str) -> Option<String> {
    let mut lexer = Token::lexer(stmt_body);
    while let Some(Ok(tok)) = lexer.next() {
        if matches!(tok, Token::Wait) {
            let start = lexer.span().start;
            return Some(stmt_body[start..].trim().to_string());
        }
    }
    None
}

/// Inserts `modifier` immediately before any trailing `wait <n><unit>` clause in `stmt_body`.
pub(crate) fn insert_before_wait(stmt_body: &str, modifier: &str) -> String {
    if modifier.is_empty() {
        return stmt_body.to_string();
    }
    let mut lexer = Token::lexer(stmt_body);
    while let Some(Ok(tok)) = lexer.next() {
        if matches!(tok, Token::Wait) {
            let start = lexer.span().start;
            let prefix = stmt_body[..start].trim_end();
            let suffix = stmt_body[start..].trim_start();
            return format!("{prefix} {modifier} {suffix}");
        }
    }
    format!("{} {modifier}", stmt_body.trim_end())
}

/// Injects elided `srcport`, `dstport`, `seq`, and `acknum` fields from `pkt` into a copy of
/// `stmt_body` so a 1-packet oracle run reproduces the exact multi-packet shadow state.
fn hydrate_elided_l4_fields(stmt_body: &str, pkt: &DissectedPacket) -> String {
    let mut has_srcport = false;
    let mut has_dstport = false;
    let mut has_seq = false;
    let mut has_acknum = false;
    let mut seen_netflow_ipfix = false;
    let mut seen_tacacs = false;

    for tok in Token::lexer(stmt_body).flatten() {
        match tok {
            Token::Netflow | Token::Ipfix => seen_netflow_ipfix = true,
            Token::Tacacs => seen_tacacs = true,
            Token::SrcPort if !seen_netflow_ipfix => has_srcport = true,
            Token::DstPort if !seen_netflow_ipfix => has_dstport = true,
            Token::Seq if !seen_tacacs => has_seq = true,
            Token::AckNum => has_acknum = true,
            _ => {}
        }
    }

    let mut prefix = Vec::new();
    let mut extra = Vec::new();
    if !has_srcport && let Some(sp) = pkt.l4.src_port {
        if seen_netflow_ipfix {
            prefix.push(format!("srcport {sp}"));
        } else {
            extra.push(format!("srcport {sp}"));
        }
    }
    if !has_dstport && let Some(dp) = pkt.l4.dst_port {
        if seen_netflow_ipfix {
            prefix.push(format!("dstport {dp}"));
        } else {
            extra.push(format!("dstport {dp}"));
        }
    }
    if !has_seq && let Some(seq) = pkt.seq {
        if seen_tacacs {
            prefix.push(format!("seq {seq}"));
        } else {
            extra.push(format!("seq {seq}"));
        }
    }
    if !has_acknum && let Some(ack) = pkt.ack_num {
        let should_ack = pkt.l4.tcp_flags.contains(&TcpFlag::Ack)
            || (pkt.dissection.protocol != Protocol::Tcp && pkt.l4.tcp_flags.is_empty());
        if ack != 0 || should_ack {
            extra.push(format!("acknum {ack}"));
        }
    }

    let with_prefix = if prefix.is_empty() {
        stmt_body.to_string()
    } else {
        format!("{} {}", prefix.join(" "), stmt_body.trim_start())
    };
    if extra.is_empty() {
        with_prefix
    } else {
        insert_before_wait(&with_prefix, &extra.join(" "))
    }
}

/// Appends single- or multi-label MPLS shim modifiers onto `parts`, eliding default `bos` flags.
fn append_mpls_stack(parts: &mut Vec<String>, mpls_entries: &[MplsSpec]) {
    let total = mpls_entries.len();
    for (idx, m) in mpls_entries.iter().enumerate() {
        parts.push(format!("mpls {}", m.label));
        if let Some(exp) = m.exp
            && exp != 0
        {
            parts.push(format!("exp {exp}"));
        }
        let default_bos = u8::from(idx + 1 == total);
        if let Some(bos) = m.bos
            && bos != default_bos
        {
            parts.push(format!("bos {bos}"));
        }
        if let Some(ttl) = m.ttl
            && ttl != 64
        {
            parts.push(format!("mplsttl {ttl}"));
        }
    }
}

/// Builds a raw L4 (`tcp`/`udp`) or raw L2 (`vlan`/`qinq`/`mpls`) step-down statement from `pkt`.
fn build_stepdown_statement(
    pkt: &DissectedPacket,
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    ep: &ResolvedFrameEndpoints,
    wait_suffix: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::new();
    let (src_host, dst_host, src_idx, dst_idx) = match ep.dir {
        Direction::LeftToRight => (caller, callee, ep.caller_idx, ep.callee_idx),
        Direction::RightToLeft => (callee, caller, ep.callee_idx, ep.caller_idx),
    };
    let synth_src = derive_host_mac(src_host.mac, None, src_host.ip, src_idx);
    let synth_dst = derive_host_mac(dst_host.mac, None, dst_host.ip, dst_idx);
    let emit_src_mac = (!pkt.is_l3_only && pkt.src_mac != synth_src).then_some(pkt.src_mac);
    let emit_dst_mac = (!pkt.is_l3_only && pkt.dst_mac != synth_dst).then_some(pkt.dst_mac);

    if pkt.has_ip_header && matches!(pkt.ip_proto, Some(6 | 17)) {
        let is_tcp = pkt.ip_proto == Some(6);
        parts.push(String::from(if is_tcp { "tcp" } else { "udp" }));

        if is_tcp {
            for flag in &pkt.l4.tcp_flags {
                let f_str = match flag {
                    TcpFlag::Syn => "syn",
                    TcpFlag::Ack => "ack",
                    TcpFlag::Fin => "fin",
                    TcpFlag::Rst => "rst",
                    TcpFlag::Psh => "psh",
                    TcpFlag::Urg => "urg",
                    TcpFlag::Ece => "ece",
                    TcpFlag::Cwr => "cwr",
                };
                parts.push(String::from(f_str));
            }
            if let Some(seq) = pkt.seq {
                parts.push(format!("seq {seq}"));
            }
            if let Some(ack) = pkt.ack_num
                && (ack != 0 || pkt.l4.tcp_flags.contains(&TcpFlag::Ack))
            {
                parts.push(format!("acknum {ack}"));
            }
            if let Some(win) = pkt.win
                && win != 64240
            {
                parts.push(format!("win {win}"));
            }
            if let Some(urg) = pkt.l4.urgent
                && urg != 0
            {
                parts.push(format!("urgent {urg}"));
            }
            if let Some(opts) = &pkt.l4.tcp_options {
                if let Some(mss) = opts.mss {
                    parts.push(format!("mss {mss}"));
                }
                if let Some(ws) = opts.wscale {
                    parts.push(format!("wscale {ws}"));
                }
                if opts.sack_perm {
                    parts.push(String::from("sackperm"));
                }
                if let Some(tsv) = opts.tsval {
                    parts.push(format!("tsval {tsv}"));
                }
                if let Some(tse) = opts.tsecr
                    && (tse != 0 || opts.tsval.is_none())
                {
                    parts.push(format!("tsecr {tse}"));
                }
            }
        }

        if let Some(sp) = pkt.l4.src_port {
            parts.push(format!("srcport {sp}"));
        }
        if let Some(dp) = pkt.l4.dst_port {
            parts.push(format!("dstport {dp}"));
        }

        append_l2_l3_modifiers(&mut parts, pkt, emit_src_mac, emit_dst_mac, true);

        let pmod = format_payload_modifier(&pkt.l4_payload);
        if !pmod.is_empty() {
            parts.push(pmod);
        }
    } else if !pkt.has_ip_header {
        let mpls_entries: &[MplsSpec] = if !pkt.l2.mpls_stack.is_empty() {
            &pkt.l2.mpls_stack
        } else {
            pkt.l2.mpls.as_slice()
        };
        if let Some(q) = &pkt.l2.qinq {
            parts.push(format!("qinq {}", q.outer_vid));
            if let Some(iv) = q.inner_vid
                && iv != 1
            {
                parts.push(format!("innervlan {iv}"));
            }
            if let Some(pcp) = q.pcp
                && pcp != 0
            {
                parts.push(format!("pcp {pcp}"));
            }
            if let Some(dei) = q.dei
                && dei != 0
            {
                parts.push(format!("dei {dei}"));
            }
            if !mpls_entries.is_empty() {
                append_mpls_stack(&mut parts, mpls_entries);
            }
        } else if !mpls_entries.is_empty() {
            append_mpls_stack(&mut parts, mpls_entries);
            if let Some(v) = &pkt.l2.vlan {
                parts.push(format!("vlan {}", v.vid));
                if let Some(pcp) = v.pcp
                    && pcp != 0
                {
                    parts.push(format!("pcp {pcp}"));
                }
                if let Some(dei) = v.dei
                    && dei != 0
                {
                    parts.push(format!("dei {dei}"));
                }
            }
        } else {
            let vid = pkt.l2.vlan.as_ref().map_or(1, |v| v.vid);
            parts.push(format!("vlan {vid}"));
            if let Some(v) = &pkt.l2.vlan {
                if let Some(pcp) = v.pcp
                    && pcp != 0
                {
                    parts.push(format!("pcp {pcp}"));
                }
                if let Some(dei) = v.dei
                    && dei != 0
                {
                    parts.push(format!("dei {dei}"));
                }
            }
        }
        if pkt.inner_ethertype != 0x88B5
            && !(!mpls_entries.is_empty() && matches!(pkt.inner_ethertype, 0x8847 | 0x8848))
        {
            parts.push(format!("ethertype 0x{:04x}", pkt.inner_ethertype));
        }
        if let Some(sm) = emit_src_mac {
            parts.push(format!("srcmac {}", format_mac_lower(sm)));
        }
        if let Some(dm) = emit_dst_mac {
            parts.push(format!("dstmac {}", format_mac_lower(dm)));
        }
        if pkt.l2.fcs {
            parts.push(String::from("fcs"));
        }
        if pkt.l2.bad_fcs {
            parts.push(String::from("badfcs"));
        }
        let pmod = format_payload_modifier(&pkt.l2_payload);
        if !pmod.is_empty() {
            parts.push(pmod);
        }
    } else {
        return None;
    }

    if let Some(w) = wait_suffix {
        parts.push(w.to_string());
    }

    Some(parts.join(" "))
}

/// Appends L2 and L3 modifiers from `pkt` and explicit MAC overrides onto `parts`.
fn append_l2_l3_modifiers(
    parts: &mut Vec<String>,
    pkt: &DissectedPacket,
    emit_src_mac: Option<[u8; 6]>,
    emit_dst_mac: Option<[u8; 6]>,
    include_l2_tags: bool,
) {
    if let Some(sm) = emit_src_mac {
        parts.push(format!("srcmac {}", format_mac_lower(sm)));
    }
    if let Some(dm) = emit_dst_mac {
        parts.push(format!("dstmac {}", format_mac_lower(dm)));
    }
    if include_l2_tags {
        if let Some(v) = &pkt.l2.vlan {
            parts.push(format!("vlan {}", v.vid));
            if let Some(pcp) = v.pcp
                && pcp != 0
            {
                parts.push(format!("pcp {pcp}"));
            }
            if let Some(dei) = v.dei
                && dei != 0
            {
                parts.push(format!("dei {dei}"));
            }
        }
        if let Some(q) = &pkt.l2.qinq {
            parts.push(format!("qinq {}", q.outer_vid));
            if let Some(iv) = q.inner_vid
                && iv != 1
            {
                parts.push(format!("innervlan {iv}"));
            }
            if let Some(pcp) = q.pcp
                && pcp != 0
            {
                parts.push(format!("pcp {pcp}"));
            }
            if let Some(dei) = q.dei
                && dei != 0
            {
                parts.push(format!("dei {dei}"));
            }
        }
        let mpls_entries: &[MplsSpec] = if !pkt.l2.mpls_stack.is_empty() {
            &pkt.l2.mpls_stack
        } else {
            pkt.l2.mpls.as_slice()
        };
        if !mpls_entries.is_empty() {
            append_mpls_stack(parts, mpls_entries);
        }
    }
    if pkt.l2.fcs {
        parts.push(String::from("fcs"));
    }
    if pkt.l2.bad_fcs {
        parts.push(String::from("badfcs"));
    }

    if pkt.has_ip_header {
        let is_ipv6 = matches!(pkt.src_ip, Some(core::net::IpAddr::V6(_)));
        if let Some(ttl) = pkt.l3.ttl
            && ttl != 64
        {
            parts.push(format!("ttl {ttl}"));
        }
        if let Some(dscp) = pkt.l3.dscp
            && dscp != 0
        {
            parts.push(format!("dscp {dscp}"));
        }
        if let Some(ecn) = pkt.l3.ecn
            && ecn != 0
        {
            parts.push(format!("ecn {ecn}"));
        }
        if is_ipv6
            && let Some(fl) = pkt.l3.flowlabel
            && fl != 0
        {
            parts.push(format!("flowlabel 0x{fl:x}"));
        }
        if let Some(ipid) = pkt.l3.ipid
            && (is_ipv6 || ipid != 0)
        {
            parts.push(format!("ipid 0x{ipid:04x}"));
        }
        if !is_ipv6 && pkt.l3.df {
            parts.push(String::from("df"));
        }
        if pkt.l3.mf {
            parts.push(String::from("mf"));
        }
        if let Some(fo) = pkt.l3.frag_offset
            && fo != 0
        {
            parts.push(format!("fragoffset {fo}"));
        }
        if pkt.l3.router_alert {
            parts.push(String::from("routeralert"));
        }
    }
}

/// Builds a minimal guaranteed-compilable fallback statement for `caller` and `callee`.
fn build_emergency_fallback(
    pkt: &DissectedPacket,
    caller: &DiscoveredHost,
    callee: &DiscoveredHost,
    wait_suffix: Option<&str>,
) -> String {
    let base = if caller.ip.is_some() && callee.ip.is_some() {
        let pmod = format_payload_modifier(&pkt.l4_payload);
        if pmod.is_empty() {
            String::from("udp")
        } else {
            format!("udp {pmod}")
        }
    } else {
        let pmod = format_payload_modifier(&pkt.l2_payload);
        if pmod.is_empty() {
            String::from("vlan 1")
        } else {
            format!("vlan 1 {pmod}")
        }
    };
    if let Some(w) = wait_suffix {
        format!("{base} {w}")
    } else {
        base
    }
}
