//! Simple Network Management Protocol v1 (`SNMP1`, RFC 1157) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe ASN.1 Basic Encoding Rules (BER) reverse dissector for
//! RFC 1157 `SNMP1` messages carried over UDP ports `161`, `162`, `10161`, and `10162`. It decodes
//! `Trap-PDU` (`enterprise`, `agentip`, `gentrap`, `spectrap`, `sysuptime`), `GetRequest-PDU`,
//! `GetNextRequest-PDU`, `GetResponse-PDU`, and `SetRequest-PDU` structures along with all SMIv1
//! (RFC 1155) `VarBind` value types (`int`, `string`, `oidval`, `ipval`, `counter32`, `gauge32`,
//! `timeticks`, `null`) and provides shared ASN.1 formatting helpers for `SNMP2` and `SNMP3`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::Ipv4Addr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, ipv4_at, ipv6_at, push_if};

use super::{is_printable_ascii_str, ok_dissect, push_str_if, quote_raw_str};

/// Converts a `rasn::types::Integer` into a primitive numeric type `T`.
pub(crate) fn int_val<T: core::str::FromStr>(val: &rasn::types::Integer) -> Option<T> {
    val.to_string().parse().ok()
}

/// Formats an ASN.1 `ObjectIdentifier` as a canonical dot-separated numeric string.
pub(crate) fn format_oid(oid: &rasn::types::ObjectIdentifier) -> String {
    oid.iter()
        .map(|arc| arc.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Formats an ASN.1 `OCTET STRING` VarBind value body as `string "..."` or IPv6 `ipval <v6>`.
pub(crate) fn format_octet_vb_body(bytes: &[u8]) -> Option<String> {
    if let Some(s) = is_printable_ascii_str(bytes) {
        Some(format!("string \"{}\"", quote_raw_str(s)))
    } else if bytes.len() == 16 {
        Some(format!("ipval {}", ipv6_at(bytes, 0)))
    } else {
        None
    }
}

/// Dissects an RFC 1157 `SNMP1` ASN.1 BER payload.
pub(crate) fn dissect_snmp1(payload: &[u8], is_ipv6: bool) -> Option<ProtocolDissection> {
    use rasn_smi::v1::NetworkAddress::Internet;
    use rasn_snmp::v1::{Message, Pdus};

    let (msg, rem): (Message<Pdus>, &[u8]) = rasn::ber::decode_with_remainder(payload).ok()?;
    if int_val::<u32>(&msg.version) != Some(0) {
        return None;
    }

    let community = core::str::from_utf8(msg.community.as_ref()).ok()?;
    let mut tokens = String::from("snmp1");

    match &msg.data {
        Pdus::Trap(trap) => {
            tokens.push_str(" trap");
            push_str_if(&mut tokens, "community", community, "public");

            let ent = format_oid(&trap.enterprise);
            let gen_trap = int_val::<u32>(&trap.generic_trap).unwrap_or(6);
            let spec_trap = int_val::<u32>(&trap.specific_trap).unwrap_or(1);
            push_if(&mut tokens, "enterprise", ent.as_str(), "1.3.6.1.4.1");

            let Internet(ip_addr) = &trap.agent_addr;
            let octets = ip_addr.0.as_ref();
            if octets.len() == 4 {
                let agent_v4 = ipv4_at(octets, 0);
                if !is_ipv6 || agent_v4 != Ipv4Addr::UNSPECIFIED {
                    let _ = write!(tokens, " agentip {agent_v4}");
                }
            }

            let auto_gen = ent
                .strip_prefix("1.3.6.1.6.3.1.1.5.")
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|&n| (1..=6).contains(&n))
                .map_or(6, |n| n - 1);
            push_if(&mut tokens, "gentrap", gen_trap, auto_gen);
            push_if(
                &mut tokens,
                "spectrap",
                spec_trap,
                u32::from(!(0..=5).contains(&gen_trap)),
            );
            push_if(&mut tokens, "sysuptime", trap.time_stamp.0, 0);
            for vb in &trap.variable_bindings {
                let _ = write!(tokens, " {}", format_v1_varbind(vb)?);
            }
        }
        Pdus::GetRequest(g) => append_v1_pdu_fields(&mut tokens, " get", community, &g.0)?,
        Pdus::GetNextRequest(gn) => {
            append_v1_pdu_fields(&mut tokens, " getnext", community, &gn.0)?
        }
        Pdus::GetResponse(r) => append_v1_pdu_fields(&mut tokens, " response", community, &r.0)?,
        Pdus::SetRequest(s) => append_v1_pdu_fields(&mut tokens, " set", community, &s.0)?,
    }

    ok_dissect(Protocol::Snmp1, tokens, rem.to_vec())
}

/// Appends SNMPv1 non-trap PDU fields (`community`, `reqid`, `oid` / `varbind`) to `tokens`.
fn append_v1_pdu_fields(
    tokens: &mut String,
    pdu_kw: &str,
    community: &str,
    pdu: &rasn_snmp::v1::Pdu,
) -> Option<()> {
    use rasn_smi::v1::{ObjectSyntax::Simple, SimpleSyntax::Empty};

    tokens.push_str(pdu_kw);
    push_str_if(tokens, "community", community, "public");
    push_if(tokens, "reqid", int_val::<u32>(&pdu.request_id)?, 1);
    let vbs = &pdu.variable_bindings;
    if vbs.len() == 1 && matches!(vbs[0].value, Simple(Empty)) {
        let _ = write!(tokens, " oid {}", format_oid(&vbs[0].name));
    } else {
        for vb in vbs {
            let _ = write!(tokens, " {}", format_v1_varbind(vb)?);
        }
    }
    Some(())
}

/// Formats a single SMIv1 `VarBind` into canonical `.fasm` `varbind <oid> <type> [val]` syntax.
fn format_v1_varbind(vb: &rasn_snmp::v1::VarBind) -> Option<String> {
    use rasn_smi::v1::{
        ApplicationSyntax as App, NetworkAddress::Internet, ObjectSyntax as Obj,
        SimpleSyntax as Sim,
    };

    let body = match &vb.value {
        Obj::Simple(Sim::Empty) => String::from("null"),
        Obj::Simple(Sim::Number(n)) => format!("int {}", int_val::<i32>(n)?),
        Obj::Simple(Sim::Object(o)) => format!("oidval {}", format_oid(o)),
        Obj::Simple(Sim::String(s)) => format_octet_vb_body(s.as_ref())?,
        Obj::ApplicationWide(App::Ticks(t)) => format!("timeticks {}", t.0),
        Obj::ApplicationWide(App::Counter(c)) => format!("counter32 {}", c.0),
        Obj::ApplicationWide(App::Gauge(g)) => format!("gauge32 {}", g.0),
        Obj::ApplicationWide(App::Address(Internet(ip))) => {
            let b = ip.0.as_ref();
            (b.len() == 4).then(|| format!("ipval {}", ipv4_at(b, 0)))?
        }
        Obj::ApplicationWide(App::Arbitrary(_)) => return None,
    };
    Some(format!("varbind {} {body}", format_oid(&vb.name)))
}
