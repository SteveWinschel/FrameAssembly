//! Simple Network Management Protocol v2c (`SNMP2`, RFC 3416) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe ASN.1 Basic Encoding Rules (BER) reverse dissector for
//! RFC 3416 and RFC 1901 community-based `SNMP2` (SNMPv2c) messages carried over UDP ports `161`,
//! `162`, `10161`, and `10162`. It decodes `SNMPv2-Trap`, `InformRequest`, `GetRequest`,
//! `GetNextRequest`, `GetBulkRequest` (`nonrepeaters`, `maxrepetitions`), `Response`, and
//! `SetRequest` PDUs along with SMIv2 (RFC 2578) `VarBind` values (`counter64`, `counter32`,
//! `gauge32`, `timeticks`, `int`, `string`, `oidval`, `ipval`, `null`) and exports shared SMIv2
//! PDU formatting routines consumed by [`super::snmp3`].

use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, ipv4_at, push_if};

use super::snmp1::{format_octet_vb_body, format_oid, int_val};
use super::{ok_dissect, push_str_if};

/// Dissects an RFC 3416 `SNMP2` (SNMPv2c) ASN.1 BER payload.
pub(crate) fn dissect_snmp2(payload: &[u8]) -> Option<ProtocolDissection> {
    use rasn_snmp::v2::Pdus as PdusV2;
    use rasn_snmp::v2c::Message;

    let (msg, rem): (Message<PdusV2>, &[u8]) = rasn::ber::decode_with_remainder(payload).ok()?;
    if int_val::<u32>(&msg.version) != Some(1) {
        return None;
    }

    let community = core::str::from_utf8(msg.community.as_ref()).ok()?;
    let mut tokens = format!("snmp2 {}", v2_pdu_keyword(&msg.data)?);
    push_str_if(&mut tokens, "community", community, "public");
    append_v2_pdu_body_tokens(&mut tokens, &msg.data)?;
    ok_dissect(Protocol::Snmp2, tokens, rem.to_vec())
}

/// Maps an SNMPv2/v3 `Pdus` variant to its lowercase `.fasm` PDU keyword.
pub(crate) fn v2_pdu_keyword(pdus: &rasn_snmp::v2::Pdus) -> Option<&'static str> {
    use rasn_snmp::v2::Pdus;
    match pdus {
        Pdus::Trap(_) => Some("trap"),
        Pdus::InformRequest(_) => Some("inform"),
        Pdus::GetRequest(_) => Some("get"),
        Pdus::GetNextRequest(_) => Some("getnext"),
        Pdus::GetBulkRequest(_) => Some("getbulk"),
        Pdus::Response(_) => Some("response"),
        Pdus::SetRequest(_) => Some("set"),
        Pdus::Report(_) => None,
    }
}

/// Appends SNMPv2/v3 PDU parameters (`reqid`, `nonrepeaters`, `maxrepetitions`, `sysuptime`, `oid`, `varbind`).
pub(crate) fn append_v2_pdu_body_tokens(
    tokens: &mut String,
    pdus: &rasn_snmp::v2::Pdus,
) -> Option<()> {
    use rasn_snmp::v2::Pdus;

    match pdus {
        Pdus::Trap(t) => append_v2_notification_vbs(tokens, &t.0),
        Pdus::InformRequest(inf) => append_v2_notification_vbs(tokens, &inf.0),
        Pdus::GetRequest(g) => {
            push_if(tokens, "reqid", g.0.request_id as u32, 1);
            append_v2_vb_list(tokens, &g.0.variable_bindings)
        }
        Pdus::GetNextRequest(gn) => {
            push_if(tokens, "reqid", gn.0.request_id as u32, 1);
            append_v2_vb_list(tokens, &gn.0.variable_bindings)
        }
        Pdus::Response(r) => {
            push_if(tokens, "reqid", r.0.request_id as u32, 1);
            append_v2_vb_list(tokens, &r.0.variable_bindings)
        }
        Pdus::SetRequest(s) => {
            push_if(tokens, "reqid", s.0.request_id as u32, 1);
            append_v2_vb_list(tokens, &s.0.variable_bindings)
        }
        Pdus::GetBulkRequest(gb) => {
            let bulk = &gb.0;
            push_if(tokens, "reqid", bulk.request_id as u32, 1);
            push_if(tokens, "nonrepeaters", bulk.non_repeaters, 0);
            push_if(tokens, "maxrepetitions", bulk.max_repetitions, 10);
            append_v2_vb_list(tokens, &bulk.variable_bindings)
        }
        Pdus::Report(_) => None,
    }
}

/// Strips prepended RFC 3416 `sysUpTime.0` and `snmpTrapOID.0` bindings into `sysuptime` and `oid` modifiers.
fn append_v2_notification_vbs(tokens: &mut String, pdu: &rasn_snmp::v2::Pdu) -> Option<()> {
    use rasn_smi::v2::{ApplicationSyntax as App, ObjectSyntax as Obj, SimpleSyntax as Sim};
    use rasn_snmp::v2::VarBindValue::Value;

    push_if(tokens, "reqid", pdu.request_id as u32, 1);
    let vbs = &pdu.variable_bindings;
    let mut start_idx = 0;

    if vbs.len() >= 2
        && format_oid(&vbs[0].name) == "1.3.6.1.2.1.1.3.0"
        && format_oid(&vbs[1].name) == "1.3.6.1.6.3.1.1.4.1.0"
        && let (Value(Obj::ApplicationWide(App::Ticks(t))), Value(Obj::Simple(Sim::ObjectId(oid)))) =
            (&vbs[0].value, &vbs[1].value)
    {
        push_if(
            tokens,
            "oid",
            format_oid(oid).as_str(),
            "1.3.6.1.6.3.1.1.5.3",
        );
        push_if(tokens, "sysuptime", t.0, 0);
        start_idx = 2;
    }

    for vb in &vbs[start_idx..] {
        let _ = write!(tokens, " {}", format_v2_varbind(vb)?);
    }
    Some(())
}

/// Appends `oid <oid>` for a single `Unspecified` VarBind or `varbind ...` entries otherwise.
fn append_v2_vb_list(tokens: &mut String, vbs: &[rasn_snmp::v2::VarBind]) -> Option<()> {
    if vbs.len() == 1 && matches!(vbs[0].value, rasn_snmp::v2::VarBindValue::Unspecified) {
        let _ = write!(tokens, " oid {}", format_oid(&vbs[0].name));
    } else {
        for vb in vbs {
            let _ = write!(tokens, " {}", format_v2_varbind(vb)?);
        }
    }
    Some(())
}

/// Formats a single SMIv2 `VarBind` into canonical `.fasm` `varbind <oid> <type> [val]` syntax.
fn format_v2_varbind(vb: &rasn_snmp::v2::VarBind) -> Option<String> {
    use rasn_smi::v2::{ApplicationSyntax as App, ObjectSyntax as Obj, SimpleSyntax as Sim};
    use rasn_snmp::v2::VarBindValue::{Unspecified, Value};

    let body = match &vb.value {
        Unspecified => String::from("null"),
        Value(Obj::Simple(Sim::Integer(n))) => format!("int {}", int_val::<i32>(n)?),
        Value(Obj::Simple(Sim::ObjectId(o))) => format!("oidval {}", format_oid(o)),
        Value(Obj::Simple(Sim::String(s))) => format_octet_vb_body(s.as_ref())?,
        Value(Obj::ApplicationWide(App::Ticks(t))) => format!("timeticks {}", t.0),
        Value(Obj::ApplicationWide(App::Counter(c))) => format!("counter32 {}", c.0),
        Value(Obj::ApplicationWide(App::Unsigned(g))) => format!("gauge32 {}", g.0),
        Value(Obj::ApplicationWide(App::BigCounter(c))) => format!("counter64 {}", c.0),
        Value(Obj::ApplicationWide(App::Address(ip))) => {
            let b = ip.0.as_ref();
            (b.len() == 4).then(|| format!("ipval {}", ipv4_at(b, 0)))?
        }
        _ => return None,
    };
    Some(format!("varbind {} {body}", format_oid(&vb.name)))
}
