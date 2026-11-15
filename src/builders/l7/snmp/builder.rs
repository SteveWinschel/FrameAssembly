//! SNMPv1, SNMPv2c, and SNMPv3 ASN.1 BER wire payload builder implementation.
//!
//! This module implements [`build_snmp1_payload`], [`build_snmp2_payload`], and
//! [`build_snmp3_payload`] using `rasn`, `rasn_smi`, and `rasn_snmp` ASN.1 BER encoders over UDP
//! ports 161 (queries) and 162 (traps/informs). It translates FrameAssembly
//! [`Snmp1Spec`], [`Snmp2Spec`],
//! and [`Snmp3Spec`] AST specifications into deterministic wire
//! bytes, supporting all 7 SNMP PDU types (`Trap`, `GetRequest`, `GetNextRequest`, `Response`,
//! `SetRequest`, `InformRequest`, `GetBulkRequest`) and all 9 SMIv1/SMIv2 VarBind value types
//! (`nullval`, `string`, `int`, `timeticks`, `ipval`, `oidval`, `counter32`, `gauge32`, `counter64`).

use super::crypto::*;
use crate::ast::*;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1::{IpAddress, NetworkAddress, TimeTicks};
use rasn_smi::v2::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
use rasn_snmp::v2::{BulkPdu, Pdu, Pdus as PdusV2, VarBind, VarBindValue};

/// Builds an SNMPv1 payload from a [`FrameStatement`].
///
/// Implements RFC 1157 PDU construction for `Trap`, `Get`, `GetNext`, `Response`, and `Set` PDUs,
/// mapping generic trap OIDs (`1.3.6.1.6.3.1.1.5.1` through `.6`) to `generic_trap` `0..=5`,
/// falling back IPv6 `agent-addr` to `0.0.0.0` per RFC 3584 §3.2 unless overridden by `agentip`,
/// and rejecting SNMPv2-only PDUs (`getbulk` and `inform`).
pub fn build_snmp1_payload(stmt: &FrameStatement, src_ip: IpAddr) -> Result<Vec<u8>, String> {
    use rasn_snmp::v1::{Message, Pdus, Trap};

    let spec = match &stmt.protocol_spec {
        Some(ProtocolSpec::Snmp1(s)) => Some(s),
        _ => None,
    };
    let eff_pdu_type = stmt
        .pdu_type
        .as_ref()
        .or_else(|| spec.and_then(|s| s.pdu_type.as_ref()));

    if let Some(pdu_type) = eff_pdu_type
        && matches!(
            pdu_type,
            SnmpPduType::GetBulk | SnmpPduType::Inform | SnmpPduType::Report
        )
    {
        return Err("SNMPv1 does not support GETBULK, INFORM, or REPORT".to_string());
    }

    let community_str = stmt
        .community
        .or_else(|| spec.and_then(|s| s.community))
        .unwrap_or("public");
    let community = OctetString::from(community_str.as_bytes().to_vec());

    let pdu_type = eff_pdu_type.unwrap_or(&SnmpPduType::Trap);

    let vbs_slice: &[VarBindAst] = if !stmt.varbinds.is_empty() {
        &stmt.varbinds
    } else if let Some(s) = spec
        && !s.varbinds.is_empty()
    {
        &s.varbinds
    } else {
        &[]
    };

    let v1_varbinds = if !vbs_slice.is_empty() {
        convert_v1_varbinds(vbs_slice)?
    } else if let Some(oid_str) = stmt.oid {
        vec![rasn_snmp::v1::VarBind {
            name: parse_oid(oid_str)?,
            value: rasn_smi::v1::ObjectSyntax::Simple(rasn_smi::v1::SimpleSyntax::Empty),
        }]
    } else {
        vec![]
    };

    let pdu_data = match pdu_type {
        SnmpPduType::Trap => {
            let eff_agent_ip = stmt.agent_ip.or_else(|| spec.and_then(|s| s.agent_ip));
            let agent_ip = if let Some(IpAddr::V4(addr)) = eff_agent_ip {
                addr.octets()
            } else {
                match src_ip {
                    IpAddr::V4(addr) => addr.octets(),
                    IpAddr::V6(_) => [0, 0, 0, 0],
                }
            };

            let eff_enterprise = stmt.enterprise.or_else(|| spec.and_then(|s| s.enterprise));
            let eff_gen_trap = stmt.gen_trap.or_else(|| spec.and_then(|s| s.gen_trap));
            let eff_spec_trap = stmt.spec_trap.or_else(|| spec.and_then(|s| s.spec_trap));
            let eff_sys_up_time = stmt
                .sys_up_time
                .or_else(|| spec.and_then(|s| s.sys_up_time));

            // Fall back enterprise to stmt.oid if enterprise is not explicitly provided.
            let enterprise_str = eff_enterprise.or(stmt.oid).unwrap_or("1.3.6.1.4.1");
            let trap_oid = parse_oid(enterprise_str)?;

            // Automatically map standard RFC 1157 generic trap OIDs (1.3.6.1.6.3.1.1.5.1 through .6)
            // to generic_trap 0..=5 with specific_trap = 0 when GENTRAP is not explicitly set.
            let (generic_trap, specific_trap) = match eff_gen_trap {
                Some(g) if (0..=5).contains(&g) => (g, eff_spec_trap.unwrap_or(0)),
                Some(g) => (g, eff_spec_trap.unwrap_or(1)),
                None => {
                    let oid_to_check = stmt.oid.or(eff_enterprise);
                    match oid_to_check.map(|s| s.trim_start_matches('.')) {
                        Some("1.3.6.1.6.3.1.1.5.1") => (0, eff_spec_trap.unwrap_or(0)), // coldStart
                        Some("1.3.6.1.6.3.1.1.5.2") => (1, eff_spec_trap.unwrap_or(0)), // warmStart
                        Some("1.3.6.1.6.3.1.1.5.3") => (2, eff_spec_trap.unwrap_or(0)), // linkDown
                        Some("1.3.6.1.6.3.1.1.5.4") => (3, eff_spec_trap.unwrap_or(0)), // linkUp
                        Some("1.3.6.1.6.3.1.1.5.5") => (4, eff_spec_trap.unwrap_or(0)), // authenticationFailure
                        Some("1.3.6.1.6.3.1.1.5.6") => (5, eff_spec_trap.unwrap_or(0)), // egpNeighborLoss
                        _ => (6, eff_spec_trap.unwrap_or(1)), // enterpriseSpecific
                    }
                }
            };

            let trap = Trap {
                enterprise: trap_oid,
                agent_addr: NetworkAddress::Internet(IpAddress(agent_ip.into())),
                generic_trap: Integer::from(generic_trap),
                specific_trap: Integer::from(specific_trap),
                time_stamp: TimeTicks(eff_sys_up_time.unwrap_or(0)),
                variable_bindings: v1_varbinds,
            };
            Pdus::Trap(trap)
        }
        SnmpPduType::Get => {
            let pdu = rasn_snmp::v1::Pdu {
                request_id: Integer::from(stmt.req_id.unwrap_or(1)),
                error_status: Integer::from(0),
                error_index: Integer::from(0),
                variable_bindings: v1_varbinds,
            };
            Pdus::GetRequest(rasn_snmp::v1::GetRequest(pdu))
        }
        SnmpPduType::GetNext => {
            let pdu = rasn_snmp::v1::Pdu {
                request_id: Integer::from(stmt.req_id.unwrap_or(1)),
                error_status: Integer::from(0),
                error_index: Integer::from(0),
                variable_bindings: v1_varbinds,
            };
            Pdus::GetNextRequest(rasn_snmp::v1::GetNextRequest(pdu))
        }
        SnmpPduType::Response => {
            let pdu = rasn_snmp::v1::Pdu {
                request_id: Integer::from(stmt.req_id.unwrap_or(1)),
                error_status: Integer::from(0),
                error_index: Integer::from(0),
                variable_bindings: v1_varbinds,
            };
            Pdus::GetResponse(rasn_snmp::v1::GetResponse(pdu))
        }
        SnmpPduType::Set => {
            let pdu = rasn_snmp::v1::Pdu {
                request_id: Integer::from(stmt.req_id.unwrap_or(1)),
                error_status: Integer::from(0),
                error_index: Integer::from(0),
                variable_bindings: v1_varbinds,
            };
            Pdus::SetRequest(rasn_snmp::v1::SetRequest(pdu))
        }
        SnmpPduType::GetBulk | SnmpPduType::Inform | SnmpPduType::Report => {
            return Err("SNMPv1 does not support GETBULK, INFORM, or REPORT".to_string());
        }
    };

    let message = Message {
        version: Integer::from(0),
        community,
        data: pdu_data,
    };

    rasn::ber::encode(&message).map_err(|e| alloc::format!("SNMP1 encode error: {:?}", e))
}

/// Builds an SNMPv2c Trap/Inform/Get payload from a [`FrameStatement`].
pub fn build_snmp2_payload(stmt: &FrameStatement) -> Result<Vec<u8>, String> {
    use rasn_snmp::v2c::Message;

    let spec = match &stmt.protocol_spec {
        Some(ProtocolSpec::Snmp2(s)) => Some(s),
        _ => None,
    };
    let community_str = stmt
        .community
        .or_else(|| spec.and_then(|s| s.community))
        .unwrap_or("public");
    let community = OctetString::from(community_str.as_bytes().to_vec());

    let pdu_data = build_v2_pdus(stmt)?;

    let message = Message {
        version: Integer::from(1),
        community,
        data: pdu_data,
    };

    rasn::ber::encode(&message).map_err(|e| alloc::format!("SNMP2 encode error: {:?}", e))
}

/// Builds an SNMPv3 payload from a [`FrameStatement`].
///
/// Implements RFC 3414 (USM & DES-CBC) and RFC 3826 (AES-128-CFB) cryptography.
pub fn build_snmp3_payload(stmt: &FrameStatement) -> Result<Vec<u8>, String> {
    use rasn_snmp::v3::{HeaderData, Message, ScopedPdu, ScopedPduData, USMSecurityParameters};

    let spec = match &stmt.protocol_spec {
        Some(ProtocolSpec::Snmp3(s)) => Some(s),
        _ => None,
    };
    let user_str = stmt
        .user
        .or_else(|| spec.and_then(|s| s.user))
        .unwrap_or("admin");
    let user = OctetString::from(user_str.as_bytes().to_vec());
    let engine_id_str = stmt
        .engine_id
        .or_else(|| spec.and_then(|s| s.engine_id))
        .unwrap_or("8000000001");
    let engine_id_bytes = hex_to_bytes(engine_id_str)?;
    let engine_id = OctetString::from(engine_id_bytes.clone());

    let pdu_data = build_v2_pdus(stmt)?;

    let context_name_str = stmt
        .context_name
        .or_else(|| spec.and_then(|s| s.context_name))
        .unwrap_or("");
    let scoped_pdu = ScopedPdu {
        engine_id: engine_id.clone(),
        name: OctetString::from(context_name_str.as_bytes().to_vec()),
        data: pdu_data,
    };

    let eff_auth = stmt
        .auth
        .as_ref()
        .or_else(|| spec.and_then(|s| s.auth.as_ref()));
    let eff_priv = stmt
        .priv_param
        .as_ref()
        .or_else(|| spec.and_then(|s| s.priv_param.as_ref()));
    let eff_boots = stmt
        .engine_boots
        .or_else(|| spec.and_then(|s| s.engine_boots))
        .unwrap_or(0);
    let eff_time = stmt
        .engine_time
        .or_else(|| spec.and_then(|s| s.engine_time))
        .unwrap_or(0);
    let eff_req_id = stmt
        .req_id
        .or_else(|| spec.and_then(|s| s.req_id))
        .unwrap_or(1);

    if let Some((_, pass)) = eff_auth
        && pass.is_empty()
    {
        return Err("SNMPv3 authentication password cannot be empty".to_string());
    }
    if let Some((_, pass)) = eff_priv
        && pass.is_empty()
    {
        return Err("SNMPv3 privacy password cannot be empty".to_string());
    }
    if eff_auth.is_none() && eff_priv.is_some() {
        return Err("SNMPv3 does not support privacy without authentication (noAuthPriv)".to_string());
    }

    let mut flags = 0u8;
    if eff_auth.is_some() {
        flags |= 1; // authFlag
    }
    if eff_priv.is_some() {
        flags |= 2; // privFlag
    }
    let pdu_type = stmt
        .pdu_type
        .as_ref()
        .or_else(|| spec.and_then(|s| s.pdu_type.as_ref()))
        .unwrap_or(&SnmpPduType::Trap);
    let is_confirmed = matches!(
        pdu_type,
        SnmpPduType::Get
            | SnmpPduType::GetNext
            | SnmpPduType::GetBulk
            | SnmpPduType::Set
            | SnmpPduType::Inform
    );
    if is_confirmed {
        flags |= 4; // reportableFlag (RFC 3412 §6.2)
    }

    let auth_len = match eff_auth.map(|(t, _)| t) {
        Some(SnmpAuthType::Md5) | Some(SnmpAuthType::Sha) => 12,
        Some(SnmpAuthType::Sha256) => 24,
        Some(SnmpAuthType::Sha384) => 32,
        Some(SnmpAuthType::Sha512) => 48,
        None => 0,
    };

    // Deterministic 8-byte salt for reproducible PCAP generation (RFC 3414 / RFC 3826)
    let deterministic_salt: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let mut usm_params = USMSecurityParameters {
        authoritative_engine_id: engine_id.clone(),
        authoritative_engine_boots: Integer::from(eff_boots),
        authoritative_engine_time: Integer::from(eff_time),
        user_name: user,
        authentication_parameters: OctetString::from(vec![0; auth_len]),
        privacy_parameters: OctetString::from(if eff_priv.is_some() {
            deterministic_salt.to_vec()
        } else {
            vec![]
        }),
    };

    let mut auth_key = None;
    if let Some((auth_type, pass)) = eff_auth {
        auth_key = Some(match auth_type {
            SnmpAuthType::Md5 => password_to_key_md5(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha => password_to_key_sha1(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha256 => password_to_key_sha256(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha384 => password_to_key_sha384(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha512 => password_to_key_sha512(pass.as_bytes(), &engine_id_bytes),
        });
    }

    let mut priv_key = None;
    if let Some((_priv_type, pass)) = eff_priv {
        let hasher = eff_auth.map(|(t, _)| t).unwrap_or(&SnmpAuthType::Md5);
        priv_key = Some(match hasher {
            SnmpAuthType::Md5 => password_to_key_md5(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha => password_to_key_sha1(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha256 => password_to_key_sha256(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha384 => password_to_key_sha384(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha512 => password_to_key_sha512(pass.as_bytes(), &engine_id_bytes),
        });
    }

    if eff_auth.is_none() {
        usm_params.authentication_parameters = OctetString::from(vec![]);
    }

    let usm_bytes =
        rasn::ber::encode(&usm_params).map_err(|e| alloc::format!("USM encode error: {:?}", e))?;

    let scoped_data = if let Some((priv_type, _)) = eff_priv {
        let plaintext_scoped = rasn::ber::encode(&scoped_pdu)
            .map_err(|e| alloc::format!("ScopedPdu encode error: {:?}", e))?;
        let pk = priv_key
            .as_ref()
            .ok_or_else(|| "Privacy key missing".to_string())?;
        let ciphertext = match priv_type {
            SnmpPrivType::Des => {
                if pk.len() < 16 {
                    return Err(
                        "Privacy key too short for DES (need at least 16 bytes)".to_string()
                    );
                }
                let des_key = &pk[0..8];
                let pre_iv = &pk[8..16];
                let mut iv = [0u8; 8];
                for i in 0..8 {
                    iv[i] = pre_iv[i] ^ deterministic_salt[i];
                }
                encrypt_des(des_key, &iv, &plaintext_scoped)?
            }
            SnmpPrivType::Aes => {
                if pk.len() < 16 {
                    return Err(
                        "Privacy key too short for AES (need at least 16 bytes)".to_string()
                    );
                }
                let aes_key = &pk[0..16];
                let mut iv = [0u8; 16];
                iv[0..4].copy_from_slice(&eff_boots.to_be_bytes());
                iv[4..8].copy_from_slice(&eff_time.to_be_bytes());
                iv[8..16].copy_from_slice(&deterministic_salt);
                encrypt_aes128(aes_key, &iv, &plaintext_scoped)?
            }
        };
        ScopedPduData::EncryptedPdu(OctetString::from(ciphertext))
    } else {
        ScopedPduData::CleartextPdu(scoped_pdu)
    };

    let mut message = Message {
        version: Integer::from(3),
        global_data: HeaderData {
            message_id: Integer::from(eff_req_id),
            max_size: Integer::from(65507),
            flags: OctetString::from(vec![flags]),
            security_model: Integer::from(3),
        },
        security_parameters: OctetString::from(usm_bytes),
        scoped_data,
    };

    if let Some((auth_type, _)) = eff_auth {
        let whole_msg =
            rasn::ber::encode(&message).map_err(|e| alloc::format!("Msg encode error: {:?}", e))?;
        let ak = auth_key
            .as_ref()
            .ok_or_else(|| "Auth key missing".to_string())?;
        let mac = match auth_type {
            SnmpAuthType::Md5 => sign_md5(ak, &whole_msg)?,
            SnmpAuthType::Sha => sign_sha1(ak, &whole_msg)?,
            SnmpAuthType::Sha256 => sign_sha256(ak, &whole_msg)?,
            SnmpAuthType::Sha384 => sign_sha384(ak, &whole_msg)?,
            SnmpAuthType::Sha512 => sign_sha512(ak, &whole_msg)?,
        };
        usm_params.authentication_parameters = OctetString::from(mac);
        let usm_bytes = rasn::ber::encode(&usm_params)
            .map_err(|e| alloc::format!("USM encode error: {:?}", e))?;
        message.security_parameters = OctetString::from(usm_bytes);
    }

    rasn::ber::encode(&message).map_err(|e| alloc::format!("SNMP3 encode error: {:?}", e))
}

/// Decodes a non-empty, even-length ASCII hexadecimal string (with optional `0x` / `0X` prefix) into bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    if hex.is_empty() {
        return Err("SNMPv3 engineid cannot be empty".to_string());
    }
    if !hex.is_ascii() || !hex.len().is_multiple_of(2) {
        return Err(alloc::format!(
            "Invalid SNMPv3 engineid '{hex}': expected an even number of hexadecimal digits"
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().as_chunks::<2>().0 {
        let pair_str = core::str::from_utf8(pair).map_err(|_| "Invalid hex")?;
        let b = u8::from_str_radix(pair_str, 16).map_err(|_| {
            alloc::format!("Invalid SNMPv3 engineid '{hex}': contains non-hexadecimal characters")
        })?;
        bytes.push(b);
    }
    Ok(bytes)
}

/// Parses an OID dot-notation string into a `rasn` `ObjectIdentifier`.
fn parse_oid(oid_str: &str) -> Result<ObjectIdentifier, String> {
    let mut oid_vec = Vec::new();
    for s in oid_str.trim_start_matches('.').split('.') {
        match s.parse::<u32>() {
            Ok(val) => oid_vec.push(val),
            Err(_) => return Err(alloc::format!("Invalid OID segment: '{}'", s)),
        }
    }
    if oid_vec.len() < 2 {
        return Err(alloc::format!(
            "Invalid OID '{}': must contain at least 2 arcs",
            oid_str
        ));
    }
    if oid_vec[0] > 2 || (oid_vec[0] < 2 && oid_vec[1] >= 40) {
        return Err(alloc::format!(
            "Invalid OID '{}': invalid root/second arc combination",
            oid_str
        ));
    }
    ObjectIdentifier::new(oid_vec).ok_or_else(|| "Invalid OID structure".to_string())
}

/// Converts AST [`VarBindAst`] nodes into `rasn` SNMPv2/v3 Variable Bindings.
fn convert_varbinds(vbs: &[VarBindAst]) -> Result<Vec<VarBind>, String> {
    let mut out = Vec::new();
    for vb in vbs {
        let name = parse_oid(vb.oid)?;
        let value = match &vb.val {
            VarBindType::Null => VarBindValue::Unspecified,
            VarBindType::String(s) => VarBindValue::Value(ObjectSyntax::Simple(
                SimpleSyntax::String(s.as_bytes().to_vec().into()),
            )),
            VarBindType::Int(i) => VarBindValue::Value(ObjectSyntax::Simple(
                SimpleSyntax::Integer(rasn::types::Integer::from(*i)),
            )),
            VarBindType::TimeTicks(t) => VarBindValue::Value(ObjectSyntax::ApplicationWide(
                ApplicationSyntax::Ticks(TimeTicks(*t)),
            )),
            VarBindType::Ip(ip) => match ip {
                IpAddr::V4(v4) => {
                    let addr = v4.octets();
                    VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(
                        IpAddress(addr.into()),
                    )))
                }
                IpAddr::V6(v6) => {
                    let addr = v6.octets();
                    VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::String(
                        addr.to_vec().into(),
                    )))
                }
            },
            VarBindType::OidVal(oid_str) => {
                let oid = parse_oid(oid_str)?;
                VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::ObjectId(oid)))
            }
            VarBindType::Counter32(c) => VarBindValue::Value(ObjectSyntax::ApplicationWide(
                ApplicationSyntax::Counter(rasn_smi::v1::Counter(*c)),
            )),
            VarBindType::Gauge32(g) => VarBindValue::Value(ObjectSyntax::ApplicationWide(
                ApplicationSyntax::Unsigned(rasn_smi::v1::Gauge(*g)),
            )),
            VarBindType::Counter64(c) => VarBindValue::Value(ObjectSyntax::ApplicationWide(
                ApplicationSyntax::BigCounter(rasn_smi::v2::Counter64(*c)),
            )),
        };
        out.push(VarBind { name, value });
    }
    Ok(out)
}

/// Converts AST [`VarBindAst`] nodes into `rasn` SNMPv1 Variable Bindings.
fn convert_v1_varbinds(vbs: &[VarBindAst]) -> Result<Vec<rasn_snmp::v1::VarBind>, String> {
    use rasn_snmp::v1::VarBind;
    let mut out = Vec::new();
    for vb in vbs {
        let name = parse_oid(vb.oid)?;
        let value = match &vb.val {
            VarBindType::Null => {
                rasn_smi::v1::ObjectSyntax::Simple(rasn_smi::v1::SimpleSyntax::Empty)
            }
            VarBindType::String(s) => rasn_smi::v1::ObjectSyntax::Simple(
                rasn_smi::v1::SimpleSyntax::String(s.as_bytes().to_vec().into()),
            ),
            VarBindType::Int(i) => rasn_smi::v1::ObjectSyntax::Simple(
                rasn_smi::v1::SimpleSyntax::Number(rasn::types::Integer::from(*i)),
            ),
            VarBindType::TimeTicks(t) => rasn_smi::v1::ObjectSyntax::ApplicationWide(
                rasn_smi::v1::ApplicationSyntax::Ticks(TimeTicks(*t)),
            ),
            VarBindType::Ip(ip) => match ip {
                IpAddr::V4(v4) => {
                    let addr = v4.octets();
                    rasn_smi::v1::ObjectSyntax::ApplicationWide(
                        rasn_smi::v1::ApplicationSyntax::Address(
                            rasn_smi::v1::NetworkAddress::Internet(IpAddress(addr.into())),
                        ),
                    )
                }
                IpAddr::V6(v6) => {
                    let addr = v6.octets();
                    rasn_smi::v1::ObjectSyntax::Simple(rasn_smi::v1::SimpleSyntax::String(
                        addr.to_vec().into(),
                    ))
                }
            },
            VarBindType::OidVal(oid_str) => {
                let oid = parse_oid(oid_str)?;
                rasn_smi::v1::ObjectSyntax::Simple(rasn_smi::v1::SimpleSyntax::Object(oid))
            }
            VarBindType::Counter32(c) => rasn_smi::v1::ObjectSyntax::ApplicationWide(
                rasn_smi::v1::ApplicationSyntax::Counter(rasn_smi::v1::Counter(*c)),
            ),
            VarBindType::Gauge32(g) => rasn_smi::v1::ObjectSyntax::ApplicationWide(
                rasn_smi::v1::ApplicationSyntax::Gauge(rasn_smi::v1::Gauge(*g)),
            ),
            VarBindType::Counter64(_) => {
                return Err(
                    "Counter64 is not supported in SNMPv1 (introduced in SNMPv2 SMIv2 RFC 2578)"
                        .to_string(),
                );
            }
        };
        out.push(VarBind { name, value });
    }
    Ok(out)
}

/// Builds SNMPv2 PDUs respecting RFC 3416 `VarBind` ordering.
///
/// For `Trap` and `Inform` PDUs, `sysUpTime.0` and `snmpTrapOID.0` are always prepended
/// as the first two `VarBind` entries, followed by user `VarBind` entries.
/// For request PDUs, only requested `VarBind` entries are encoded.
fn build_v2_pdus(stmt: &FrameStatement) -> Result<PdusV2, String> {
    let (s2, s3) = match &stmt.protocol_spec {
        Some(ProtocolSpec::Snmp2(s)) => (Some(s), None),
        Some(ProtocolSpec::Snmp3(s)) => (None, Some(s)),
        _ => (None, None),
    };
    let pdu_type = stmt
        .pdu_type
        .as_ref()
        .or_else(|| s2.and_then(|s| s.pdu_type.as_ref()))
        .or_else(|| s3.and_then(|s| s.pdu_type.as_ref()))
        .unwrap_or(&SnmpPduType::Trap);
    let is_notification = matches!(pdu_type, SnmpPduType::Trap | SnmpPduType::Inform);

    let vbs_slice: &[VarBindAst] = if !stmt.varbinds.is_empty() {
        &stmt.varbinds
    } else if let Some(s) = s2
        && !s.varbinds.is_empty()
    {
        &s.varbinds
    } else if let Some(s) = s3
        && !s.varbinds.is_empty()
    {
        &s.varbinds
    } else {
        &[]
    };

    let varbinds = if is_notification {
        let sys_up_time_oid = ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 3, 0])
            .ok_or_else(|| "Invalid sysUpTime OID".to_string())?;
        let snmp_trap_oid_name = ObjectIdentifier::new(vec![1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0])
            .ok_or_else(|| "Invalid snmpTrapOID".to_string())?;
        let requested_trap_oid = parse_oid(stmt.oid.unwrap_or("1.3.6.1.6.3.1.1.5.3"))?;

        let mut vbs = vec![
            VarBind {
                name: sys_up_time_oid,
                value: VarBindValue::Value(ObjectSyntax::ApplicationWide(
                    ApplicationSyntax::Ticks(TimeTicks(stmt.sys_up_time.unwrap_or(0))),
                )),
            },
            VarBind {
                name: snmp_trap_oid_name,
                value: VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::ObjectId(
                    requested_trap_oid,
                ))),
            },
        ];
        let user_vbs = convert_varbinds(vbs_slice)?;
        vbs.extend(user_vbs);
        vbs
    } else if !vbs_slice.is_empty() {
        convert_varbinds(vbs_slice)?
    } else if let Some(oid_str) = stmt.oid {
        let oid = parse_oid(oid_str)?;
        vec![VarBind {
            name: oid,
            value: VarBindValue::Unspecified,
        }]
    } else {
        vec![]
    };

    let req_id = stmt
        .req_id
        .or_else(|| s2.and_then(|s| s.req_id))
        .or_else(|| s3.and_then(|s| s.req_id))
        .unwrap_or(1) as i32;
    let non_repeaters = stmt
        .non_repeaters
        .or_else(|| s2.and_then(|s| s.non_repeaters))
        .or_else(|| s3.and_then(|s| s.non_repeaters))
        .unwrap_or(0);
    let max_repetitions = stmt
        .max_repetitions
        .or_else(|| s2.and_then(|s| s.max_repetitions))
        .or_else(|| s3.and_then(|s| s.max_repetitions))
        .unwrap_or(10);

    let pdu = Pdu {
        request_id: req_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: varbinds.clone(),
    };

    match pdu_type {
        SnmpPduType::Trap => Ok(PdusV2::Trap(rasn_snmp::v2::Trap(pdu))),
        SnmpPduType::Get => Ok(PdusV2::GetRequest(rasn_snmp::v2::GetRequest(pdu))),
        SnmpPduType::Set => Ok(PdusV2::SetRequest(rasn_snmp::v2::SetRequest(pdu))),
        SnmpPduType::Response => Ok(PdusV2::Response(rasn_snmp::v2::Response(pdu))),
        SnmpPduType::Inform => Ok(PdusV2::InformRequest(rasn_snmp::v2::InformRequest(pdu))),
        SnmpPduType::GetNext => Ok(PdusV2::GetNextRequest(rasn_snmp::v2::GetNextRequest(pdu))),
        SnmpPduType::Report => Ok(PdusV2::Report(rasn_snmp::v2::Report(pdu))),
        SnmpPduType::GetBulk => {
            let bulk_pdu = BulkPdu {
                request_id: req_id,
                non_repeaters,
                max_repetitions,
                variable_bindings: varbinds,
            };
            Ok(PdusV2::GetBulkRequest(rasn_snmp::v2::GetBulkRequest(
                bulk_pdu,
            )))
        }
    }
}
