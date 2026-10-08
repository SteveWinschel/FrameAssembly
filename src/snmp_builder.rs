use crate::ast::*;
use crate::snmp_crypto::*;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1::{IpAddress, NetworkAddress, TimeTicks};
use rasn_smi::v2::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
use rasn_snmp::v2::{BulkPdu, Pdu, Pdus as PdusV2, VarBind, VarBindValue};

/// Builds an SNMPv1 Trap payload from a FrameStatement
pub fn build_snmp1_payload(stmt: &FrameStatement, src_ip: IpAddr) -> Result<Vec<u8>, String> {
    use rasn_snmp::v1::{Message, Pdus, Trap};

    let community_str = stmt.community.unwrap_or("public");
    let community = OctetString::from(community_str.as_bytes().to_vec());

    let enterprise_str = stmt.enterprise.unwrap_or("1.3.6.1.4.1");
    let trap_oid = parse_oid(enterprise_str)?;

    let agent_ip = match stmt.agent_ip.unwrap_or(src_ip) {
        IpAddr::V4(addr) => addr.octets(),
        _ => return Err("SNMPv1 Trap requires IPv4 address".to_string()),
    };

    let trap = Trap {
        enterprise: trap_oid,
        agent_addr: NetworkAddress::Internet(IpAddress(agent_ip.into())),
        generic_trap: Integer::from(stmt.gen_trap.unwrap_or(6)),
        specific_trap: Integer::from(stmt.spec_trap.unwrap_or(1)),
        time_stamp: TimeTicks(stmt.sys_up_time.unwrap_or(0)),
        variable_bindings: convert_v1_varbinds(&stmt.varbinds)?,
    };

    let message = Message {
        version: Integer::from(0),
        community,
        data: Pdus::Trap(trap),
    };

    rasn::ber::encode(&message).map_err(|e| alloc::format!("SNMP1 encode error: {:?}", e))
}

/// Builds an SNMPv2c Trap/Inform/Get payload from a FrameStatement
pub fn build_snmp2_payload(stmt: &FrameStatement) -> Result<Vec<u8>, String> {
    use rasn_snmp::v2c::Message;

    let community_str = stmt.community.unwrap_or("public");
    let community = OctetString::from(community_str.as_bytes().to_vec());

    let pdu_data = build_v2_pdus(stmt)?;

    let message = Message {
        version: Integer::from(1),
        community,
        data: pdu_data,
    };

    rasn::ber::encode(&message).map_err(|e| alloc::format!("SNMP2 encode error: {:?}", e))
}

/// Builds an SNMPv3 payload from a FrameStatement
pub fn build_snmp3_payload(stmt: &FrameStatement) -> Result<Vec<u8>, String> {
    use rasn_snmp::v3::{HeaderData, Message, ScopedPdu, ScopedPduData, USMSecurityParameters};

    let user_str = stmt.user.unwrap_or("admin");
    let user = OctetString::from(user_str.as_bytes().to_vec());
    let engine_id_str = stmt.engine_id.unwrap_or("8000000001");
    let engine_id_bytes =
        hex_to_bytes(engine_id_str).unwrap_or_else(|_| vec![0x80, 0x00, 0x00, 0x00, 0x01]);
    let engine_id = OctetString::from(engine_id_bytes.clone());

    let pdu_data = build_v2_pdus(stmt)?;

    let scoped_pdu = ScopedPdu {
        engine_id: engine_id.clone(),
        name: OctetString::from(stmt.context_name.unwrap_or("").as_bytes().to_vec()),
        data: pdu_data,
    };

    let mut flags = 0u8;
    if stmt.auth.is_some() {
        flags |= 1; // authFlag
    }
    if stmt.priv_param.is_some() {
        flags |= 2; // privFlag
    }

    let auth_len = match stmt.auth.as_ref().map(|(t, _)| t) {
        Some(SnmpAuthType::Md5) | Some(SnmpAuthType::Sha) => 12,
        Some(SnmpAuthType::Sha256) => 24,
        Some(SnmpAuthType::Sha384) => 32,
        Some(SnmpAuthType::Sha512) => 48,
        None => 0,
    };

    let mut usm_params = USMSecurityParameters {
        authoritative_engine_id: engine_id.clone(),
        authoritative_engine_boots: Integer::from(stmt.engine_boots.unwrap_or(0)),
        authoritative_engine_time: Integer::from(stmt.engine_time.unwrap_or(0)),
        user_name: user,
        authentication_parameters: OctetString::from(vec![0; auth_len]),
        privacy_parameters: OctetString::from(vec![0; 8]),
    };

    let mut auth_key = None;
    if let Some((auth_type, pass)) = &stmt.auth {
        auth_key = Some(match auth_type {
            SnmpAuthType::Md5 => password_to_key_md5(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha => password_to_key_sha1(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha256 => password_to_key_sha256(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha384 => password_to_key_sha384(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha512 => password_to_key_sha512(pass.as_bytes(), &engine_id_bytes),
        });
    }

    let mut priv_key = None;
    let mut priv_iv = vec![0u8; 16];
    if let Some((_priv_type, pass)) = &stmt.priv_param {
        let hasher = stmt
            .auth
            .as_ref()
            .map(|(t, _)| t)
            .unwrap_or(&SnmpAuthType::Md5);
        priv_key = Some(match hasher {
            SnmpAuthType::Md5 => password_to_key_md5(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha => password_to_key_sha1(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha256 => password_to_key_sha256(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha384 => password_to_key_sha384(pass.as_bytes(), &engine_id_bytes),
            SnmpAuthType::Sha512 => password_to_key_sha512(pass.as_bytes(), &engine_id_bytes),
        });

        let iv = vec![0u8; 16];
        priv_iv = iv;
        usm_params.privacy_parameters = OctetString::from(priv_iv[0..8].to_vec());
    } else {
        usm_params.privacy_parameters = OctetString::from(vec![]);
    }

    if stmt.auth.is_none() {
        usm_params.authentication_parameters = OctetString::from(vec![]);
    }

    let usm_bytes =
        rasn::ber::encode(&usm_params).map_err(|e| alloc::format!("USM encode error: {:?}", e))?;

    let scoped_data = if let Some((priv_type, _)) = &stmt.priv_param {
        let plaintext_scoped = rasn::ber::encode(&scoped_pdu)
            .map_err(|e| alloc::format!("ScopedPdu encode error: {:?}", e))?;
        let pk = priv_key.unwrap();
        let ciphertext = match priv_type {
            SnmpPrivType::Des => encrypt_des(&pk[0..8], &priv_iv[0..8], &plaintext_scoped),
            SnmpPrivType::Aes => encrypt_aes128(&pk[0..16], &priv_iv[0..16], &plaintext_scoped),
        };
        ScopedPduData::EncryptedPdu(OctetString::from(ciphertext))
    } else {
        ScopedPduData::CleartextPdu(scoped_pdu)
    };

    let mut message = Message {
        version: Integer::from(3),
        global_data: HeaderData {
            message_id: Integer::from(stmt.req_id.unwrap_or(1)),
            max_size: Integer::from(65507),
            flags: OctetString::from(vec![flags]),
            security_model: Integer::from(3),
        },
        security_parameters: OctetString::from(usm_bytes),
        scoped_data,
    };

    if let Some((auth_type, _)) = &stmt.auth {
        let whole_msg =
            rasn::ber::encode(&message).map_err(|e| alloc::format!("Msg encode error: {:?}", e))?;
        let ak = auth_key.unwrap();
        let mac = match auth_type {
            SnmpAuthType::Md5 => sign_md5(&ak, &whole_msg),
            SnmpAuthType::Sha => sign_sha1(&ak, &whole_msg),
            SnmpAuthType::Sha256 => sign_sha256(&ak, &whole_msg),
            SnmpAuthType::Sha384 => sign_sha384(&ak, &whole_msg),
            SnmpAuthType::Sha512 => sign_sha512(&ak, &whole_msg),
        };
        usm_params.authentication_parameters = OctetString::from(mac);
        let usm_bytes = rasn::ber::encode(&usm_params)
            .map_err(|e| alloc::format!("USM encode error: {:?}", e))?;
        message.security_parameters = OctetString::from(usm_bytes);
    }

    rasn::ber::encode(&message).map_err(|e| alloc::format!("SNMP3 encode error: {:?}", e))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have an even length".to_string());
    }
    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "Invalid hex")?);
    }
    Ok(bytes)
}

fn parse_oid(oid_str: &str) -> Result<ObjectIdentifier, String> {
    let mut oid_vec = Vec::new();
    for s in oid_str.trim_start_matches('.').split('.') {
        match s.parse::<u32>() {
            Ok(val) => oid_vec.push(val),
            Err(_) => return Err(alloc::format!("Invalid OID segment: '{}'", s)),
        }
    }
    ObjectIdentifier::new(oid_vec).ok_or_else(|| "Invalid OID structure".to_string())
}

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
                SimpleSyntax::Integer(rasn::types::Integer::from(*i as i32)),
            )),
            VarBindType::TimeTicks(t) => VarBindValue::Value(ObjectSyntax::ApplicationWide(
                ApplicationSyntax::Ticks(TimeTicks(*t)),
            )),
            VarBindType::Ip(ip) => {
                let addr = match ip {
                    IpAddr::V4(v4) => v4.octets(),
                    _ => return Err("IPv6 not supported in VarBind".to_string()),
                };
                VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(
                    IpAddress(addr.into()),
                )))
            }
        };
        out.push(VarBind { name, value });
    }
    Ok(out)
}

fn convert_v1_varbinds(vbs: &[VarBindAst]) -> Result<Vec<rasn_snmp::v1::VarBind>, String> {
    use rasn_snmp::v1::VarBind;
    let mut out = Vec::new();
    for vb in vbs {
        let name = parse_oid(vb.oid)?;
        let value = match &vb.val {
            VarBindType::Null => return Err("Null varbind not supported in v1".to_string()),
            VarBindType::String(s) => rasn_smi::v1::ObjectSyntax::Simple(
                rasn_smi::v1::SimpleSyntax::String(s.as_bytes().to_vec().into()),
            ),
            VarBindType::Int(i) => rasn_smi::v1::ObjectSyntax::Simple(
                rasn_smi::v1::SimpleSyntax::Number(rasn::types::Integer::from(*i as i32)),
            ),
            VarBindType::TimeTicks(t) => rasn_smi::v1::ObjectSyntax::ApplicationWide(
                rasn_smi::v1::ApplicationSyntax::Ticks(TimeTicks(*t)),
            ),
            VarBindType::Ip(ip) => {
                let addr = match ip {
                    IpAddr::V4(v4) => v4.octets(),
                    _ => return Err("IPv6 not supported in VarBind".to_string()),
                };
                rasn_smi::v1::ObjectSyntax::ApplicationWide(rasn_smi::v1::ApplicationSyntax::Address(
                    rasn_smi::v1::NetworkAddress::Internet(IpAddress(addr.into())),
                ))
            }
        };
        out.push(VarBind { name, value });
    }
    Ok(out)
}

fn build_v2_pdus(stmt: &FrameStatement) -> Result<PdusV2, String> {
    let mut varbinds = convert_varbinds(&stmt.varbinds)?;

    if varbinds.is_empty() {
        let sys_up_time_oid = ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap();
        let snmp_trap_oid_name =
            ObjectIdentifier::new(vec![1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]).unwrap();
        let requested_trap_oid = parse_oid(stmt.oid.unwrap_or("1.3.6.1.6.3.1.1.5.3"))?;

        varbinds = vec![
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
    }

    let pdu = Pdu {
        request_id: stmt.req_id.unwrap_or(1) as i32,
        error_status: 0,
        error_index: 0,
        variable_bindings: varbinds.clone(),
    };

    let pdu_type = stmt.pdu_type.as_ref().unwrap_or(&SnmpPduType::Trap);
    match pdu_type {
        SnmpPduType::Trap => Ok(PdusV2::Trap(rasn_snmp::v2::Trap(pdu))),
        SnmpPduType::Get => Ok(PdusV2::GetRequest(rasn_snmp::v2::GetRequest(pdu))),
        SnmpPduType::Set => Ok(PdusV2::SetRequest(rasn_snmp::v2::SetRequest(pdu))),
        SnmpPduType::Response => Ok(PdusV2::Response(rasn_snmp::v2::Response(pdu))),
        SnmpPduType::Inform => Ok(PdusV2::InformRequest(rasn_snmp::v2::InformRequest(pdu))),
        SnmpPduType::GetNext => Ok(PdusV2::GetNextRequest(rasn_snmp::v2::GetNextRequest(pdu))),
        SnmpPduType::GetBulk => {
            let bulk_pdu = BulkPdu {
                request_id: stmt.req_id.unwrap_or(1) as i32,
                non_repeaters: stmt.non_repeaters.unwrap_or(0),
                max_repetitions: stmt.max_repetitions.unwrap_or(10),
                variable_bindings: varbinds,
            };
            Ok(PdusV2::GetBulkRequest(rasn_snmp::v2::GetBulkRequest(
                bulk_pdu,
            )))
        }
    }
}
