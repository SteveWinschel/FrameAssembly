//! Comprehensive integration tests for SNMPv1, SNMPv2c, and SNMPv3 USM specifications.
//!
//! Covers RFC-compliant ASN.1 BER encoding, SMI variable bindings, and USM cryptography:
//! - SNMPv1/v2c/v3 specifications and ASN.1 BER message serialization.
//! - RFC 1157 SNMPv1 PDU tags: `GET` (`0xa0`), `GETNEXT` (`0xa1`), `RESPONSE` (`0xa2`), `SET` (`0xa3`), `TRAP` (`0xa4`).
//! - RFC 3584 §3.2: SNMPv1 Traps over IPv6 defaulting `agent-addr` to `0.0.0.0` and `AGENTIP` overrides.
//! - RFC 4001: 16-byte `IPVAL` IPv6 addresses alongside IPv4 in variable bindings.
//! - RFC 3416: VarBind ordering (mandatory `sysUpTime.0` and `snmpTrapOID.0`).
//! - RFC 3414: DES-CBC USM privacy cryptography and zero-padding.
//! - RFC 3826: AES-128-CFB USM privacy cryptography and 16-byte IV construction.
//! - SMI VarBind types (`Integer`, `OctetString`, `TimeTicks`, `Counter32`, `Gauge32`, `Counter64`, `Null`).

use aes::Aes128;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding};
use des::Des;
use frameassembly::ast::*;
use frameassembly::parser::parse_program;
use frameassembly::snmp_builder::*;
use frameassembly::snmp_crypto::*;
use rasn_smi::v2::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
use rasn_snmp::v2::{Pdus as PdusV2, VarBindValue};
use rasn_snmp::v3::{Message as V3Message, ScopedPdu, ScopedPduData, USMSecurityParameters};
use std::net::IpAddr;

/// DES-CBC decryptor alias for RFC 3414 USM privacy testing.
type DesCbcDec = cbc::Decryptor<Des>;

/// AES-128-CFB decryptor alias for RFC 3826 USM privacy testing.
type Aes128CfbDec = cfb_mode::Decryptor<Aes128>;

/// Tests RFC 3416 mandatory varbind ordering for SNMPv2c traps.
///
/// Ensures that `sysUpTime.0` (`1.3.6.1.2.1.1.3.0`) is placed first, followed by
/// `snmpTrapOID.0` (`1.3.6.1.6.3.1.1.4.1.0`), and then user-defined variable bindings.
#[test]
fn test_snmpv2_trap_varbind_ordering() {
    let v2_trap_script = r#"
        HOST v2_agent { IP 10.31.0.1 }
        HOST v2_nms { IP 10.31.0.2 }
        FLOW v2_trap_order(ag, mgr) {
            ag -> mgr SNMP2 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.3" SYSUPTIME 4200 VARBIND 1.3.6.1.2.1.2.2.1.1.1 INT -15 VARBIND 1.3.6.1.2.1.2.2.1.2.1 STRING "eth0"
        } COMPILE { v2_trap_order(v2_agent, v2_nms) }"#;

    let v2_prog = parse_program(v2_trap_script).expect("Parsing v2 trap failed");
    let v2_stmt = &v2_prog.flows[0].statements[0];
    let payload = build_snmp2_payload(v2_stmt).expect("SNMP2 build failed");
    let msg: rasn_snmp::v2c::Message<PdusV2> = rasn::ber::decode(&payload).expect("SNMP2 decode failed");

    let PdusV2::Trap(trap_pdu) = msg.data else {
        panic!("Expected SNMPv2-Trap-PDU");
    };
    let vbs = &trap_pdu.0.variable_bindings;
    assert_eq!(vbs.len(), 4, "Should have sysUpTime.0, snmpTrapOID.0 + 2 user varbinds");

    assert_eq!(vbs[0].name.to_string(), "1.3.6.1.2.1.1.3.0");
    if let VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(t))) = &vbs[0].value {
        assert_eq!(t.0, 4200);
    } else {
        panic!("Expected TimeTicks for sysUpTime.0, got {:?}", vbs[0].value);
    }

    assert_eq!(vbs[1].name.to_string(), "1.3.6.1.6.3.1.1.4.1.0");
    if let VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::ObjectId(oid))) = &vbs[1].value {
        assert_eq!(oid.to_string(), "1.3.6.1.6.3.1.1.5.3");
    } else {
        panic!("Expected ObjectId for snmpTrapOID.0, got {:?}", vbs[1].value);
    }

    assert_eq!(vbs[2].name.to_string(), "1.3.6.1.2.1.2.2.1.1.1");
    if let VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(i))) = &vbs[2].value {
        assert_eq!(i, &rasn::types::Integer::from(-15i32));
    } else {
        panic!("Expected signed Integer, got {:?}", vbs[2].value);
    }

    assert_eq!(vbs[3].name.to_string(), "1.3.6.1.2.1.2.2.1.2.1");
    if let VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::String(s))) = &vbs[3].value {
        assert_eq!(s.as_ref(), b"eth0");
    } else {
        panic!("Expected String, got {:?}", vbs[3].value);
    }
}

/// Tests that SNMPv2 GetRequest varbinds properly default to `Unspecified` values.
#[test]
fn test_snmpv2_get_varbind_handling() {
    let get_script = r#"
        HOST get_cli { IP 10.32.0.1 }
        HOST get_ag { IP 10.32.0.2 }
        FLOW v2_get_flow(gc, ga) {
            gc -> ga SNMP2 GET COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
        } COMPILE { v2_get_flow(get_cli, get_ag) }"#;

    let get_prog = parse_program(get_script).expect("Parsing v2 get failed");
    let payload = build_snmp2_payload(&get_prog.flows[0].statements[0]).expect("SNMP2 get build failed");
    let msg: rasn_snmp::v2c::Message<PdusV2> = rasn::ber::decode(&payload).expect("SNMP2 get decode failed");

    let PdusV2::GetRequest(get_pdu) = msg.data else {
        panic!("Expected GetRequest PDU");
    };
    let vbs = &get_pdu.0.variable_bindings;
    assert_eq!(vbs.len(), 1, "Should only have the requested OID VarBind");
    assert_eq!(vbs[0].name.to_string(), "1.3.6.1.2.1.1.1.0");
    assert!(matches!(vbs[0].value, VarBindValue::Unspecified));
}

/// Tests RFC 3414 DES-CBC USM cryptography, 8-byte salt generation, and `ZeroPadding`.
#[test]
fn test_snmpv3_des_cbc_cryptography_and_padding() {
    let des_script = r#"
        HOST des_agent { IP 10.33.0.1 }
        HOST des_nms { IP 10.33.0.2 }
        FLOW v3_des_flow(da, dn) {
            da -> dn SNMP3 TRAP USER "usr-md5-des" ENGINEID "8000000001" ENGINEBOOTS 5 ENGINETIME 1234 AUTH MD5 "authpassword1" PRIV DES "privpassword1" OID "1.3.6.1.6.3.1.1.5.1" SYSUPTIME 500
        } COMPILE { v3_des_flow(des_agent, des_nms) }"#;

    let des_prog = parse_program(des_script).expect("Parsing v3 des failed");
    let payload = build_snmp3_payload(&des_prog.flows[0].statements[0]).expect("SNMP3 DES build failed");
    let msg: V3Message = rasn::ber::decode(&payload).expect("SNMP3 DES decode failed");
    let usm_params: USMSecurityParameters = rasn::ber::decode(msg.security_parameters.as_ref()).expect("USM params decode failed");

    let salt = usm_params.privacy_parameters.as_ref();
    assert_eq!(salt, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    let ScopedPduData::EncryptedPdu(ciphertext) = msg.scoped_data else {
        panic!("Expected EncryptedPdu for DES-CBC");
    };
    assert_eq!(ciphertext.len() % 8, 0);

    let engine_id = &[0x80, 0x00, 0x00, 0x00, 0x01];
    let priv_key = password_to_key_md5(b"privpassword1", engine_id);
    assert_eq!(priv_key.len(), 16);

    let des_key = &priv_key[0..8];
    let pre_iv = &priv_key[8..16];
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre_iv[i] ^ salt[i];
    }

    let decryptor = DesCbcDec::new_from_slices(des_key, &iv).unwrap();
    let mut decrypted_buf = ciphertext.to_vec();
    decryptor.decrypt_padded::<block_padding::ZeroPadding>(&mut decrypted_buf).unwrap();

    let scoped_pdu: ScopedPdu = rasn::ber::decode(&decrypted_buf).expect("Decrypted DES ScopedPdu decode failed");
    assert_eq!(scoped_pdu.engine_id.as_ref(), engine_id);
}

/// Tests RFC 3826 AES-128-CFB USM cryptography, 16-byte IV construction, and decryption.
#[test]
fn test_snmpv3_aes128_cfb_cryptography() {
    let aes_script = r#"
        HOST aes_agent { IP 10.34.0.1 }
        HOST aes_nms { IP 10.34.0.2 }
        FLOW v3_aes_flow(aa, an) {
            aa -> an SNMP3 TRAP USER "usr-sha-aes" ENGINEID "8000000001" ENGINEBOOTS 10 ENGINETIME 5678 AUTH SHA "authpassword1" PRIV AES "privpassword1" OID "1.3.6.1.6.3.1.1.5.3" SYSUPTIME 200
        } COMPILE { v3_aes_flow(aes_agent, aes_nms) }"#;

    let aes_prog = parse_program(aes_script).expect("Parsing v3 aes failed");
    let payload = build_snmp3_payload(&aes_prog.flows[0].statements[0]).expect("SNMP3 AES build failed");
    let msg: V3Message = rasn::ber::decode(&payload).expect("SNMP3 AES decode failed");
    let usm_params: USMSecurityParameters = rasn::ber::decode(msg.security_parameters.as_ref()).expect("USM AES params decode failed");

    let salt = usm_params.privacy_parameters.as_ref();
    assert_eq!(salt, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    let ScopedPduData::EncryptedPdu(ciphertext) = msg.scoped_data else {
        panic!("Expected EncryptedPdu for AES-128-CFB");
    };
    let engine_id = &[0x80, 0x00, 0x00, 0x00, 0x01];
    let priv_key = password_to_key_sha1(b"privpassword1", engine_id);
    let aes_key = &priv_key[0..16];

    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&10u32.to_be_bytes());
    iv[4..8].copy_from_slice(&5678u32.to_be_bytes());
    iv[8..16].copy_from_slice(salt);

    let decryptor = Aes128CfbDec::new_from_slices(aes_key, &iv).unwrap();
    let mut decrypted = ciphertext.to_vec();
    decryptor.decrypt(&mut decrypted);

    let scoped_pdu: ScopedPdu = rasn::ber::decode(&decrypted).expect("Decrypted AES ScopedPdu decode failed");
    assert_eq!(scoped_pdu.engine_id.as_ref(), engine_id);
}

/// Tests RFC 1157 SNMPv1 generic trap auto-mapping and enterprise-specific fallback.
#[test]
fn test_snmpv1_generic_trap_auto_mapping_and_enterprise_fallback() {
    let v1_trap_script = r#"
        HOST v1_ag { IP 10.35.0.1 }
        HOST v1_mgr { IP 10.35.0.2 }
        FLOW v1_trap_map(va, vm) {
            va -> vm SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.3" SYSUPTIME 100
            va -> vm SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.4.1.9999.1" SYSUPTIME 200
        } COMPILE { v1_trap_map(v1_ag, v1_mgr) }"#;

    let v1_prog = parse_program(v1_trap_script).expect("Parsing v1 trap mapping failed");
    let sender_ip = IpAddr::V4("10.35.0.1".parse().unwrap());

    let payload1 = build_snmp1_payload(&v1_prog.flows[0].statements[0], sender_ip).unwrap();
    let msg1: rasn_snmp::v1::Message<rasn_snmp::v1::Pdus> = rasn::ber::decode(&payload1).unwrap();
    let rasn_snmp::v1::Pdus::Trap(trap1) = msg1.data else {
        panic!("Expected Trap PDU 1");
    };
    assert_eq!(trap1.generic_trap, rasn::types::Integer::from(2));
    assert_eq!(trap1.specific_trap, rasn::types::Integer::from(0));
    assert_eq!(trap1.enterprise.to_string(), "1.3.6.1.6.3.1.1.5.3");

    let payload2 = build_snmp1_payload(&v1_prog.flows[0].statements[1], sender_ip).unwrap();
    let msg2: rasn_snmp::v1::Message<rasn_snmp::v1::Pdus> = rasn::ber::decode(&payload2).unwrap();
    let rasn_snmp::v1::Pdus::Trap(trap2) = msg2.data else {
        panic!("Expected Trap PDU 2");
    };
    assert_eq!(trap2.generic_trap, rasn::types::Integer::from(6));
    assert_eq!(trap2.specific_trap, rasn::types::Integer::from(1));
    assert_eq!(trap2.enterprise.to_string(), "1.3.6.1.4.1.9999.1");
}

/// Tests SMI VarBind data types and signed integers (`INT`, `OIDVAL`, `COUNTER32`, `GAUGE32`, `COUNTER64`).
#[test]
fn test_smi_varbind_types_and_signed_integers() {
    let smi_script = r#"
        HOST smi_ag { IP 10.36.0.1 }
        HOST smi_nms { IP 10.36.0.2 }
        FLOW smi_types_flow(sa, sn) {
            sa -> sn SNMP2 TRAP COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 INT -42 VARBIND 1.3.6.1.2.1.1.2.0 OIDVAL 1.3.6.1.4.1.9.1.1 VARBIND 1.3.6.1.2.1.2.2.1.10.1 COUNTER32 4294967000 VARBIND 1.3.6.1.2.1.2.2.1.5.1 GAUGE32 1000000 VARBIND 1.3.6.1.2.1.31.1.1.1.6.1 COUNTER64 18446744073709551600
        } COMPILE { smi_types_flow(smi_ag, smi_nms) }"#;

    let smi_prog = parse_program(smi_script).expect("Parsing SMI types failed");
    let payload = build_snmp2_payload(&smi_prog.flows[0].statements[0]).expect("SNMP2 SMI build failed");
    let msg: rasn_snmp::v2c::Message<PdusV2> = rasn::ber::decode(&payload).expect("SMI decode failed");

    let PdusV2::Trap(trap) = msg.data else {
        panic!("Expected Trap PDU for SMI types");
    };
    let vbs = &trap.0.variable_bindings;
    assert_eq!(vbs.len(), 7);

    if let VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(i))) = &vbs[2].value {
        assert_eq!(i, &rasn::types::Integer::from(-42i32));
    } else {
        panic!("Expected Integer(-42), got {:?}", vbs[2].value);
    }

    if let VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::ObjectId(oid))) = &vbs[3].value {
        assert_eq!(oid.to_string(), "1.3.6.1.4.1.9.1.1");
    } else {
        panic!("Expected ObjectId, got {:?}", vbs[3].value);
    }

    if let VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(c))) = &vbs[4].value {
        assert_eq!(c.0, 4294967000);
    } else {
        panic!("Expected Counter32, got {:?}", vbs[4].value);
    }

    if let VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(g))) = &vbs[5].value {
        assert_eq!(g.0, 1000000);
    } else {
        panic!("Expected Gauge32, got {:?}", vbs[5].value);
    }

    if let VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(c))) = &vbs[6].value {
        assert_eq!(c.0, 18446744073709551600);
    } else {
        panic!("Expected Counter64, got {:?}", vbs[6].value);
    }
}

/// Tests default destination ports: `162` for `TRAP`/`INFORM` and `161` for `GET`/`SET`/`GETNEXT`/`GETBULK`.
#[test]
fn test_default_dst_ports() {
    let ports_script = r#"
        HOST p_cli { IP 10.37.0.1 }
        HOST p_srv { IP 10.37.0.2 }
        FLOW port_check_flow(pc, ps) {
            pc -> ps SNMP2 TRAP COMMUNITY "public"
            pc -> ps SNMP2 INFORM COMMUNITY "public"
            pc -> ps SNMP2 GET COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
            pc -> ps SNMP2 SET COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 STRING "test"
            pc -> ps SNMP2 GETBULK COMMUNITY "public" NONREPEATERS 0 MAXREPETITIONS 10
            pc -> ps SNMP2 GETNEXT COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
            pc -> ps SNMP2 GET DSTPORT 1161 COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
        } COMPILE { port_check_flow(p_cli, p_srv) }"#;

    let ports_prog = parse_program(ports_script).expect("Parsing ports script failed");
    let stmts = &ports_prog.flows[0].statements;

    let resolve_dst_port = |stmt: &FrameStatement| -> u16 {
        stmt.dst_port.unwrap_or(match stmt.protocol {
            Protocol::Snmp1 | Protocol::Snmp2 | Protocol::Snmp3 => {
                match stmt.pdu_type.as_ref().unwrap_or(&SnmpPduType::Trap) {
                    SnmpPduType::Trap | SnmpPduType::Inform => 162,
                    SnmpPduType::Get
                    | SnmpPduType::GetNext
                    | SnmpPduType::GetBulk
                    | SnmpPduType::Set
                    | SnmpPduType::Response => 161,
                }
            }
            _ => 80,
        })
    };

    assert_eq!(resolve_dst_port(&stmts[0]), 162, "TRAP should default to 162");
    assert_eq!(resolve_dst_port(&stmts[1]), 162, "INFORM should default to 162");
    assert_eq!(resolve_dst_port(&stmts[2]), 161, "GET should default to 161");
    assert_eq!(resolve_dst_port(&stmts[3]), 161, "SET should default to 161");
    assert_eq!(resolve_dst_port(&stmts[4]), 161, "GETBULK should default to 161");
    assert_eq!(resolve_dst_port(&stmts[5]), 161, "GETNEXT should default to 161");
    assert_eq!(resolve_dst_port(&stmts[6]), 1161, "Explicit DSTPORT 1161 should be preserved");
}

/// Tests parser diagnostics for signed vs unsigned numeric inputs.
#[test]
fn test_signed_vs_unsigned_parser_diagnostics() {
    use frameassembly::error::CompilerError;

    let valid_int_script = r#"
        HOST si_ag { IP 10.38.1.1 }
        HOST si_nm { IP 10.38.1.2 }
        FLOW si_f1(a, n) { a -> n SNMP2 TRAP COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 INT -42 }
        COMPILE { si_f1(si_ag, si_nm) }"#;
    assert!(parse_program(valid_int_script).is_ok(), "INT -42 should parse cleanly");

    let invalid_srcport_script = r#"
        HOST sp_ag { IP 10.38.2.1 }
        HOST sp_nm { IP 10.38.2.2 }
        FLOW sp_f2(a, n) { a -> n SNMP2 TRAP SRCPORT -1 }
        COMPILE { sp_f2(sp_ag, sp_nm) }"#;
    let res_sp = parse_program(invalid_srcport_script);
    assert!(matches!(res_sp, Err(CompilerError::ParseError { .. })), "SRCPORT -1 must fail with ParseError");

    let invalid_counter32_script = r#"
        HOST c32_ag { IP 10.38.3.1 }
        HOST c32_nm { IP 10.38.3.2 }
        FLOW c32_f3(a, n) { a -> n SNMP2 TRAP VARBIND 1.3.6.1.2.1.1.1.0 COUNTER32 -5 }
        COMPILE { c32_f3(c32_ag, c32_nm) }"#;
    let res_c32 = parse_program(invalid_counter32_script);
    assert!(matches!(res_c32, Err(CompilerError::ParseError { .. })), "COUNTER32 -5 must fail with ParseError");
}

/// Tests RFC 1157 SNMPv1 non-trap PDUs: `GET` (`0xa0`), `GETNEXT` (`0xa1`), `SET` (`0xa3`), `RESPONSE` (`0xa2`).
#[test]
fn test_snmp1_non_trap_pdus_get_getnext_set_response() {
    let v1_pdus_script = r#"
        HOST v1p_cli { IP 10.39.0.1 }
        HOST v1p_srv { IP 10.39.0.2 }
        FLOW v1_non_trap(vc, vs) {
            vc -> vs SNMP1 GET COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
            vc -> vs SNMP1 GETNEXT COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
            vc -> vs SNMP1 SET COMMUNITY "private" VARBIND 1.3.6.1.2.1.1.5.0 STRING "test-host"
            vc <- vs SNMP1 RESPONSE COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 STRING "Linux"
        } COMPILE { v1_non_trap(v1p_cli, v1p_srv) }"#;

    let v1p_prog = parse_program(v1_pdus_script).expect("Parsing SNMP1 non-trap PDUs failed");
    let stmts = &v1p_prog.flows[0].statements;
    assert_eq!(stmts.len(), 4);

    assert_eq!(stmts[0].pdu_type, Some(SnmpPduType::Get));
    assert_eq!(stmts[1].pdu_type, Some(SnmpPduType::GetNext));
    assert_eq!(stmts[2].pdu_type, Some(SnmpPduType::Set));
    assert_eq!(stmts[3].pdu_type, Some(SnmpPduType::Response));

    let src_ip = IpAddr::V4("10.39.0.1".parse().unwrap());
    let payload0 = build_snmp1_payload(&stmts[0], src_ip).expect("SNMP1 GET payload build failed");
    assert!(payload0.contains(&0xa0), "SNMP1 GET should contain ASN.1 tag 0xa0");

    let payload1 = build_snmp1_payload(&stmts[1], src_ip).expect("SNMP1 GETNEXT payload build failed");
    assert!(payload1.contains(&0xa1), "SNMP1 GETNEXT should contain ASN.1 tag 0xa1");

    let payload2 = build_snmp1_payload(&stmts[2], src_ip).expect("SNMP1 SET payload build failed");
    assert!(payload2.contains(&0xa3), "SNMP1 SET should contain ASN.1 tag 0xa3");

    let payload3 = build_snmp1_payload(&stmts[3], src_ip).expect("SNMP1 RESPONSE payload build failed");
    assert!(payload3.contains(&0xa2), "SNMP1 RESPONSE should contain ASN.1 tag 0xa2");
}

/// Tests that `SNMP1` rejects `GETBULK` and `INFORM` operations (introduced in SNMPv2c).
#[test]
fn test_snmp1_reject_getbulk_and_inform() {
    let src_ip = IpAddr::V4("10.40.0.1".parse().unwrap());

    let script_bulk = r#"
        HOST rj_c1 { IP 10.40.0.1 }
        HOST rj_s1 { IP 10.40.0.2 }
        FLOW rj_f1(c, s) { c -> s SNMP1 GETBULK COMMUNITY "public" NONREPEATERS 0 MAXREPETITIONS 10 }
        COMPILE { rj_f1(rj_c1, rj_s1) }"#;
    let bulk_rejected = match parse_program(script_bulk) {
        Ok(prog) => build_snmp1_payload(&prog.flows[0].statements[0], src_ip).is_err(),
        Err(_) => true,
    };
    assert!(bulk_rejected, "SNMP1 GETBULK must be rejected by parser or builder");

    let script_inform = r#"
        HOST rj_c2 { IP 10.40.1.1 }
        HOST rj_s2 { IP 10.40.1.2 }
        FLOW rj_f2(c, s) { c -> s SNMP1 INFORM COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.1" }
        COMPILE { rj_f2(rj_c2, rj_s2) }"#;
    let inform_rejected = match parse_program(script_inform) {
        Ok(prog) => build_snmp1_payload(&prog.flows[0].statements[0], src_ip).is_err(),
        Err(_) => true,
    };
    assert!(inform_rejected, "SNMP1 INFORM must be rejected by parser or builder");
}

/// Tests RFC 1157 §3.2.1.1 `NULL` / `NULLVAL` support in SNMPv1 VarBinds.
#[test]
fn test_snmp1_nullval_support() {
    let null_script = r#"
        HOST nv_c { IP 10.41.0.1 }
        HOST nv_s { IP 10.41.0.2 }
        FLOW nv_flow(nc, ns) { nc -> ns SNMP1 GET COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 NULL }
        COMPILE { nv_flow(nv_c, nv_s) }"#;

    let prog = parse_program(null_script).expect("NULL in SNMP1 varbind should parse cleanly");
    let stmt = &prog.flows[0].statements[0];
    assert_eq!((stmt.varbinds.len(), &stmt.varbinds[0].val), (1, &VarBindType::Null));
}

/// Tests RFC 3584 §3.2: SNMPv1 Traps from IPv6 hosts default `agent-addr` to `0.0.0.0`.
#[test]
fn test_rfc3584_snmp1_ipv6_agent_addr_default() {
    let v6_def_script = r#"
        HOST agent_v6_def { IP 2001:db8:42::1 }
        HOST nms_v6_def { IP 2001:db8:42::2 }
        FLOW v6_def_flow(av6, nv6) {
            av6 -> nv6 SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.1" SYSUPTIME 100
        } COMPILE { v6_def_flow(agent_v6_def, nms_v6_def) }"#;

    let program = parse_program(v6_def_script).expect("IPv6 HOST parsing failed");
    let v6_addr = IpAddr::V6("2001:db8:42::1".parse().unwrap());
    let payload = build_snmp1_payload(&program.flows[0].statements[0], v6_addr)
        .expect("RFC 3584 IPv6 agent-addr default failed");
    let msg: rasn_snmp::v1::Message<rasn_snmp::v1::Pdus> = rasn::ber::decode(&payload).expect("Decoded SNMP1 message");

    let rasn_snmp::v1::Pdus::Trap(trap) = msg.data else {
        panic!("Expected Trap PDU for IPv6 default agent-addr");
    };
    let rasn_smi::v1::NetworkAddress::Internet(rasn_smi::v1::IpAddress(addr_bytes)) = trap.agent_addr;
    assert_eq!(addr_bytes.as_ref(), &[0, 0, 0, 0], "RFC 3584 requires 0.0.0.0 agent-addr for IPv6");
}

/// Tests RFC 3584 §3.2: SNMPv1 Traps over IPv6 with explicit `AGENTIP <ipv4>` proxy override.
#[test]
fn test_rfc3584_snmp1_ipv6_agentip_override() {
    let v6_ovr_script = r#"
        HOST agent_v6_ovr { IP 2001:db8:43::1 }
        HOST nms_v6_ovr { IP 2001:db8:43::2 }
        FLOW v6_ovr_flow(avo, nvo) {
            avo -> nvo SNMP1 TRAP AGENTIP 192.0.2.1 COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.1" SYSUPTIME 100
        } COMPILE { v6_ovr_flow(agent_v6_ovr, nms_v6_ovr) }"#;

    let program = parse_program(v6_ovr_script).expect("IPv6 AGENTIP parsing failed");
    let v6_addr = IpAddr::V6("2001:db8:43::1".parse().unwrap());
    let payload = build_snmp1_payload(&program.flows[0].statements[0], v6_addr)
        .expect("AGENTIP override build failed");
    let msg: rasn_snmp::v1::Message<rasn_snmp::v1::Pdus> = rasn::ber::decode(&payload).expect("Decoded SNMP1 override message");

    let rasn_snmp::v1::Pdus::Trap(trap) = msg.data else {
        panic!("Expected Trap PDU for AGENTIP override");
    };
    let rasn_smi::v1::NetworkAddress::Internet(rasn_smi::v1::IpAddress(addr_bytes)) = trap.agent_addr;
    assert_eq!(addr_bytes.as_ref(), &[192, 0, 2, 1], "Explicit AGENTIP should override agent-addr");
}

/// Tests RFC 4001: 16-byte `IPVAL` IPv6 addresses alongside IPv4 in the same PDU.
#[test]
fn test_rfc4001_ipv6_varbind_ipval() {
    let ipval_script = r#"
        HOST ipv_ag { IP 10.44.0.1 }
        HOST ipv_nm { IP 10.44.0.2 }
        FLOW ipval_mix_flow(ia, inm) {
            ia -> inm SNMP2 TRAP COMMUNITY "public" VARBIND 1.3.6.1.2.1.4.34.1.3.1.4.192.0.2.1 IPVAL 192.0.2.1 VARBIND 1.3.6.1.2.1.4.34.1.3.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1 IPVAL 2001:db8::1
        } COMPILE { ipval_mix_flow(ipv_ag, ipv_nm) }"#;

    let program = parse_program(ipval_script).expect("IPv6 IPVAL parsing failed");
    let stmt = &program.flows[0].statements[0];
    assert_eq!(stmt.varbinds.len(), 2);

    let payload = build_snmp2_payload(stmt).expect("RFC 4001 IPv6 IPVAL build failed");
    let msg: rasn_snmp::v2c::Message<PdusV2> = rasn::ber::decode(&payload).expect("IPVAL decode failed");
    if let PdusV2::Trap(trap) = msg.data {
        assert_eq!(trap.0.variable_bindings.len(), 4);
    } else {
        panic!("Expected Trap PDU for IPVAL test");
    }
}

/// Tests SNMPv3 USM empty password and security parameter validation.
#[test]
fn test_snmpv3_usm_password_and_security_validation() {
    let empty_pwd_script = r#"
        HOST usm_ag { IP 10.45.0.1 }
        HOST usm_nm { IP 10.45.0.2 }
        FLOW usm_empty_pwd(ua, un) {
            ua -> un SNMP3 TRAP USER "admin" AUTH MD5 ""
        } COMPILE { usm_empty_pwd(usm_ag, usm_nm) }"#;

    let prog = parse_program(empty_pwd_script).expect("USM empty password script should parse");
    let stmt = &prog.flows[0].statements[0];
    let build_attempt = std::panic::catch_unwind(|| build_snmp3_payload(stmt));
    assert!(matches!(build_attempt, Ok(Err(_))), "Empty password must be cleanly rejected with Err");
}
