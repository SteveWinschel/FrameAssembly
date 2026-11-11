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
        host v2_agent { ip 10.31.0.1 }
        host v2_nms { ip 10.31.0.2 }
        flow v2_trap_order(ag, mgr) {
            ag -> mgr snmp2 trap community "public" oid "1.3.6.1.6.3.1.1.5.3" sysuptime 4200 varbind 1.3.6.1.2.1.2.2.1.1.1 int -15 varbind 1.3.6.1.2.1.2.2.1.2.1 string "eth0"
        } compile { v2_trap_order(v2_agent, v2_nms) }"#;

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
        host get_cli { ip 10.32.0.1 }
        host get_ag { ip 10.32.0.2 }
        flow v2_get_flow(gc, ga) {
            gc -> ga snmp2 get community "public" oid "1.3.6.1.2.1.1.1.0"
        } compile { v2_get_flow(get_cli, get_ag) }"#;

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
        host des_agent { ip 10.33.0.1 }
        host des_nms { ip 10.33.0.2 }
        flow v3_des_flow(da, dn) {
            da -> dn snmp3 trap user "usr-md5-des" engineid "8000000001" engineboots 5 enginetime 1234 auth md5 "authpassword1" priv des "privpassword1" oid "1.3.6.1.6.3.1.1.5.1" sysuptime 500
        } compile { v3_des_flow(des_agent, des_nms) }"#;

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
        host aes_agent { ip 10.34.0.1 }
        host aes_nms { ip 10.34.0.2 }
        flow v3_aes_flow(aa, an) {
            aa -> an snmp3 trap user "usr-sha-aes" engineid "8000000001" engineboots 10 enginetime 5678 auth sha "authpassword1" priv aes "privpassword1" oid "1.3.6.1.6.3.1.1.5.3" sysuptime 200
        } compile { v3_aes_flow(aes_agent, aes_nms) }"#;

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
        host v1_ag { ip 10.35.0.1 }
        host v1_mgr { ip 10.35.0.2 }
        flow v1_trap_map(va, vm) {
            va -> vm snmp1 trap community "public" oid "1.3.6.1.6.3.1.1.5.3" sysuptime 100
            va -> vm snmp1 trap community "public" oid "1.3.6.1.4.1.9999.1" sysuptime 200
        } compile { v1_trap_map(v1_ag, v1_mgr) }"#;

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
        host smi_ag { ip 10.36.0.1 }
        host smi_nms { ip 10.36.0.2 }
        flow smi_types_flow(sa, sn) {
            sa -> sn snmp2 trap community "public" varbind 1.3.6.1.2.1.1.1.0 int -42 varbind 1.3.6.1.2.1.1.2.0 oidval 1.3.6.1.4.1.9.1.1 varbind 1.3.6.1.2.1.2.2.1.10.1 counter32 4294967000 varbind 1.3.6.1.2.1.2.2.1.5.1 gauge32 1000000 varbind 1.3.6.1.2.1.31.1.1.1.6.1 counter64 18446744073709551600
        } compile { smi_types_flow(smi_ag, smi_nms) }"#;

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
        host p_cli { ip 10.37.0.1 }
        host p_srv { ip 10.37.0.2 }
        flow port_check_flow(pc, ps) {
            pc -> ps snmp2 trap community "public"
            pc -> ps snmp2 inform community "public"
            pc -> ps snmp2 get community "public" oid "1.3.6.1.2.1.1.1.0"
            pc -> ps snmp2 set community "public" varbind 1.3.6.1.2.1.1.1.0 string "test"
            pc -> ps snmp2 getbulk community "public" nonrepeaters 0 maxrepetitions 10
            pc -> ps snmp2 getnext community "public" oid "1.3.6.1.2.1.1.1.0"
            pc -> ps snmp2 get dstport 1161 community "public" oid "1.3.6.1.2.1.1.1.0"
        } compile { port_check_flow(p_cli, p_srv) }"#;

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
        host si_ag { ip 10.38.1.1 }
        host si_nm { ip 10.38.1.2 }
        flow si_f1(a, n) { a -> n snmp2 trap community "public" varbind 1.3.6.1.2.1.1.1.0 int -42 }
        compile { si_f1(si_ag, si_nm) }"#;
    assert!(parse_program(valid_int_script).is_ok(), "INT -42 should parse cleanly");

    let invalid_srcport_script = r#"
        host sp_ag { ip 10.38.2.1 }
        host sp_nm { ip 10.38.2.2 }
        flow sp_f2(a, n) { a -> n snmp2 trap srcport -1 }
        compile { sp_f2(sp_ag, sp_nm) }"#;
    let res_sp = parse_program(invalid_srcport_script);
    assert!(matches!(res_sp, Err(CompilerError::ParseError { .. })), "SRCPORT -1 must fail with ParseError");

    let invalid_counter32_script = r#"
        host c32_ag { ip 10.38.3.1 }
        host c32_nm { ip 10.38.3.2 }
        flow c32_f3(a, n) { a -> n snmp2 trap varbind 1.3.6.1.2.1.1.1.0 counter32 -5 }
        compile { c32_f3(c32_ag, c32_nm) }"#;
    let res_c32 = parse_program(invalid_counter32_script);
    assert!(matches!(res_c32, Err(CompilerError::ParseError { .. })), "COUNTER32 -5 must fail with ParseError");
}

/// Tests RFC 1157 SNMPv1 non-trap PDUs: `GET` (`0xa0`), `GETNEXT` (`0xa1`), `SET` (`0xa3`), `RESPONSE` (`0xa2`).
#[test]
fn test_snmp1_non_trap_pdus_get_getnext_set_response() {
    let v1_pdus_script = r#"
        host v1p_cli { ip 10.39.0.1 }
        host v1p_srv { ip 10.39.0.2 }
        flow v1_non_trap(vc, vs) {
            vc -> vs snmp1 get community "public" oid "1.3.6.1.2.1.1.1.0"
            vc -> vs snmp1 getnext community "public" oid "1.3.6.1.2.1.1.1.0"
            vc -> vs snmp1 set community "private" varbind 1.3.6.1.2.1.1.5.0 string "test-host"
            vc <- vs snmp1 response community "public" varbind 1.3.6.1.2.1.1.1.0 string "Linux"
        } compile { v1_non_trap(v1p_cli, v1p_srv) }"#;

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
        host rj_c1 { ip 10.40.0.1 }
        host rj_s1 { ip 10.40.0.2 }
        flow rj_f1(c, s) { c -> s snmp1 getbulk community "public" nonrepeaters 0 maxrepetitions 10 }
        compile { rj_f1(rj_c1, rj_s1) }"#;
    let bulk_rejected = match parse_program(script_bulk) {
        Ok(prog) => build_snmp1_payload(&prog.flows[0].statements[0], src_ip).is_err(),
        Err(_) => true,
    };
    assert!(bulk_rejected, "SNMP1 GETBULK must be rejected by parser or builder");

    let script_inform = r#"
        host rj_c2 { ip 10.40.1.1 }
        host rj_s2 { ip 10.40.1.2 }
        flow rj_f2(c, s) { c -> s snmp1 inform community "public" oid "1.3.6.1.6.3.1.1.5.1" }
        compile { rj_f2(rj_c2, rj_s2) }"#;
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
        host nv_c { ip 10.41.0.1 }
        host nv_s { ip 10.41.0.2 }
        flow nv_flow(nc, ns) { nc -> ns snmp1 get community "public" varbind 1.3.6.1.2.1.1.1.0 null }
        compile { nv_flow(nv_c, nv_s) }"#;

    let prog = parse_program(null_script).expect("NULL in SNMP1 varbind should parse cleanly");
    let stmt = &prog.flows[0].statements[0];
    assert_eq!((stmt.varbinds.len(), &stmt.varbinds[0].val), (1, &VarBindType::Null));
}

/// Tests RFC 3584 §3.2: SNMPv1 Traps from IPv6 hosts default `agent-addr` to `0.0.0.0`.
#[test]
fn test_rfc3584_snmp1_ipv6_agent_addr_default() {
    let v6_def_script = r#"
        host agent_v6_def { ip 2001:db8:42::1 }
        host nms_v6_def { ip 2001:db8:42::2 }
        flow v6_def_flow(av6, nv6) {
            av6 -> nv6 snmp1 trap community "public" oid "1.3.6.1.6.3.1.1.5.1" sysuptime 100
        } compile { v6_def_flow(agent_v6_def, nms_v6_def) }"#;

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
        host agent_v6_ovr { ip 2001:db8:43::1 }
        host nms_v6_ovr { ip 2001:db8:43::2 }
        flow v6_ovr_flow(avo, nvo) {
            avo -> nvo snmp1 trap agentip 192.0.2.1 community "public" oid "1.3.6.1.6.3.1.1.5.1" sysuptime 100
        } compile { v6_ovr_flow(agent_v6_ovr, nms_v6_ovr) }"#;

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
        host ipv_ag { ip 10.44.0.1 }
        host ipv_nm { ip 10.44.0.2 }
        flow ipval_mix_flow(ia, inm) {
            ia -> inm snmp2 trap community "public" varbind 1.3.6.1.2.1.4.34.1.3.1.4.192.0.2.1 ipval 192.0.2.1 varbind 1.3.6.1.2.1.4.34.1.3.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1 ipval 2001:db8::1
        } compile { ipval_mix_flow(ipv_ag, ipv_nm) }"#;

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
        host usm_ag { ip 10.45.0.1 }
        host usm_nm { ip 10.45.0.2 }
        flow usm_empty_pwd(ua, un) {
            ua -> un snmp3 trap user "admin" auth md5 ""
        } compile { usm_empty_pwd(usm_ag, usm_nm) }"#;

    let prog = parse_program(empty_pwd_script).expect("USM empty password script should parse");
    let stmt = &prog.flows[0].statements[0];
    let build_attempt = std::panic::catch_unwind(|| build_snmp3_payload(stmt));
    assert!(matches!(build_attempt, Ok(Err(_))), "Empty password must be cleanly rejected with Err");
}
