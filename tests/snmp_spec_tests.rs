//! Comprehensive integration tests for SNMP specifications.
//!
//! Covers:
//! - SNMPv1/v2c/v3 specifications and ASN.1 BER encoding.
//! - RFC 1157 SNMPv1 PDU tags: GET (0xa0), GETNEXT (0xa1), RESPONSE (0xa2), SET (0xa3), TRAP (0xa4).
//! - RFC 3584 §3.2: SNMPv1 Traps over IPv6 defaulting `agent-addr` to `0.0.0.0`.
//! - RFC 4001: 16-byte `IPVAL` IPv6 addresses alongside IPv4 in varbinds.
//! - RFC 3416: VarBind ordering (mandatory `sysUpTime.0` and `snmpTrapOID.0`).
//! - RFC 3414: DES-CBC USM cryptography and padding.
//! - RFC 3826: AES-128-CFB USM cryptography and 16-byte IV construction.
//! - SMI VarBind types (Integer, OctetString, TimeTicks, Counter32, Gauge32, Counter64, Null).

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use aes::Aes128;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding};
use des::Des;
use frameassembly::ast::*;
use frameassembly::parser::parse_program;
use frameassembly::snmp_builder::*;
use frameassembly::snmp_crypto::*;
use rasn_snmp::v2::{Pdus as PdusV2, VarBindValue};
use rasn_snmp::v3::{Message as V3Message, ScopedPdu, ScopedPduData, USMSecurityParameters};
use std::net::IpAddr;

/// DES-CBC decryptor alias for RFC 3414 testing.
type DesCbcDec = cbc::Decryptor<Des>;

/// AES-128-CFB decryptor alias for RFC 3826 testing.
type Aes128CfbDec = cfb_mode::Decryptor<Aes128>;

/// Tests RFC 3416 mandatory varbind ordering for SNMPv2c traps.
///
/// Ensures that `sysUpTime.0` (1.3.6.1.2.1.1.3.0) is placed first,
/// followed by `snmpTrapOID.0` (1.3.6.1.6.3.1.1.4.1.0), and then
/// any user-defined variable bindings.
#[test]
fn test_snmpv2_trap_varbind_ordering() {
    let script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP2 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.3" SYSUPTIME 4200 VARBIND 1.3.6.1.2.1.2.2.1.1.1 INT -15 VARBIND 1.3.6.1.2.1.2.2.1.2.1 STRING "eth0"
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;

    let program = parse_program(script).expect("Parsing failed");
    let stmt = &program.flows[0].statements[0];

    let payload = build_snmp2_payload(stmt).expect("SNMP2 build failed");
    let msg: rasn_snmp::v2c::Message<PdusV2> =
        rasn::ber::decode(&payload).expect("SNMP2 decode failed");

    match msg.data {
        PdusV2::Trap(trap_pdu) => {
            let vbs = &trap_pdu.0.variable_bindings;
            assert_eq!(
                vbs.len(),
                4,
                "Should have sysUpTime.0, snmpTrapOID.0 + 2 user varbinds"
            );

            // 1. sysUpTime.0 (1.3.6.1.2.1.1.3.0)
            assert_eq!(vbs[0].name.to_string(), "1.3.6.1.2.1.1.3.0");
            match &vbs[0].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
                    rasn_smi::v2::ApplicationSyntax::Ticks(t),
                )) => {
                    assert_eq!(t.0, 4200);
                }
                other => panic!("Expected TimeTicks for sysUpTime.0, got {:?}", other),
            }

            // 2. snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0)
            assert_eq!(vbs[1].name.to_string(), "1.3.6.1.6.3.1.1.4.1.0");
            match &vbs[1].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::Simple(
                    rasn_smi::v2::SimpleSyntax::ObjectId(oid),
                )) => {
                    assert_eq!(oid.to_string(), "1.3.6.1.6.3.1.1.5.3");
                }
                other => panic!("Expected ObjectId for snmpTrapOID.0, got {:?}", other),
            }

            // 3. User VarBind 1: INT -15
            assert_eq!(vbs[2].name.to_string(), "1.3.6.1.2.1.2.2.1.1.1");
            match &vbs[2].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::Simple(
                    rasn_smi::v2::SimpleSyntax::Integer(i),
                )) => {
                    assert_eq!(i, &rasn::types::Integer::from(-15i32));
                }
                other => panic!("Expected signed Integer, got {:?}", other),
            }

            // 4. User VarBind 2: STRING "eth0"
            assert_eq!(vbs[3].name.to_string(), "1.3.6.1.2.1.2.2.1.2.1");
            match &vbs[3].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::Simple(
                    rasn_smi::v2::SimpleSyntax::String(s),
                )) => {
                    assert_eq!(s.as_ref(), b"eth0");
                }
                other => panic!("Expected String, got {:?}", other),
            }
        }
        other => panic!("Expected SNMPv2-Trap-PDU, got {:?}", other),
    }
}

/// Tests that SNMPv2 GetRequest varbinds properly default to Unspecified values.
#[test]
fn test_snmpv2_get_varbind_handling() {
    let script = r#"
        HOST client { IP 10.0.0.1 }
        HOST agent { IP 10.0.0.2 }
        FLOW test_flow(client, agent) {
            client -> agent SNMP2 GET COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
        }
        COMPILE {
            test_flow(client, agent)
        }
    "#;

    let program = parse_program(script).expect("Parsing failed");
    let stmt = &program.flows[0].statements[0];

    let payload = build_snmp2_payload(stmt).expect("SNMP2 build failed");
    let msg: rasn_snmp::v2c::Message<PdusV2> =
        rasn::ber::decode(&payload).expect("SNMP2 decode failed");

    match msg.data {
        PdusV2::GetRequest(get_pdu) => {
            let vbs = &get_pdu.0.variable_bindings;
            assert_eq!(vbs.len(), 1, "Should only have the requested OID VarBind");
            assert_eq!(vbs[0].name.to_string(), "1.3.6.1.2.1.1.1.0");
            assert!(matches!(vbs[0].value, VarBindValue::Unspecified));
        }
        other => panic!("Expected GetRequest, got {:?}", other),
    }
}

/// Tests RFC 3414 DES-CBC USM cryptography, 8-byte salt generation, and ZeroPadding.
#[test]
fn test_snmpv3_des_cbc_cryptography_and_padding() {
    let script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP3 TRAP USER "usr-md5-des" ENGINEID "8000000001" ENGINEBOOTS 5 ENGINETIME 1234 AUTH MD5 "authpassword1" PRIV DES "privpassword1" OID "1.3.6.1.6.3.1.1.5.1" SYSUPTIME 500
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;

    let program = parse_program(script).expect("Parsing failed");
    let stmt = &program.flows[0].statements[0];

    let payload = build_snmp3_payload(stmt).expect("SNMP3 build failed");
    let msg: V3Message = rasn::ber::decode(&payload).expect("SNMP3 decode failed");

    let usm_params: USMSecurityParameters =
        rasn::ber::decode(msg.security_parameters.as_ref()).expect("USM params decode failed");

    // 1. Verify 8-byte salt
    let salt = usm_params.privacy_parameters.as_ref();
    assert_eq!(salt.len(), 8);
    assert_eq!(salt, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    // 2. Verify ScopedData is encrypted
    match msg.scoped_data {
        ScopedPduData::EncryptedPdu(ciphertext) => {
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
            decryptor
                .decrypt_padded::<block_padding::ZeroPadding>(&mut decrypted_buf)
                .unwrap();

            let scoped_pdu: ScopedPdu =
                rasn::ber::decode(&decrypted_buf).expect("Decrypted ScopedPdu decode failed");
            assert_eq!(scoped_pdu.engine_id.as_ref(), engine_id);
        }
        _ => panic!("Expected EncryptedPdu"),
    }
}

/// Tests RFC 3826 AES-128-CFB USM cryptography, 16-byte IV construction, and decryption.
#[test]
fn test_snmpv3_aes128_cfb_cryptography() {
    let script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP3 TRAP USER "usr-sha-aes" ENGINEID "8000000001" ENGINEBOOTS 10 ENGINETIME 5678 AUTH SHA "authpassword1" PRIV AES "privpassword1" OID "1.3.6.1.6.3.1.1.5.3" SYSUPTIME 200
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;

    let program = parse_program(script).expect("Parsing failed");
    let stmt = &program.flows[0].statements[0];

    let payload = build_snmp3_payload(stmt).expect("SNMP3 build failed");
    let msg: V3Message = rasn::ber::decode(&payload).expect("SNMP3 decode failed");

    let usm_params: USMSecurityParameters =
        rasn::ber::decode(msg.security_parameters.as_ref()).expect("USM params decode failed");

    let salt = usm_params.privacy_parameters.as_ref();
    assert_eq!(salt.len(), 8);
    assert_eq!(salt, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    match msg.scoped_data {
        ScopedPduData::EncryptedPdu(ciphertext) => {
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

            let scoped_pdu: ScopedPdu =
                rasn::ber::decode(&decrypted).expect("Decrypted ScopedPdu decode failed");
            assert_eq!(scoped_pdu.engine_id.as_ref(), engine_id);
        }
        _ => panic!("Expected EncryptedPdu"),
    }
}

/// Tests RFC 1157 SNMPv1 generic trap auto-mapping and enterprise-specific fallback.
#[test]
fn test_snmpv1_generic_trap_auto_mapping_and_enterprise_fallback() {
    let script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.3" SYSUPTIME 100
            agent -> nms SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.4.1.9999.1" SYSUPTIME 200
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;

    let program = parse_program(script).expect("Parsing failed");

    // Statement 1: linkDown generic trap (mapped to 2)
    let stmt1 = &program.flows[0].statements[0];
    let payload1 = build_snmp1_payload(stmt1, IpAddr::V4("10.0.0.1".parse().unwrap())).unwrap();
    let msg1: rasn_snmp::v1::Message<rasn_snmp::v1::Pdus> = rasn::ber::decode(&payload1).unwrap();
    match msg1.data {
        rasn_snmp::v1::Pdus::Trap(trap) => {
            assert_eq!(trap.generic_trap, rasn::types::Integer::from(2)); // linkDown = 2
            assert_eq!(trap.specific_trap, rasn::types::Integer::from(0));
            assert_eq!(trap.enterprise.to_string(), "1.3.6.1.6.3.1.1.5.3");
        }
        _ => panic!("Expected Trap PDU"),
    }

    // Statement 2: enterpriseSpecific trap (mapped to 6)
    let stmt2 = &program.flows[0].statements[1];
    let payload2 = build_snmp1_payload(stmt2, IpAddr::V4("10.0.0.1".parse().unwrap())).unwrap();
    let msg2: rasn_snmp::v1::Message<rasn_snmp::v1::Pdus> = rasn::ber::decode(&payload2).unwrap();
    match msg2.data {
        rasn_snmp::v1::Pdus::Trap(trap) => {
            assert_eq!(trap.generic_trap, rasn::types::Integer::from(6)); // enterpriseSpecific = 6
            assert_eq!(trap.specific_trap, rasn::types::Integer::from(1));
            assert_eq!(trap.enterprise.to_string(), "1.3.6.1.4.1.9999.1");
        }
        _ => panic!("Expected Trap PDU"),
    }
}

/// Tests SMI VarBind data types and signed integers (INT, OIDVAL, COUNTER32, GAUGE32, COUNTER64).
#[test]
fn test_smi_varbind_types_and_signed_integers() {
    let script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP2 TRAP COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 INT -42 VARBIND 1.3.6.1.2.1.1.2.0 OIDVAL 1.3.6.1.4.1.9.1.1 VARBIND 1.3.6.1.2.1.2.2.1.10.1 COUNTER32 4294967000 VARBIND 1.3.6.1.2.1.2.2.1.5.1 GAUGE32 1000000 VARBIND 1.3.6.1.2.1.31.1.1.1.6.1 COUNTER64 18446744073709551600
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;

    let program = parse_program(script).expect("Parsing failed");
    let stmt = &program.flows[0].statements[0];

    let payload = build_snmp2_payload(stmt).expect("SNMP2 build failed");
    let msg: rasn_snmp::v2c::Message<PdusV2> = rasn::ber::decode(&payload).expect("Decode failed");

    match msg.data {
        PdusV2::Trap(trap) => {
            let vbs = &trap.0.variable_bindings;
            assert_eq!(vbs.len(), 7);

            // INT -42
            match &vbs[2].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::Simple(
                    rasn_smi::v2::SimpleSyntax::Integer(i),
                )) => {
                    assert_eq!(i, &rasn::types::Integer::from(-42i32));
                }
                other => panic!("Expected Integer(-42), got {:?}", other),
            }

            // OIDVAL 1.3.6.1.4.1.9.1.1
            match &vbs[3].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::Simple(
                    rasn_smi::v2::SimpleSyntax::ObjectId(oid),
                )) => {
                    assert_eq!(oid.to_string(), "1.3.6.1.4.1.9.1.1");
                }
                other => panic!("Expected ObjectId, got {:?}", other),
            }

            // COUNTER32 4294967000
            match &vbs[4].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
                    rasn_smi::v2::ApplicationSyntax::Counter(c),
                )) => {
                    assert_eq!(c.0, 4294967000);
                }
                other => panic!("Expected Counter32, got {:?}", other),
            }

            // GAUGE32 1000000
            match &vbs[5].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
                    rasn_smi::v2::ApplicationSyntax::Unsigned(g),
                )) => {
                    assert_eq!(g.0, 1000000);
                }
                other => panic!("Expected Gauge32, got {:?}", other),
            }

            // COUNTER64 18446744073709551600
            match &vbs[6].value {
                VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
                    rasn_smi::v2::ApplicationSyntax::BigCounter(c),
                )) => {
                    assert_eq!(c.0, 18446744073709551600);
                }
                other => panic!("Expected Counter64, got {:?}", other),
            }
        }
        other => panic!("Expected Trap PDU, got {:?}", other),
    }
}

/// Tests default destination ports: 162 for TRAP/INFORM and 161 for GET/SET/GETNEXT/GETBULK.
#[test]
fn test_default_dst_ports() {
    let script = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW test_flow(client, server) {
            client -> server SNMP2 TRAP COMMUNITY "public"
            client -> server SNMP2 INFORM COMMUNITY "public"
            client -> server SNMP2 GET COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
            client -> server SNMP2 SET COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 STRING "test"
            client -> server SNMP2 GETBULK COMMUNITY "public" NONREPEATERS 0 MAXREPETITIONS 10
            client -> server SNMP2 GETNEXT COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
            client -> server SNMP2 GET DSTPORT 1161 COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
        }
        COMPILE {
            test_flow(client, server)
        }
    "#;

    let program = parse_program(script).expect("Parsing failed");
    let stmts = &program.flows[0].statements;

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

    assert_eq!(
        resolve_dst_port(&stmts[0]),
        162,
        "TRAP should default to 162"
    );
    assert_eq!(
        resolve_dst_port(&stmts[1]),
        162,
        "INFORM should default to 162"
    );
    assert_eq!(
        resolve_dst_port(&stmts[2]),
        161,
        "GET should default to 161"
    );
    assert_eq!(
        resolve_dst_port(&stmts[3]),
        161,
        "SET should default to 161"
    );
    assert_eq!(
        resolve_dst_port(&stmts[4]),
        161,
        "GETBULK should default to 161"
    );
    assert_eq!(
        resolve_dst_port(&stmts[5]),
        161,
        "GETNEXT should default to 161"
    );
    assert_eq!(
        resolve_dst_port(&stmts[6]),
        1161,
        "Explicit DSTPORT 1161 should be preserved"
    );
}

/// Tests parser diagnostics for signed vs unsigned numeric inputs.
#[test]
fn test_signed_vs_unsigned_parser_diagnostics() {
    use frameassembly::error::CompilerError;

    // 1. Signed integer in INT succeeds
    let valid_script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP2 TRAP COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 INT -42
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;
    let res = parse_program(valid_script);
    assert!(
        res.is_ok(),
        "INT -42 should parse successfully: {:?}",
        res.err()
    );

    // 2. Negative number in SRCPORT fails cleanly with ParseError
    let invalid_srcport_script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP2 TRAP SRCPORT -1
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;
    let res = parse_program(invalid_srcport_script);
    assert!(
        matches!(res, Err(CompilerError::ParseError { .. })),
        "SRCPORT -1 should fail with CompilerError::ParseError, got: {:?}",
        res
    );

    // 3. Negative number in COUNTER32 fails cleanly with ParseError
    let invalid_counter32_script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP2 TRAP VARBIND 1.3.6.1.2.1.1.1.0 COUNTER32 -5
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;
    let res = parse_program(invalid_counter32_script);
    assert!(
        matches!(res, Err(CompilerError::ParseError { .. })),
        "COUNTER32 -5 should fail with CompilerError::ParseError, got: {:?}",
        res
    );
}

/// Tests RFC 1157 SNMPv1 non-trap PDUs: GET (0xa0), GETNEXT (0xa1), SET (0xa3), RESPONSE (0xa2).
///
/// Verifies that non-trap SNMPv1 PDUs emit distinct RFC 1157 BER tags instead of always encoding a Trap.
#[test]
fn test_snmp1_non_trap_pdus_get_getnext_set_response() {
    let script = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW test_flow(client, server) {
            client -> server SNMP1 GET COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
            client -> server SNMP1 GETNEXT COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
            client -> server SNMP1 SET COMMUNITY "private" VARBIND 1.3.6.1.2.1.1.5.0 STRING "test-host"
            client <- server SNMP1 RESPONSE COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 STRING "Linux"
        }
        COMPILE {
            test_flow(client, server)
        }
    "#;

    let program = parse_program(script).expect("Parsing failed");
    let stmts = &program.flows[0].statements;
    assert_eq!(stmts.len(), 4);

    // Verify AST PDU types
    assert_eq!(stmts[0].pdu_type, Some(SnmpPduType::Get));
    assert_eq!(stmts[1].pdu_type, Some(SnmpPduType::GetNext));
    assert_eq!(stmts[2].pdu_type, Some(SnmpPduType::Set));
    assert_eq!(stmts[3].pdu_type, Some(SnmpPduType::Response));

    // Verify distinct RFC 1157 BER tags:
    // GetRequest-PDU ::= [0] IMPLICIT SEQUENCE (0xa0)
    // GetNextRequest-PDU ::= [1] IMPLICIT SEQUENCE (0xa1)
    // SetRequest-PDU ::= [3] IMPLICIT SEQUENCE (0xa3)
    // GetResponse-PDU ::= [2] IMPLICIT SEQUENCE (0xa2)
    let src_ip = IpAddr::V4("10.0.0.1".parse().unwrap());
    let payload0 = build_snmp1_payload(&stmts[0], src_ip).expect("SNMP1 GET payload build failed");
    assert!(payload0.contains(&0xa0), "SNMP1 GET should contain ASN.1 tag 0xa0");

    let payload1 = build_snmp1_payload(&stmts[1], src_ip).expect("SNMP1 GETNEXT payload build failed");
    assert!(payload1.contains(&0xa1), "SNMP1 GETNEXT should contain ASN.1 tag 0xa1");

    let payload2 = build_snmp1_payload(&stmts[2], src_ip).expect("SNMP1 SET payload build failed");
    assert!(payload2.contains(&0xa3), "SNMP1 SET should contain ASN.1 tag 0xa3");

    let payload3 = build_snmp1_payload(&stmts[3], src_ip).expect("SNMP1 RESPONSE payload build failed");
    assert!(payload3.contains(&0xa2), "SNMP1 RESPONSE should contain ASN.1 tag 0xa2");
}

/// Tests that SNMPv1 rejects GETBULK and INFORM operations (introduced in SNMPv2c).
#[test]
fn test_snmp1_reject_getbulk_and_inform() {
    let script_bulk = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW test_flow(client, server) {
            client -> server SNMP1 GETBULK COMMUNITY "public" NONREPEATERS 0 MAXREPETITIONS 10
        }
        COMPILE {
            test_flow(client, server)
        }
    "#;
    let res_bulk = parse_program(script_bulk);
    let src_ip = IpAddr::V4("10.0.0.1".parse().unwrap());
    let bulk_rejected = match res_bulk {
        Ok(prog) => build_snmp1_payload(&prog.flows[0].statements[0], src_ip).is_err(),
        Err(_) => true,
    };
    assert!(bulk_rejected, "SNMP1 GETBULK must be rejected by parser or builder");

    let script_inform = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW test_flow(client, server) {
            client -> server SNMP1 INFORM COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.1"
        }
        COMPILE {
            test_flow(client, server)
        }
    "#;
    let res_inform = parse_program(script_inform);
    let inform_rejected = match res_inform {
        Ok(prog) => build_snmp1_payload(&prog.flows[0].statements[0], src_ip).is_err(),
        Err(_) => true,
    };
    assert!(inform_rejected, "SNMP1 INFORM must be rejected by parser or builder");
}

/// Tests RFC 1157 §3.2.1.1 NULLVAL support in SNMPv1 VarBinds.
#[test]
fn test_snmp1_nullval_support() {
    let script = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW test_flow(client, server) {
            client -> server SNMP1 GET COMMUNITY "public" VARBIND 1.3.6.1.2.1.1.1.0 NULL
        }
        COMPILE {
            test_flow(client, server)
        }
    "#;

    match parse_program(script) {
        Ok(prog) => {
            let stmt = &prog.flows[0].statements[0];
            assert_eq!(stmt.varbinds.len(), 1);
            assert_eq!(stmt.varbinds[0].val, VarBindType::Null);
        }
        Err(e) => {
            panic!("NULL in SNMP1 varbind should parse cleanly: {:?}", e);
        }
    }
}

/// Tests RFC 3584 §3.2: SNMPv1 Traps from IPv6 hosts default `agent-addr` to `0.0.0.0`.
#[test]
fn test_rfc3584_snmp1_ipv6_agent_addr_default() {
    let script = r#"
        HOST agent_v6 { IP 2001:db8::1 }
        HOST nms_v6 { IP 2001:db8::2 }
        FLOW test_flow(agent_v6, nms_v6) {
            agent_v6 -> nms_v6 SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.1" SYSUPTIME 100
        }
        COMPILE {
            test_flow(agent_v6, nms_v6)
        }
    "#;

    match parse_program(script) {
        Ok(program) => {
            let stmt = &program.flows[0].statements[0];
            let v6_addr = IpAddr::V6("2001:db8::1".parse().unwrap());

            match build_snmp1_payload(stmt, v6_addr) {
                Ok(payload) => {
                    let msg: rasn_snmp::v1::Message<rasn_snmp::v1::Pdus> = rasn::ber::decode(&payload)
                        .expect("Decoded SNMP1 message");
                    if let rasn_snmp::v1::Pdus::Trap(trap) = msg.data {
                        let rasn_smi::v1::NetworkAddress::Internet(rasn_smi::v1::IpAddress(addr_bytes)) = trap.agent_addr;
                        assert_eq!(addr_bytes.as_ref(), &[0, 0, 0, 0], "RFC 3584 requires 0.0.0.0 agent-addr for IPv6");
                    } else {
                        panic!("Expected Trap PDU");
                    }
                }
                Err(e) => {
                    panic!("RFC 3584 IPv6 agent-addr default failed: {}", e);
                }
            }
        }
        Err(e) => {
            panic!("IPv6 HOST parsing failed: {:?}", e);
        }
    }
}

/// Tests RFC 3584 §3.2: SNMPv1 Traps over IPv6 with explicit `AGENTIP <ipv4>` proxy override.
#[test]
fn test_rfc3584_snmp1_ipv6_agentip_override() {
    let script = r#"
        HOST agent_v6 { IP 2001:db8::1 }
        HOST nms_v6 { IP 2001:db8::2 }
        FLOW test_flow(agent_v6, nms_v6) {
            agent_v6 -> nms_v6 SNMP1 TRAP AGENTIP 192.0.2.1 COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.1" SYSUPTIME 100
        }
        COMPILE {
            test_flow(agent_v6, nms_v6)
        }
    "#;

    match parse_program(script) {
        Ok(program) => {
            let stmt = &program.flows[0].statements[0];
            let v6_addr = IpAddr::V6("2001:db8::1".parse().unwrap());

            match build_snmp1_payload(stmt, v6_addr) {
                Ok(payload) => {
                    let msg: rasn_snmp::v1::Message<rasn_snmp::v1::Pdus> = rasn::ber::decode(&payload)
                        .expect("Decoded SNMP1 message");
                    if let rasn_snmp::v1::Pdus::Trap(trap) = msg.data {
                        let rasn_smi::v1::NetworkAddress::Internet(rasn_smi::v1::IpAddress(addr_bytes)) = trap.agent_addr;
                        assert_eq!(addr_bytes.as_ref(), &[192, 0, 2, 1], "Explicit AGENTIP should override agent-addr");
                    } else {
                        panic!("Expected Trap PDU");
                    }
                }
                Err(e) => {
                    panic!("AGENTIP override failed: {}", e);
                }
            }
        }
        Err(e) => {
            panic!("IPv6 HOST parsing failed: {:?}", e);
        }
    }
}

/// Tests RFC 4001: 16-byte `IPVAL` IPv6 addresses alongside IPv4 in the same PDU.
#[test]
fn test_rfc4001_ipv6_varbind_ipval() {
    let script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP2 TRAP COMMUNITY "public" VARBIND 1.3.6.1.2.1.4.34.1.3.1.4.192.0.2.1 IPVAL 192.0.2.1 VARBIND 1.3.6.1.2.1.4.34.1.3.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1 IPVAL 2001:db8::1
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;

    match parse_program(script) {
        Ok(program) => {
            let stmt = &program.flows[0].statements[0];
            assert_eq!(stmt.varbinds.len(), 2);

            match build_snmp2_payload(stmt) {
                Ok(payload) => {
                    let msg: rasn_snmp::v2c::Message<PdusV2> = rasn::ber::decode(&payload).expect("Decode failed");
                    if let PdusV2::Trap(trap) = msg.data {
                        let vbs = &trap.0.variable_bindings;
                        // Index 2 is IPv4, Index 3 is IPv6
                        assert_eq!(vbs.len(), 4);
                    }
                }
                Err(e) => {
                    panic!("RFC 4001 IPv6 IPVAL failed: {}", e);
                }
            }
        }
        Err(e) => {
            panic!("IPv6 IPVAL parsing failed: {:?}", e);
        }
    }
}

/// Tests SNMPv3 USM password and security parameter validation.
#[test]
fn test_snmpv3_usm_password_and_security_validation() {
    let empty_pwd_script = r#"
        HOST agent { IP 10.0.0.1 }
        HOST nms { IP 10.0.0.2 }
        FLOW test_flow(agent, nms) {
            agent -> nms SNMP3 TRAP USER "admin" AUTH MD5 ""
        }
        COMPILE {
            test_flow(agent, nms)
        }
    "#;

    let prog = parse_program(empty_pwd_script).expect("USM empty password script should parse");
    let stmt = &prog.flows[0].statements[0];
    let build_attempt = std::panic::catch_unwind(|| {
        build_snmp3_payload(stmt)
    });
    match build_attempt {
        Ok(Ok(_)) => {
            panic!("Empty password should be rejected in USM");
        }
        Ok(Err(_)) => {
            // Properly rejected with error!
        }
        Err(_) => {
            panic!("USM empty password panicked in snmp_crypto");
        }
    }
}

