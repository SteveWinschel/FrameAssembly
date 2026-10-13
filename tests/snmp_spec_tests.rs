//! Comprehensive integration tests for SNMPv1/v2c/v3 specifications,
//! RFC 3416 VarBind ordering, RFC 3414 DES-CBC cryptography,
//! RFC 3826 AES-128-CFB cryptography, and SMI VarBind types.

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

type DesCbcDec = cbc::Decryptor<Des>;
type Aes128CfbDec = cfb_mode::Decryptor<Aes128>;

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
            // Ciphertext length must be multiple of 8 for DES
            assert_eq!(ciphertext.len() % 8, 0);

            // Reconstruct decryption key and IV according to RFC 3414
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

            // Decode ScopedPdu
            let scoped_pdu: ScopedPdu =
                rasn::ber::decode(&decrypted_buf).expect("Decrypted ScopedPdu decode failed");
            assert_eq!(scoped_pdu.engine_id.as_ref(), engine_id);
        }
        _ => panic!("Expected EncryptedPdu"),
    }
}

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

    // 1. Verify 8-byte salt
    let salt = usm_params.privacy_parameters.as_ref();
    assert_eq!(salt.len(), 8);
    assert_eq!(salt, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    // 2. Verify ScopedData is encrypted and decryptable with RFC 3826 128-bit IV
    match msg.scoped_data {
        ScopedPduData::EncryptedPdu(ciphertext) => {
            let engine_id = &[0x80, 0x00, 0x00, 0x00, 0x01];
            let priv_key = password_to_key_sha1(b"privpassword1", engine_id);
            let aes_key = &priv_key[0..16];

            // 16-byte IV = boots (4) + time (4) + salt (8)
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

    // Statement 1: linkDown generic trap
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

    // Statement 2: enterpriseSpecific trap
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
            // First 2 are sysUpTime.0 and snmpTrapOID.0, next 5 are custom varbinds
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
