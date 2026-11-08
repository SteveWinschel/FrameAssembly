---
trigger: glob
globs: "src/builders/l7/snmp/**/*.rs, src/builders/l7/ldap.rs, src/builders/l7/kerberos.rs, src/reverse/l7/snmp*.rs, src/reverse/l7/ldap.rs, src/reverse/l7/kerberos.rs, src/ast/l7/snmp*.rs, src/parser/l7/snmp*.rs, Cargo.toml, tests/*snmp*.rs"
description: "Rasn, rasn-smi, and rasn-snmp 0.28.15 (and 0.29.0/0.30.0 lockstep) ASN.1 BER/DER encoding, decompilation, SMIv1/SMIv2 rules, SNMPv1/v2c/v3 USM, and RFC 4511 LDAP / RFC 4120 Kerberos wire verification."
---

# ASN.1 & SNMP Architecture & Best Practices (`rasn`, `rasn-smi`, `rasn-snmp`)

Enforce these version-exact ASN.1 and SNMP codec rules across `src/builders/l7/snmp/`, `src/builders/l7/ldap.rs`, `src/builders/l7/kerberos.rs`, `src/reverse/l7/snmp*.rs`, `src/reverse/l7/ldap.rs`, `src/reverse/l7/kerberos.rs`, and ASN.1 verification suites:

## 1. Version Lockstep Guardrail (`0.28.15` Active vs. `0.29.0` / `0.30.0` Upstream)
- **Keep `rasn`, `rasn-smi`, and `rasn-snmp` on Matching Minor Versions**:
  - `Cargo.toml` and `Cargo.lock` currently pin `rasn = "0.28.15"`, `rasn-smi = "0.28.15"`, and `rasn-snmp = "0.28.15"`.
  - **CRITICAL Upgrade Trap**: Upstream `rasn` has a `0.30.0` release while `rasn-snmp` and `rasn-smi` are on `0.29.0` (depending on `rasn ^0.29`). **Never** upgrade `rasn` to `0.30.0` independently of `rasn-smi` and `rasn-snmp`, or Cargo will link two incompatible versions of `rasn::Encode`/`Decode`! Only bump all three together (`0.29.0` across all three, or `0.30.x` once `rasn-snmp 0.30` is published).
- **BER vs. DER, `encode_buf` Reuse & `decode_with_remainder` Decompilation**:
  - Use `rasn::ber` for SNMPv1/v2c/v3 and RFC 4511 LDAPv3 (`rasn::ber::encode_buf(&value, &mut buf)` for buffer reuse); use `rasn::der` for RFC 4120 Kerberos v5.
  - In PCAP-to-`.fasm` decompilation (`src/reverse/`) and QA round-trip tests, always decode with `rasn::ber::decode_with_remainder::<T>(wire)` (or `rasn::der::decode_with_remainder::<T>(wire)`) to inspect or assert `remainder.is_empty()`.

## 2. OID Validation, Zero-Heap Primitives & Upstream Quirks (`rasn 0.28.15`)
- **Mandatory 2-Arc & Root-Arc Guard in `parse_oid`**:
  - In `rasn 0.28.15`, `ObjectIdentifier::new(vec![1])` returns `Some(...)` and only fails later inside `rasn::ber::encode` (`InvalidObjectIdentifier`). Always strip leading dots (`.trim_start_matches('.')`), enforce `oid_vec.len() >= 2`, and validate ITU-T X.660 root arcs (`arc0 <= 2`, and `arc1 < 40` when `arc0 < 2`) before calling `ObjectIdentifier::new`.
- **Zero-Heap Primitives**:
  - `rasn::types::Integer` uses a stack `Primitive(isize)` representation for all `i32`/`u32`/`i64` (64-bit) values—construct directly via `Integer::from(val)`.
  - Prefer `ObjectIdentifier::from(Oid::const_new(&[...]))` for compile-time OIDs and `OctetString::from_static(b"public")` for static byte slices.
- **Known `0.28.15` Quirks**: Never use `rasn_smi::v2::ExtUtcTime` in decoders (upstream `len != 11 || len != 13` tautology bug); never derive `Decode` on `u128` (use `Integer`); avoid `FixedBitString<N>` (`8 * N` stack byte layout; use `BitString`).

## 3. SMIv1 vs. SMIv2 & SNMPv1/v2c/v3 Wire Rules
- **SMIv1 (`rasn_smi::v1`) vs. SMIv2 (`rasn_smi::v2`) Asymmetries**:
  - **NULL**: `v1::ObjectSyntax::Simple(v1::SimpleSyntax::Empty)` vs. `v2::VarBindValue::Unspecified` (`0x05 0x00`).
  - **Integer / OID / Gauge / IPv4**: `v1` uses `SimpleSyntax::{Number, Object}`, `ApplicationSyntax::Gauge`, and wraps `IpAddress` in `NetworkAddress::Internet(...)`; `v2` uses `SimpleSyntax::{Integer, ObjectId}`, `ApplicationSyntax::Unsigned`, and passes `v1::IpAddress` directly.
  - **PDU Fields**: `v1::Pdu` uses `Integer` for `request_id`/`error_status`/`error_index`; `v2::Pdu` uses `request_id: i32`, `error_status: u32`, `error_index: u32`.
  - **SNMPv1 Rejections & IPv6 Fallback**: Reject `Counter64` (`0x46`), `GETBULK`, and `INFORM` in `SNMP1`. Auto-map `1.3.6.1.6.3.1.1.5.1`..=`.6` to `generic_trap` `0..=5` (`specific_trap = 0`), default IPv6 `agent-addr` to `0.0.0.0` (RFC 3584 §3.2), and encode IPv6 `IPVAL` varbinds as 16-byte `OctetString` (RFC 4001).
- **Mandatory SNMPv2c/v3 Notification Prepending (Exact `snmpTrapOID.0`!)**:
  - Every `SNMP2` or `SNMP3` `Trap` (`0xa7`) or `InformRequest` (`0xa6`) MUST prepend in exact order:
    1. Index 0: `sysUpTime.0` (`1.3.6.1.2.1.1.3.0`) -> `TimeTicks`.
    2. Index 1: `snmpTrapOID.0` (**`1.3.6.1.6.3.1.1.4.1.0`**, RFC 3418—**never** `.4.2.0`!) -> `ObjectId(trap_oid)` (defaulting `trap_oid` to `1.3.6.1.6.3.1.1.5.3` `linkDown`).
  - Non-notification PDUs (`Get`, `GetNext`, `GetBulk`, `Set`, `Response`) MUST NOT prepend these two bindings.
- **SNMPv3 USM**: Reject `noAuthPriv` (`0x02`) and empty passwords; set `reportableFlag` (`0x04`) on confirmed PDUs (`Get`, `GetNext`, `GetBulk`, `Set`, `Inform`); pre-fill `authentication_parameters` with `vec![0u8; auth_len]` (`12`/`24`/`32`/`48`) before computing the outer `Message` HMAC.

## 4. RFC 4511 LDAPv3 BER & RFC 4120 Kerberos v5 DER Wire Verification
- **`src/builders/l7/ldap.rs`**: Encodes full RFC 4511 `LDAPMessage` (`0x30`) across all 6 operations (`BindRequest` `0x60`, `BindResponse` `0x61`, `UnbindRequest` `0x42`, 8-field `SearchRequest` `0x63` with `[7] Present` filter `0x87`, `SearchResultEntry` `0x64`, `SearchResultDone` `0x65`). Verify wire output against `#[derive(AsnType, Decode, Encode)]` `LdapMessage` schemas via `rasn::ber::decode_with_remainder`.
- **`src/builders/l7/kerberos.rs`**: Encodes full RFC 4120 explicit-tagged DER structures across `AS-REQ` (`0x6A`), `AS-REP` (`0x6B`), `TGS-REQ` (`0x6C`), `TGS-REP` (`0x6D`), and `KRB-ERROR` (`0x7E`), including `[7] till` and `[8] nonce` in `KDC-REQ-BODY`. Verify wire output via `rasn::der::decode_with_remainder`.