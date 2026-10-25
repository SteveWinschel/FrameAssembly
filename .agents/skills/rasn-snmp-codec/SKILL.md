---
name: rasn-snmp-codec
description: Comprehensive architecture guide, API selection matrix, SMIv1/SMIv2 type mapping tables, and production reference patterns for ASN.1 BER/DER encoding, decoding, SMIv1/SMIv2 data modeling, and SNMPv1/SNMPv2c/SNMPv3 USM wire protocol implementation in Rust using rasn, rasn-smi, and rasn-snmp 0.28.15.
---

# ASN.1 & SNMP Codec Stack Engineering Skill (`rasn`, `rasn-smi`, `rasn-snmp` `0.28.15`)

Use this skill when designing, implementing, debugging, or verifying ASN.1 BER/DER codecs, SMIv1/SMIv2 data structures, SNMPv1/v2c/v3 network management protocol builders, or LDAP (RFC 4511) and Kerberos (RFC 4120) ASN.1 wire encoders in Rust using `rasn = "0.28.15"`, `rasn-smi = "0.28.15"`, and `rasn-snmp = "0.28.15"`.

---

## 1. Quick API Selection Matrix

| Management / Codec Goal | Idiomatic `rasn` / `rasn-smi` / `rasn-snmp 0.28.15` API | Avoid (Legacy / Broken / Non-Standard) |
| :--- | :--- | :--- |
| **ASN.1 BER serialization** | `rasn::ber::encode(&value)` or `rasn::ber::encode_buf(&value, &mut buf)` | Manual TLV byte slicing or hand-rolled length packing |
| **ASN.1 BER deserialization** | `rasn::ber::decode::<T>(&bytes)` | Unbounded manual length decoding |
| **Stream / QA remainder decode** | `rasn::ber::decode_with_remainder::<T>(&bytes)` (`(T, &[u8])`) | Allocating intermediate vectors or ignoring trailing unconsumed bytes in TCP/QA streams |
| **Canonical ASN.1 encoding** | `rasn::der::encode(&value)` / `rasn::der::decode_with_remainder::<T>(&bytes)` | Using BER where DER is required (e.g., X.509, RFC 4120 Kerberos) |
| **OID parsing & 1-arc guard** | `oid_str.trim_start_matches('.')` + **check `arcs.len() >= 2`** + `ObjectIdentifier::new(arcs)` | Calling `ObjectIdentifier::new(vec![1])` without `len >= 2` check (succeeds in `new`, then fails in `ber::encode`!) |
| **Compile-time static OIDs** | `ObjectIdentifier::from(Oid::const_new(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))` | `ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap()` (heap-allocates every call) |
| **Zero-heap static `OctetString`** | `OctetString::from_static(b"public")` (wraps `Bytes::from_static`) | `"public".as_bytes().to_vec().into()` on static string literals |
| **Zero-heap `Integer` construction** | `Integer::from(val)` (`IntegerKind::Primitive(isize)` stack path for all `i64`/`u32`) | Converting `i64` to `BigInt` before constructing `rasn::types::Integer` |
| **SMIv1 NULL varbind value** | `smiv1::ObjectSyntax::Simple(smiv1::SimpleSyntax::Empty)` (`0x05 0x00`) | `SimpleSyntax::Number(0.into())` (emits Integer `0x02 0x01 0x00`) |
| **SMIv2 NULL query varbind** | `snmpv2::VarBindValue::Unspecified` (Universal NULL `0x05 0x00`) | Searching for `Empty` in `smiv2::SimpleSyntax` (does not exist) |
| **SMIv1 vs. SMIv2 Integer/OID** | v1: `SimpleSyntax::{Number, Object}`; v2: `SimpleSyntax::{Integer, ObjectId}` | Mixing v1 and v2 variant names across protocol versions |
| **SMIv1 vs. SMIv2 IPv4 Address** | v1: `ApplicationSyntax::Address(NetworkAddress::Internet(IpAddress(octets.into())))`; v2: `ApplicationSyntax::Address(IpAddress(octets.into()))` | Wrapping v2 `IpAddress` in `NetworkAddress::Internet` (type error) |
| **SMIv1 vs. SMIv2 Gauge32** | v1: `ApplicationSyntax::Gauge(Gauge(v))`; v2: `ApplicationSyntax::Unsigned(Gauge(v))` | Using `ApplicationSyntax::Gauge` in SMIv2 (variant is `Unsigned`) |
| **SMIv2 64-bit counter (`0x46`)** | `smiv2::ApplicationSyntax::BigCounter(smiv2::Counter64(val))` (reject in SNMPv1!) | Allowing `Counter64` in SNMPv1 (violates RFC 1157 / RFC 2578) |
| **SNMPv1 vs. SNMPv2 PDU fields** | `v1::Pdu`: `Integer` fields (`u64` constants `0..=5`); `v2::Pdu`: `request_id: i32, error_status: u32, error_index: u32` (`u32` constants `0..=18`); `v2::BulkPdu`: `request_id: i32, non_repeaters: u32, max_repetitions: u32` | Typing `v2::Pdu` `error_status` or `error_index` as `i32` or `Integer` |
| **SNMPv1 PDU context tags** | `v1::Pdus::{GetRequest (0xa0), GetNextRequest (0xa1), GetResponse (0xa2), SetRequest (0xa3), Trap (0xa4)}` | Emitting tag `0xa4` (`Trap`) for non-trap SNMPv1 requests |
| **SNMPv1 generic trap OID mapping** | Auto-map `1.3.6.1.6.3.1.1.5.1`..=`.6` to `generic_trap` `0..=5` (`specific_trap = 0`); else `6` (`specific_trap = 1`) | Hardcoding `generic_trap = 6` for standard `coldStart`/`linkDown` OIDs |
| **SNMPv1 bulk / inform guard** | Reject `GetBulk` and `Inform` under `SNMP1` with diagnostic error | Silently coercing `GETBULK` or `INFORM` into an SNMPv1 `GET` or `TRAP` |
| **SNMPv1 trap from IPv6 host** | Default `agent_addr` to `0.0.0.0` (RFC 3584 §3.2) unless `AGENTIP <ipv4>` set | Truncating 16-byte IPv6 address into 4 bytes or panicking |
| **SNMPv2c/v3 Trap & Inform header** | Prepend Index 0: `sysUpTime.0` (`TimeTicks`), Index 1: `snmpTrapOID.0` (`ObjectId`) | Placing user varbinds ahead of standard notification OIDs (RFC 3416 violation) |
| **Dual-stack IPv6 in varbinds** | 16-byte `OctetString` (`SimpleSyntax::String(v6.octets().to_vec().into())`, RFC 4001) | Coercing 16-byte IPv6 into 4-octet `IpAddress(FixedOctetString<4>)` |
| **SNMPv3 USM parameters** | `rasn::ber::encode(&usm)` or `msg.encode_security_parameters(Codec::Ber, &usm)` / `msg.decode_security_parameters::<USMSecurityParameters>(Codec::Ber)` | Inlining `USMSecurityParameters` SEQUENCE directly into outer `Message` |
| **SNMPv3 USM password validation** | Reject empty `""` auth/priv passwords before RFC 3414 1MB key localization | Calling `password[i % password.len()]` on empty slice (panics with div-by-zero!) |
| **SNMPv3 DES-CBC padding** | Encrypt with `ZeroPadding` (RFC 3414 §8.1.1.2); **decrypt with `NoPadding`** before `rasn::ber::decode` | Decrypting BER `ScopedPdu` with `ZeroPadding` (strips valid trailing `0x00` on 8B-aligned `INT 0` / `NULLVAL`!) |
| **SNMPv3 AES-128-CFB cipher** | Stream mode (0 padding bytes) with 16-byte IV `boots_be[4] \|\| time_be[4] \|\| salt[8]` (RFC 3826) | Adding block padding to CFB stream or reusing DES 8-byte IV logic |
| **SNMPv3 auth MAC calculation** | Zero-fill `authentication_parameters` (`12`/`24`/`32`/`48` `0x00` bytes) before hashing outer `Message` | Hashing outer `Message` with empty `vec![]` instead of `vec![0u8; auth_len]` |
| **SNMPv3 security flags** | `0x00` (`noAuthNoPriv`), `0x01` (`authNoPriv`), `0x03` (`authPriv`), plus `0x04` (`reportableFlag` on confirmed PDUs) | `0x02` (`noAuthPriv` — forbidden by RFC 3412 §6.4) or omitting `0x04` on `GET`/`INFORM` |

---

## 2. SMIv1 vs. SMIv2 Type & PDU Structural Mapping (`rasn-smi` & `rasn-snmp` `0.28.15`)

A frequent source of compile errors when working with `rasn-smi` and `rasn-snmp` is the structural asymmetry between the `v1` and `v2` modules:

| Concept | SNMPv1 / SMIv1 (`rasn_smi::v1`, `rasn_snmp::v1`) | SNMPv2c & SNMPv3 / SMIv2 (`rasn_smi::v2`, `rasn_snmp::v2`) | Wire BER Tag |
| :--- | :--- | :--- | :--- |
| **NULL VarBind** | `v1::ObjectSyntax::Simple(v1::SimpleSyntax::Empty)` | `v2::VarBindValue::Unspecified` | `0x05 0x00` (Universal NULL) |
| **Signed Integer** | `v1::SimpleSyntax::Number(Integer::from(i))` | `v2::SimpleSyntax::Integer(Integer::from(i))` | `0x02` (Universal INTEGER) |
| **Octet String** | `v1::SimpleSyntax::String(OctetString)` | `v2::SimpleSyntax::String(OctetString)` | `0x04` (Universal OCTET STRING) |
| **Object Identifier** | `v1::SimpleSyntax::Object(ObjectIdentifier)` | `v2::SimpleSyntax::ObjectId(ObjectIdentifier)` | `0x06` (Universal OBJECT IDENTIFIER) |
| **IPv4 Address (4B)** | `v1::ApplicationSyntax::Address(v1::NetworkAddress::Internet(v1::IpAddress(octets.into())))` | `v2::ApplicationSyntax::Address(v1::IpAddress(octets.into()))` | `0x40` (Application 0, 4 octets) |
| **Counter32** | `v1::ApplicationSyntax::Counter(v1::Counter(u32))` | `v2::ApplicationSyntax::Counter(v1::Counter(u32))` | `0x41` (Application 1) |
| **Gauge32 / Unsigned32** | `v1::ApplicationSyntax::Gauge(v1::Gauge(u32))` | `v2::ApplicationSyntax::Unsigned(v1::Gauge(u32))` | `0x42` (Application 2) |
| **TimeTicks** | `v1::ApplicationSyntax::Ticks(v1::TimeTicks(u32))` | `v2::ApplicationSyntax::Ticks(v1::TimeTicks(u32))` | `0x43` (Application 3) |
| **Opaque** | `v1::ApplicationSyntax::Arbitrary(v1::Opaque)` | `v2::ApplicationSyntax::Arbitrary(v1::Opaque)` | `0x44` (Application 4) |
| **Counter64** | *Unsupported — MUST reject with error* | `v2::ApplicationSyntax::BigCounter(v2::Counter64(u64))` | `0x46` (Application 6) |
| **PDU Header Fields** | `request_id: Integer`, `error_status: Integer`, `error_index: Integer` (`ERROR_STATUS_*`: `u64` `0..=5`) | `request_id: i32`, `error_status: u32`, `error_index: u32` (`ERROR_STATUS_*`: `u32` `0..=18`) | `0x02` (Universal INTEGER) |
| **BulkPDU Fields** | *Unsupported — MUST reject with error* | `request_id: i32`, `non_repeaters: u32`, `max_repetitions: u32`, `variable_bindings: VarBindList` | `0xa5` (`GetBulkRequest`) |

---

## 3. Zero-Heap & Buffer-Reuse `rasn 0.28.15` Internals & Upstream Quirks

### 3.1 Zero-Heap Primitives & Buffer Reuse
1. **Hybrid Stack/Heap `rasn::types::Integer`**:
   - Internally, `rasn::types::Integer` is a two-variant enum (`IntegerKind::Primitive(isize)` vs. `IntegerKind::Big(BigInt)`). Every integer that fits in `isize` (`i8`, `i16`, `i32`, `u8`, `u16`, `u32`, and `i64` on 64-bit hosts) uses `IntegerKind::Primitive(isize)` with **zero heap allocation**. Heap allocation via `BigInt` only occurs when a value overflows `isize` (e.g., `u64` values $> \text{isize::MAX}$).
2. **Zero-Heap Static `OctetString` & `ObjectIdentifier`**:
   - Use `OctetString::from_static(b"public")` (which calls `bytes::Bytes::from_static`) instead of `"public".as_bytes().to_vec().into()` whenever constructing an `OctetString` from a static slice.
   - Use `ObjectIdentifier::from(rasn::types::Oid::const_new(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))` for well-known static OIDs (`sysUpTime.0`, `snmpTrapOID.0`) instead of `ObjectIdentifier::new(vec![...])`.
3. **1-Arc OID Edge Case in `ObjectIdentifier::new`**:
   - `ObjectIdentifier::new(vec![1])` returns `Some(...)` in `rasn 0.28.15` because `Oid::new` only validates `arc0 <= 2` and `arc1 < 40` when `slice.len() >= 2`. However, encoding that 1-arc OID subsequently fails inside `rasn::ber::encode` (`BerEncodeErrorKind::InvalidObjectIdentifier`) because ITU-T X.690 §8.19 packs the first two arcs as `(arc0 * 40) + arc1`. Always check `if oid_vec.len() < 2 { return Err(...); }` in `parse_oid` before calling `ObjectIdentifier::new`.
4. **Pre-Allocated Encoding & Remainder Decoding**:
   - Use `rasn::ber::encode_buf(&value, &mut buffer)` to encode directly into a reusable `Vec<u8>`.
   - Use `rasn::ber::decode_with_remainder::<T>(slice)` to decode a PDU and inspect the unconsumed remainder slice `&[u8]` (essential for TCP stream framing in LDAP/Kerberos and asserting `remainder.is_empty()` in unit tests).
   - Use `v3::Message::encode_security_parameters(rasn::Codec::Ber, &usm)` and `msg.decode_security_parameters::<USMSecurityParameters>(rasn::Codec::Ber)` as ergonomic helpers around two-stage USM BER encoding/decoding.

### 3.2 Known `rasn 0.28.15` Upstream Quirks
- **`rasn_smi::v2::ExtUtcTime` Decoder Bug**: `ExtUtcTime` has a broken length check (`if len != 11 || len != 13` — a boolean tautology that is always `true`), causing `rasn::ber::decode::<ExtUtcTime>` to fail on every input. Decode UTC timestamps as `OctetString` instead.
- **`u128` Lacks `Decode`**: In `rasn 0.28.15`, `u128` implements `AsnType` and `Encode`, but does **not** implement `Decode`. Use `rasn::types::Integer` when decoding integers larger than 64 bits.
- **`FixedBitString<N>` Memory Layout**: `FixedBitString<N>` wraps `[u8; N]` (`8 * N` bits of memory) while constraining the ASN.1 bit length to `N` bits. Prefer `rasn::types::BitString` or `FixedOctetString<4>`.

---

## 4. Complete `#[derive(AsnType, Encode, Decode)]` Attribute Matrix (`rasn-derive 0.28.15`)

When defining custom ASN.1 protocols (such as RFC 4511 LDAPv3 or RFC 4120 Kerberos v5), combine `#[derive(AsnType, Encode, Decode)]` with these `#[rasn(...)]` attributes:

| Attribute | Target | ASN.1 Semantics & Wire Effect |
| :--- | :--- | :--- |
| **`#[rasn(delegate)]`** | Newtype struct `struct S(pub T);` | Transparently delegates encoding/decoding to inner type `T` (or retags `T` when paired with `#[rasn(tag(...))]`). |
| **`#[rasn(choice)]`** | `enum` | Encodes each variant directly using its own distinct tag without an outer `SEQUENCE` wrapper. |
| **`#[rasn(enumerated)]`** | Fieldless `enum` | Encodes discriminant values using Universal `ENUMERATED` tag (`0x0A`). |
| **`#[rasn(tag(class, N))]`** | Struct, variant, or field | **Implicit** tag override where `class` is `context` (`0x80`), `application` (`0x40`), `universal` (`0x00`), or `private` (`0xC0`). Replaces the inner type's tag. |
| **`#[rasn(tag(explicit(class, N)))]`** | Struct, variant, or field | **Explicit** constructed tag wrapper (`0xA0 \| N` for `context`, `0x60 \| N` for `application`) enclosing the inner type's complete TLV (required by RFC 4120 Kerberos v5). |
| **`#[rasn(extension_addition)]`** | Struct field or enum variant | Marks fields/variants after an ASN.1 `...` extension marker. |
| **`#[rasn(default)]` / `#[rasn(default = "fn")]`** | Struct field | Uses `Default::default()` or `fn()` when an optional-with-default field is absent during decoding, and omits default values in DER encoding. |
| **`#[rasn(size("MIN..=MAX"))]`** | String / `SequenceOf` field | Attaches an ASN.1 `SIZE (MIN..MAX)` or fixed `SIZE (N)` constraint. |
| **`#[rasn(value("MIN..=MAX"))]`** | Integer field or type | Attaches an ASN.1 `INTEGER (MIN..MAX)` value range constraint (e.g., `MessageID (0..2147483647)`). |

---

## 5. Architecture Decision Guide & LDAP / Kerberos Wire Audit

1. **SNMP Version Selection (`v1` vs. `v2c` vs. `v3`)**:
   - **SNMPv1 (RFC 1157)**: Restricted to 32-bit counters (`Counter64` rejected), 4-octet IPv4 `agent-addr` in traps (`0.0.0.0` fallback on IPv6 per RFC 3584 §3.2), and 5 PDU tags (`0xa0`..=`0xa4`). Rejects `GetBulk` and `Inform`.
   - **SNMPv2c (RFC 1901 / RFC 3416)**: Supports `Counter64` (`0x46`), `GetBulkRequest` (`0xa5`), `InformRequest` (`0xa6`), `Trap` (`0xa7`), and `Report` (`0xa8`). Context tag 4 (`0xa4`) is omitted.
   - **SNMPv3 (RFC 3412 / RFC 3414 / RFC 3826 / RFC 7860)**: USM authentication (`MD5`/`SHA` 12B, `SHA256` 24B, `SHA384` 32B, `SHA512` 48B), privacy (`DES` CBC with `ZeroPadding` on encrypt and `NoPadding` on BER decrypt; `AES` 128-CFB stream mode), and `ScopedPdu`.
2. **LDAPv3 (RFC 4511) & Kerberos v5 (RFC 4120) Builder Audit & Verification**:
   - In `src/builders/l7/ldap.rs`, `build_ldap_payload` currently encodes a shortened 3-field `SearchRequest` (`0x63` with only `baseObject`, `scope`, and `derefAliases`, omitting the 5 remaining mandatory RFC 4511 §4.5.1 fields `sizeLimit`, `timeLimit`, `typesOnly`, `filter`, and `attributes`) and ignores `is_bind_res`, `is_search_entry`, `is_search_done`, `is_unbind_req`, `filter`, and `result_code`.
   - In `src/builders/l7/kerberos.rs`, `build_kerberos_payload` currently emits raw ASCII `b"KRB5_AS_REQ:..."` inside `[APPLICATION 10]` (`0x6A`) instead of a DER `SEQUENCE` with explicit tags `[1] pvno (5)`, `[2] msg-type (10)`, `[3] padata`, and `[4] req-body` (with mandatory `[7] till` and `[8] nonce`).
   - Use Pattern 6 in [references/patterns.md](references/patterns.md) for complete `#[derive(AsnType, Encode, Decode)]` schemas to verify RFC 4511 LDAPv3 BER and RFC 4120 Kerberos v5 DER frames.

---

## 6. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations verified against `rasn = "0.28.15"`, `rasn-smi = "0.28.15"`, and `rasn-snmp = "0.28.15"`:
1. **ASN.1 BER/DER Encoding, 1-Arc OID Validation, Zero-Heap Static Types & Derive Matrix (`rasn`)**: Root arc + `len >= 2` validation, `Oid::const_new`, `OctetString::from_static`, `encode_buf`, `decode_with_remainder`, and all 9 `#[rasn(...)]` derive attributes.
2. **Complete SMIv1 & SMIv2 VarBind Conversion Engine (`rasn-smi`)**: Full dual-stack IPv4/IPv6 `VarBind` translator covering all 9 SMI value types and SNMPv1 `Counter64` rejection.
3. **SNMPv1 PDU Builder, Generic Trap OID Auto-Mapper & RFC 3584 IPv6 Trap Adaptation (`rasn-snmp::v1`)**: Distinct tags `0xa0`..=`0xa4`, automatic mapping of `1.3.6.1.6.3.1.1.5.1`..=`.6` to `generic_trap` `0..=5`, and `0.0.0.0` / `AGENTIP` handling.
4. **SNMPv2c Bulk Retrieval, Trap/Inform Mandatory Prepending & Exact `u32` PDU Fields (`rasn-snmp::v2`, `rasn-snmp::v2c`)**: `v2::Pdu` (`request_id: i32, error_status: u32, error_index: u32`), `BulkPdu`, and zero-heap `Oid::const_new` notification prepending.
5. **SNMPv3 Scoped PDU, Two-Stage USM Serialization & DES-CBC `NoPadding` BER Decryption (`rasn-snmp::v3`)**: End-to-end `noAuthNoPriv`, `authNoPriv`, and `authPriv` builder and verifier with `encode_security_parameters`, `decode_security_parameters`, and `NoPadding` BER decryption.
6. **RFC 4511 LDAPv3 BER & RFC 4120 Kerberos v5 DER Wire Verification Schemas (`#[derive(AsnType, Encode, Decode)]`)**: Production ASN.1 models and QA verification functions for LDAP (`BindRequest`, `BindResponse`, 8-field `SearchRequest`, `SearchResultEntry`, `SearchResultDone`, `UnbindRequest`) and Kerberos (`AsReq`, `KdcReq`, `KdcReqBody`, `PrincipalName`, `KrbError`).
