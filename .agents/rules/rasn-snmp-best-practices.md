---
trigger: glob
globs: "src/builders/l7/snmp/**/*.rs, src/builders/l7/ldap.rs, src/builders/l7/kerberos.rs, src/ast/l7/snmp*.rs, src/parser/l7/snmp*.rs, tests/*snmp*.rs"
description: "Rasn 0.28.15, rasn-derive, rasn-smi, and rasn-snmp ASN.1 BER/DER encoding, SMIv1/SMIv2 modeling, SNMPv1/v2c/v3 USM, and LDAP/Kerberos ASN.1 verification rules."
---

# ASN.1 & SNMP Architecture & Best Practices (`rasn`, `rasn-smi`, `rasn-snmp` `0.28.15`)

Always enforce these version-exact (`0.28.15`), RFC-compliant, zero-copy, and cryptographically hardened ASN.1 and SNMP codec rules when designing, implementing, or auditing network management, directory (`LDAP`), and authentication (`Kerberos`) protocol stacks in Rust.

---

## 1. Core ASN.1 Type System, Object Identifiers & BER/DER Codec Selection (`rasn 0.28.15`)

- **BER vs. DER Codec Selection & Buffer Reuse**:
  - Use Basic Encoding Rules (`rasn::ber`) for all SNMPv1, SNMPv2c, and SNMPv3 wire packets per RFC 1157, RFC 1901, RFC 3412, and RFC 3416, and for LDAPv3 per RFC 4511 §5.1. BER supports non-canonical TLV encodings and variable-length headers.
  - Use Distinguished Encoding Rules (`rasn::der`) when strict canonicalization is mandatory (e.g., cryptographic signatures, X.509 certificates, Kerberos v5 tickets and messages in RFC 4120 §5.1). DER prohibits indefinite-length encodings and mandates minimal tag and length octets.
  - Top-level encoding entry points:
    - `rasn::ber::encode(&value)` and `rasn::der::encode(&value)` return `Result<Vec<u8>, EncodeError>`.
    - `rasn::ber::encode_buf(&value, &mut buffer)` appends encoded BER octets directly into a pre-allocated `Vec<u8>`, avoiding repeated heap allocations in packet-generation loops.
  - Top-level decoding entry points:
    - `rasn::ber::decode::<T>(&bytes)` and `rasn::der::decode::<T>(&bytes)` return `Result<T, DecodeError>`.
    - **Stream & QA Remainder Decoding**: Use `rasn::ber::decode_with_remainder::<T>(&bytes)` (or `rasn::der::decode_with_remainder::<T>(&bytes)`) to decode a value and return a borrowed sub-slice `(&[u8])` of unconsumed bytes. Always use `decode_with_remainder` when parsing concatenated TCP BER/DER streams (`LDAP`, `Kerberos`) or when asserting in QA tests that a frame contains zero trailing garbage bytes (`assert!(remainder.is_empty())`).

- **Object Identifier Arc Validation & The 1-Arc `parse_oid` Edge Case (ITU-T X.660 / X.690 §8.19)**:
  - ASN.1 Object Identifiers (`rasn::types::ObjectIdentifier` owned, `rasn::types::Oid` borrowed) must adhere to ITU-T X.660 / ISO/IEC 9834-1 and ITU-T X.690 §8.19.4:
    - Strip optional leading dots before splitting: `oid_str.trim_start_matches('.').split('.')`.
    - Root arc (`arc0`) MUST be in `0..=2` (`0 = itu-t`, `1 = iso`, `2 = joint-iso-itu-t`). Any `arc0 > 2` is invalid.
    - If `arc0 == 0` or `arc0 == 1`, second arc (`arc1`) MUST be `<= 39` (`< 40`). X.690 packs the first two arcs into a single initial subidentifier via `(arc0 * 40) + arc1`. An `arc1 >= 40` would alias onto subsequent root arcs (e.g., `0.40` would encode as `40`, decoding back as `1.0`).
    - If `arc0 == 2`, `arc1` has no upper limit (`2.999999` is valid).
  - **CRITICAL 1-Arc Bug in `ObjectIdentifier::new`**:
    - In `rasn 0.28.15`, `ObjectIdentifier::new(vec![1])` **succeeds** (`Returns Some(...)`) because `Oid::new` only checks `arc0 <= 2` and `arc1 < 40` when `slice.len() >= 2`!
    - However, passing a 1-arc `ObjectIdentifier` to `rasn::ber::encode` fails at serialization time with `BerEncodeErrorKind::InvalidObjectIdentifier` because ITU-T X.690 §8.19 requires at least 2 arcs to compute `(first * 40) + second`.
    - **Mandatory Rule**: Every `parse_oid` implementation MUST explicitly enforce `if oid_vec.len() < 2 { return Err(...); }` before calling `ObjectIdentifier::new(oid_vec)`. Never call `new_unchecked` on untrusted or external DSL input.
  - **Zero-Heap Compile-Time Static OIDs**:
    - For standard protocol OIDs (such as `sysUpTime.0` `1.3.6.1.2.1.1.3.0` or `snmpTrapOID.0` `1.3.6.1.6.3.1.1.4.1.0`), use `ObjectIdentifier::from(Oid::const_new(&[1, 3, 6, 1, 2, 1, 1, 3, 0]))` instead of `ObjectIdentifier::new(vec![...]).unwrap()` to avoid heap allocation during `const` construction.

- **Zero-Heap `Integer` & `OctetString` Representation (`rasn 0.28.15`)**:
  - `rasn::types::Integer` is a **hybrid enum** (`IntegerKind::Primitive(isize)` vs. `IntegerKind::Big(BigInt)`), **not** an unconditional heap-allocated `BigInt`! All `i8`, `i16`, `i32`, `i64` (on 64-bit targets), `u8`, `u16`, `u32`, and `isize` values construct `IntegerKind::Primitive(isize)` on the stack with **zero heap allocation**, while seamlessly spilling over to `Big(BigInt)` only for values outside `isize::MIN..=isize::MAX` (such as `u64::MAX`).
  - Fixed-width native integers (`u8`, `i32`, `u32`, `u64`): If decoded BER integer bytes exceed the target bit width, `rasn::ber::decode` returns `DecodeError` with `DecodeErrorKind::IntegerOverflow { max_width }`.
  - `rasn::types::OctetString` is backed by `bytes::Bytes`, making `.clone()` and sub-slicing $O(1)$ reference-counted operations. For static byte literals (e.g., default community `"public"` or default user `"admin"`), prefer `OctetString::from_static(b"public")` (zero heap allocation) over `.as_bytes().to_vec().into()`.

- **Complete `#[derive(AsnType, Encode, Decode)]` Attribute Matrix (`rasn-derive 0.28.15`)**:
  - `#[rasn(delegate)]`: Transparent newtype wrapper (`struct MyId(pub Integer);`) that inherits the inner type's tag and encoding unless overridden by `#[rasn(tag(...))]`.
  - `#[rasn(choice)]`: Applied to a Rust `enum` where each variant has a distinct tag and encodes directly without an outer `SEQUENCE`.
  - `#[rasn(enumerated)]`: Applied to a fieldless Rust `enum` to encode as Universal `ENUMERATED` (`0x0A`) instead of `CHOICE`.
  - `#[rasn(tag(context|application|universal|private, N))]`: Implicitly retags a field, struct, or enum variant (`context` = `0x80 | N` primitive / `0xA0 | N` constructed; `application` = `0x40 | N` primitive / `0x60 | N` constructed; `universal` = `0x00 | N`; `private` = `0xC0 | N`).
  - `#[rasn(tag(explicit(context|application|universal|private, N)))]`: Wraps the inner TLV inside an outer constructed explicit tag (mandatory throughout RFC 4120 Kerberos v5 `SEQUENCE` fields `[0]..[11]` and `[APPLICATION N]` wrappers).
  - `#[rasn(extension_addition)]` / `#[rasn(extension_addition_group)]`: Marks extensible ASN.1 `...` fields in a `SEQUENCE` or `CHOICE`.
  - `#[rasn(default)]` / `#[rasn(default = "fn_path")]`: Omits encoding when a field equals its default value in DER/CER (or decodes missing optional-with-default BER fields via `fn_path()`).
  - `#[rasn(size("N"))]` / `#[rasn(size("MIN..=MAX"))]`: Enforces `SIZE` constraints on `OctetString`, `BitString`, `Utf8String`, or `SequenceOf`.
  - `#[rasn(value("MIN..=MAX"))]`: Enforces integer value range constraints (`INTEGER (0..2147483647)`).

- **Known `rasn 0.28.15` Upstream Quirks**:
  - **`rasn_smi::v2::ExtUtcTime` Decoder Bug**: Upstream `rasn-smi 0.28.15` contains a tautology bug (`if len != 11 || len != 13`, always `true`) in `ExtUtcTime`'s decoder, causing `ExtUtcTime` decoding to unconditionally fail. Never use `ExtUtcTime` in round-trip decoders; decode raw `OctetString` instead.
  - **`u128` Asymmetric Trait Implementation**: In `rasn 0.28.15`, `u128` implements `AsnType` and `Encode`, but **does not implement `Decode`**. Use `rasn::types::Integer` for values exceeding 64 bits.
  - **`FixedBitString<N>` Sizing Quirk**: `FixedBitString<N>` allocates `[u8; N]` (`8 * N` bits of storage) while constraining the ASN.1 bit length to `N` bits. Prefer `rasn::types::BitString` (or `FixedOctetString<4>` for 32-bit Kerberos flags) to avoid 8x stack bloat.

---

## 2. Structure of Management Information (SMIv1 vs. SMIv2: `rasn-smi 0.28.15`)

- **SMIv1 Data Model (`rasn_smi::v1`, RFC 1155 / RFC 1212)**:
  - `rasn_smi::v1::ObjectSyntax` choice: `Simple(SimpleSyntax)` or `ApplicationWide(ApplicationSyntax)`.
  - `v1::SimpleSyntax` variants: `Number(Integer)`, `String(OctetString)`, `Object(ObjectIdentifier)`, and `Empty`.
  - **SMIv1 NULL Invariant**: When an SNMPv1 variable binding carries no value (e.g., in `GetRequest`, `GetNextRequest`, or explicit `NULLVAL` varbind), the value MUST be `v1::ObjectSyntax::Simple(v1::SimpleSyntax::Empty)`. In BER, this encodes to Universal primitive tag 5 (ASN.1 NULL): `0x05 0x00`.
  - `v1::ApplicationSyntax` variants:
    - `Address(NetworkAddress::Internet(IpAddress(FixedOctetString<4>)))`: Application tag 0 (`0x40`), strictly 4 bytes (IPv4 only). Notice the mandatory `NetworkAddress::Internet(...)` wrapper in `v1`!
    - `Counter(Counter(pub u32))`: Application tag 1 (`0x41`), 32-bit wrapping counter.
    - `Gauge(Gauge(pub u32))`: Application tag 2 (`0x42`), 32-bit non-wrapping metric.
    - `Ticks(TimeTicks(pub u32))`: Application tag 3 (`0x43`), hundredths of a second ($0.01\text{s}$) since epoch/system boot.
    - `Arbitrary(Opaque(Vec<u8>))`: Application tag 4 (`0x44`), BER-encoded payload nested inside an application octet string via `ToOpaque`.

- **SMIv2 Data Model (`rasn_smi::v2`, RFC 2578 / STD 58)**:
  - `rasn_smi::v2::ObjectSyntax` choice: `Simple(SimpleSyntax)` or `ApplicationWide(ApplicationSyntax)`.
  - `v2::SimpleSyntax` variants: `Integer(Integer)`, `String(OctetString)`, `ObjectId(ObjectIdentifier)`.
  - **Critical SMIv1 vs. SMIv2 Differences**:
    1. `v2::SimpleSyntax` **does not have** an `Empty` variant! In SNMPv2c and SNMPv3, NULL variable bindings are represented at the PDU layer via `rasn_snmp::v2::VarBindValue::Unspecified`.
    2. `v2::SimpleSyntax` renames `Number` -> `Integer` and `Object` -> `ObjectId`.
    3. `v2::ApplicationSyntax::Address(IpAddress)` takes `v1::IpAddress` **directly** without the `v1::NetworkAddress::Internet` enum wrapper.
    4. `v2::ApplicationSyntax::Unsigned(Unsigned32)` (where `pub type Unsigned32 = v1::Gauge`) replaces `v1::ApplicationSyntax::Gauge`.
    5. `v2::ApplicationSyntax::BigCounter(Counter64(pub u64))` adds Application tag 6 (`0x46`) for 64-bit high-speed interface counters. Attempting to encode `Counter64` in an SNMPv1 packet MUST be rejected with a descriptive error (`"Counter64 is not supported in SNMPv1 (introduced in SNMPv2 SMIv2 RFC 2578)"`).

---

## 3. SNMPv1 Wire Protocol Framing, Generic Trap Auto-Mapping & Dual-Stack Adaptation (`rasn-snmp::v1`)

- **Exact `rasn_snmp::v1::Pdu` vs. `rasn_snmp::v2::Pdu` Field Types**:
  - `rasn_snmp::v1::Message<T>`: `version: Integer` (`0`, `Message::<()>::VERSION_1`), `community: OctetString`, `data: T` (`rasn_snmp::v1::Pdus`).
  - **Field Type Asymmetry (`Integer` vs. `i32`/`u32`)**:
    - `rasn_snmp::v1::Pdu` defines `pub request_id: Integer`, `pub error_status: Integer`, `pub error_index: Integer`, `pub variable_bindings: VarBindList` (with `v1::Pdu::ERROR_STATUS_*` constants `0..=5` typed as `u64`).
    - `rasn_snmp::v2::Pdu` defines `pub request_id: i32`, `pub error_status: u32`, `pub error_index: u32`, `pub variable_bindings: VarBindList` (with `v2::Pdu::ERROR_STATUS_*` constants `0..=18` typed as `u32`). Never state that `v2::Pdu` uses `i32` for `error_status` or `error_index`!
    - `rasn_snmp::v2::BulkPdu` defines `pub request_id: i32`, `pub non_repeaters: u32`, `pub max_repetitions: u32`, `pub variable_bindings: VarBindList`.

- **Distinct Context Tags & Operation Rejection for SNMPv1 PDUs**:
  - `GetRequest` (`0xa0`), `GetNextRequest` (`0xa1`), `GetResponse` (`0xa2`), `SetRequest` (`0xa3`), `Trap` (`0xa4`). Never encode non-trap operations (`Get`, `GetNext`, `Set`, `Response`) as `Trap` (`0xa4`).
  - SNMPv1 does not define `GetBulkRequest` or `InformRequest` (introduced in SNMPv2c RFC 1905). Any attempt to encode `GetBulk` or `Inform` under `SNMP1` MUST be rejected with a diagnostic error.

- **RFC 1157 Trap Fields, Generic Trap OID Auto-Mapping & RFC 3584 §3.2 IPv6 Adaptation**:
  - `Trap` fields: `enterprise: ObjectIdentifier`, `agent_addr: NetworkAddress::Internet(IpAddress)` (strictly 4-octet IPv4), `generic_trap: Integer` (`0..=6`), `specific_trap: Integer`, `time_stamp: TimeTicks`, `variable_bindings: VarBindList`.
  - **Automatic OID-to-Generic-Trap Mapping**: When `GENTRAP` is not explicitly set, inspect the trap OID (`.trim_start_matches('.')`) and set `specific_trap = 0` for standard traps (`1.3.6.1.6.3.1.1.5.1`..=`.6`):
    - `.1` -> `0` (`coldStart`); `.2` -> `1` (`warmStart`); `.3` -> `2` (`linkDown`); `.4` -> `3` (`linkUp`); `.5` -> `4` (`authenticationFailure`); `.6` -> `5` (`egpNeighborLoss`).
    - Any other OID -> `generic_trap = 6` (`enterpriseSpecific`), `specific_trap = spec_trap.unwrap_or(1)`.
  - **RFC 3584 §3.2 Dual-Stack IPv6 Trap Adaptation**: Because `agent_addr` is strictly 4-octet IPv4, traps emitted from IPv6 hosts MUST default `agent_addr` to `0.0.0.0` (`[0, 0, 0, 0]`) unless overridden by an explicit `AGENTIP <ipv4>`.

---

## 4. SNMPv2c Operations, Bulk Retrieval & RFC 4001 IPv6 VarBinds (`rasn-snmp::v2`, `v2c`)

- **RFC 1901 Community Message & RFC 3416 PDU Tags (Tag 4 Omission)**:
  - `rasn_snmp::v2c::Message<T>`: `version: Integer::from(1)` (`Message::<()>::VERSION`), `community: OctetString`, `data: T` (`rasn_snmp::v2::Pdus`).
  - Context tags: `0xa0` (`GetRequest`), `0xa1` (`GetNextRequest`), `0xa2` (`Response`), `0xa3` (`SetRequest`), *tag 4 omitted*, `0xa5` (`GetBulkRequest`), `0xa6` (`InformRequest`), `0xa7` (`Trap`), `0xa8` (`Report`).

- **RFC 3416 `VarBindValue` Exceptions & ASN.1 NULL**:
  - `VarBindValue::Unspecified`: Encodes to Universal tag 5 (`0x05 0x00`). Used in request PDUs (`Get`, `GetNext`, `GetBulk`).
  - Response exception tokens: `NoSuchObject` (`0x80 0x00`), `NoSuchInstance` (`0x81 0x00`), `EndOfMibView` (`0x82 0x00`).

- **Mandatory SNMPv2c/v3 Notification VarBind Ordering (`Trap` & `Inform`)**:
  - Every SNMPv2c/v3 `Trap` (`0xa7`) or `InformRequest` (`0xa6`) PDU MUST prepend two standard variable bindings in exact order before any user variable bindings:
    1. Index 0: `sysUpTime.0` (`1.3.6.1.2.1.1.3.0`) -> `ApplicationSyntax::Ticks(TimeTicks(uptime))`.
    2. Index 1: `snmpTrapOID.0` (`1.3.6.1.6.3.1.1.4.1.0`) -> `SimpleSyntax::ObjectId(trap_oid)`.
    3. Index 2+: User-supplied variable bindings.
  - Non-notification PDUs (`Get`, `GetNext`, `GetBulk`, `Set`, `Response`) MUST NOT prepend `sysUpTime.0` or `snmpTrapOID.0`.

- **RFC 4001 Dual-Stack IP Addresses in VarBinds**:
  - IPv4 `IPVAL` -> 4-byte `ApplicationSyntax::Address(IpAddress(v4.octets().into()))` (`0x40`).
  - IPv6 `IPVAL` -> 16-byte `SimpleSyntax::String(OctetString::from(v6.octets().to_vec()))` (`0x04`).

---

## 5. SNMPv3 Architecture, Scoped PDUs & Two-Stage USM Security Parameters (`rasn-snmp::v3`)

- **RFC 3412 Message & Two-Stage BER Encoding**:
  - `rasn_snmp::v3::Message`: `version: Integer::from(3)`, `global_data: HeaderData`, `security_parameters: OctetString`, `scoped_data: ScopedPduData`.
  - Because `Message.security_parameters` is an `OCTET STRING` (not an inline `SEQUENCE`), `USMSecurityParameters` MUST be BER-encoded into bytes first (`rasn::ber::encode(&usm_params)` or `message.encode_security_parameters(rasn::Codec::Ber, &usm_params)`), and decoded on receipt via `rasn::ber::decode(msg.security_parameters.as_ref())` or `msg.decode_security_parameters::<USMSecurityParameters>(rasn::Codec::Ber)`.

- **UDP Port Conventions**:
  - Queries (`Get`, `GetNext`, `GetBulk`, `Set`) and `Response`: default destination port UDP `161`.
  - Notifications (`Trap`, `Inform`): default destination port UDP `162`.

---

## 6. USM Cryptography, Key Localization, Padding & BER Decryption Invariants

- **RFC 3414 A.2.1 / RFC 7860 1-Megabyte Key Localization & Empty-Password Guard**:
  - Pass 1 expands the user password by repeating it to `1,048,576` bytes ($2^{20}$ bytes = $16,384 \times 64$-byte blocks) and hashing to produce `Ku`.
  - Pass 2 hashes `Ku || engine_id || Ku` to produce the localized key `Kul`.
  - **Division-by-Zero Guard**: Never index `password[password_index % password.len()]` without first checking `if password.is_empty()`! Reject empty authentication or privacy passwords (`""`) at validation time (`Err("SNMPv3 authentication/privacy password cannot be empty")`).

- **Authentication MAC Truncation Lengths & Pre-Sized Zero Placeholder Invariant**:
  - Wire MAC truncation lengths: `MD5` (`12`B), `SHA` (`12`B), `SHA224` (`16`B), `SHA256` (`24`B), `SHA384` (`32`B), `SHA512` (`48`B).
  - **Pre-Sized Zero Placeholder Invariant**: Before BER-encoding the outer `Message` to compute the HMAC, `usm_params.authentication_parameters` MUST be initialized to `OctetString::from(vec![0u8; auth_len])` (never `vec![]` when `auth` is enabled!). Using `vec![0u8; auth_len]` ensures the BER length octets of `USMSecurityParameters`, `Message.security_parameters`, and the outer `Message` SEQUENCE remain identical before and after replacing the zeros with the computed MAC.

- **Privacy Encryption & The DES-CBC `ZeroPadding` vs. `NoPadding` BER Decryption Invariant**:
  - **DES-CBC Encryption (RFC 3414 §8.1.1.1 – §8.1.1.2)**:
    - Localized `priv_key` must be at least 16 bytes: `des_key = &priv_key[0..8]`, `pre_iv = &priv_key[8..16]`, `iv[i] = pre_iv[i] ^ salt[i]`.
    - Encrypt with `block_padding::ZeroPadding`: if `plaintext.len() % 8 == 0`, add `0` padding bytes; otherwise pad with `0x00` to the next 8-byte multiple. Never use `Pkcs7`!
  - **DES-CBC Decryption (`NoPadding` Invariant)**:
    - When decrypting an SNMPv3 DES-CBC `EncryptedPdu` (see `tests/snmp_spec_tests.rs:194`), **do not pass the slice returned by `decrypt_padded::<ZeroPadding>` to `rasn::ber::decode`**! If the BER-encoded `ScopedPdu` length is an exact multiple of 8 bytes and its final VarBind ends in `0x00` (e.g., `INT 0` = `02 01 00` or `NULLVAL` = `05 00`), `ZeroPadding::unpad` strips the valid trailing `0x00` byte(s) of the BER TLV, corrupting the final VarBind!
    - Instead, because an ASN.1 BER `ScopedPdu` (`0x30`) is self-delimiting via its outer TLV length header, decrypt raw 8-byte blocks using `decrypt_padded::<NoPadding>(&mut ciphertext_buf)` and pass `&ciphertext_buf` to `rasn::ber::decode::<ScopedPdu>`.
  - **AES-128-CFB (RFC 3826 §3.1.2.1)**:
    - Uses `aes_key = &priv_key[0..16]` and 16-byte IV `engine_boots.to_be_bytes() (4B) || engine_time.to_be_bytes() (4B) || salt (8B)`. Stream mode: zero padding bytes.

- **Security Level Flags Bitmask (RFC 3412 §6.4)**:
  - Bit 0 (`0x01`): `authFlag`; Bit 1 (`0x02`): `privFlag`; Bit 2 (`0x04`): `reportableFlag`.
  - Reject `noAuthPriv` (`auth.is_none() && priv_param.is_some()`, `flags & 0x03 == 0x02`).
  - Set `reportableFlag` (`0x04`) on all confirmed PDUs (`Get`, `GetNext`, `GetBulk`, `Set`, `Inform`); clear it on unconfirmed PDUs (`Trap`, `Response`).

---

## 7. LDAPv3 (RFC 4511) & Kerberos v5 (RFC 4120) ASN.1 Wire Verification Rules

- **LDAPv3 (RFC 4511) BER Structure**:
  - `LDAPMessage ::= SEQUENCE { messageID MessageID (1..2147483647), protocolOp CHOICE { bindRequest [APPLICATION 0], bindResponse [APPLICATION 1], unbindRequest [APPLICATION 2], searchRequest [APPLICATION 3], searchResEntry [APPLICATION 4], searchResDone [APPLICATION 5], ... }, controls [0] Controls OPTIONAL }`.
  - **Known Builder Gap in `src/builders/l7/ldap.rs`**: `build_ldap_payload` currently only branches on `spec.is_search_req` (`0x63`) vs. default `BindRequest` (`0x60`), ignoring `is_bind_res`, `is_search_entry`, `is_search_done`, `is_unbind_req`, `filter`, and `result_code`. Furthermore, its `SearchRequest` (`0x63`) encodes only 3 of the 8 mandatory RFC 4511 §4.5.1 fields (`baseObject`, `scope`, `derefAliases`), omitting `sizeLimit`, `timeLimit`, `typesOnly`, `filter`, and `attributes`. When writing strict RFC 4511 QA tests or upgrading the builder, validate against the full `#[derive(AsnType, Encode, Decode)]` `LdapMessage` schema in `.agents/skills/rasn-snmp-codec/references/patterns.md`.

- **Kerberos v5 (RFC 4120) DER Structure**:
  - Every `AS-REQ` (`[APPLICATION 10]`, `0x6A`), `AS-REP` (`[APPLICATION 11]`, `0x6B`), `TGS-REQ` (`[APPLICATION 12]`, `0x6C`), `TGS-REP` (`[APPLICATION 13]`, `0x6D`), and `KRB-ERROR` (`[APPLICATION 30]`, `0x7E`) wraps a DER `SEQUENCE` whose fields use **explicit** context tags (`#[rasn(tag(explicit(context, N)))]`): `[1] pvno (5)`, `[2] msg-type`, `[3] padata OPTIONAL`, `[4] req-body KDC-REQ-BODY` (which requires `[0] kdc-options`, `[2] realm`, `[7] till`, `[8] nonce`, `[9] etype`).
  - **Known Builder Gap in `src/builders/l7/kerberos.rs`**: `build_kerberos_payload` currently emits `[0x6A, len, b"KRB5_AS_REQ:<realm>:<cname>"...]` (raw ASCII inside `[APPLICATION 10]`) instead of a valid DER `SEQUENCE` with explicit tags `[1]..[4]`. Use the `#[derive(AsnType, Encode, Decode)]` `AsReq` / `KdcReqBody` schemas in `.agents/skills/rasn-snmp-codec/references/patterns.md` for canonical RFC 4120 DER verification.

---

## 8. Anti-Patterns & Architectural Guardrails

| # | Anti-Pattern | Correct Idiomatic Approach | Rationale / Failure Mode |
|---|:---|:---|:---|
| 1 | Calling `ObjectIdentifier::new(oid_vec)` without checking `oid_vec.len() >= 2` | Guard `if oid_vec.len() < 2 { return Err(...); }` before `ObjectIdentifier::new` | `ObjectIdentifier::new(vec![1])` returns `Some` in `rasn 0.28.15` and then fails inside `rasn::ber::encode` (`InvalidObjectIdentifier`). |
| 2 | Typing `v2::Pdu` `error_status` or `error_index` as `i32` or `Integer` | Use `request_id: i32`, `error_status: u32`, `error_index: u32` in `v2::Pdu` (`Integer` in `v1::Pdu`) | `rasn_snmp::v2::Pdu` defines `error_status` and `error_index` as `u32` (with `u32` `ERROR_STATUS_*` constants). |
| 3 | Using `SimpleSyntax::Number(0)` to represent NULL in SNMPv1 | Use `v1::SimpleSyntax::Empty` (and `v2::VarBindValue::Unspecified` in v2/v3) | BER tag becomes Universal Integer (`0x02 0x01 0x00`) instead of Universal NULL (`0x05 0x00`). |
| 4 | Wrapping `v2::ApplicationSyntax::Address` in `NetworkAddress::Internet` | Pass `v1::IpAddress` directly in v2; wrap in `NetworkAddress::Internet` only in v1 | Compile error: `v1` and `v2` `ApplicationSyntax::Address` have different inner types. |
| 5 | Allowing `Counter64` (`0x46`) or `GETBULK`/`INFORM` in `SNMP1` | Reject with descriptive error; only valid in `SNMP2` and `SNMP3` | Violates RFC 1157 / RFC 2578; SNMPv1 agents cannot decode tag `0x46`, `0xa5`, or `0xa6`. |
| 6 | Truncating 16-byte IPv6 address for SNMPv1 `agent-addr` or SMI `IpAddress` | Use `0.0.0.0` for v1 `agent-addr` (RFC 3584 §3.2) and 16B `OctetString` in VarBinds (RFC 4001) | `IpAddress` is `FixedOctetString<4>`; RFC 4001 encodes IPv6 `InetAddress` as 16-octet `OCTET STRING`. |
| 7 | Passing empty password `""` into RFC 3414 key localization | Guard `if password.is_empty()` and reject empty USM passwords | `password[i % password.len()]` panics with division-by-zero on empty slice. |
| 8 | Using `vec![]` instead of `vec![0u8; auth_len]` during pre-MAC BER encode | Pre-fill `authentication_parameters` with `auth_len` (`12`/`24`/`32`/`48`) zero bytes | Outer BER SEQUENCE length octets shift when MAC is inserted, invalidating the HMAC digest. |
| 9 | Decrypting DES-CBC `ScopedPdu` with `decrypt_padded::<ZeroPadding>` | Decrypt with `decrypt_padded::<NoPadding>` and pass buffer to `rasn::ber::decode` | If an 8-byte-aligned BER `ScopedPdu` ends in `0x00` (`INT 0` or `NULLVAL`), `ZeroPadding` strips the valid BER byte! |
| 10 | Using `rasn_smi::v2::ExtUtcTime` or `u128` in `Decode` structs | Use `OctetString` for UTC time and `rasn::types::Integer` for $>64$-bit integers | `ExtUtcTime` has an upstream `len != 11 \|\| len != 13` decoder bug; `u128` lacks `Decode` in `rasn 0.28.15`. |
