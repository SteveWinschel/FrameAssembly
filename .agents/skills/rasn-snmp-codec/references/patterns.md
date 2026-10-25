# ASN.1 & SNMP Production Reference Patterns (`rasn`, `rasn-smi`, `rasn-snmp` `0.28.15`)

This reference contains production-ready, fully-documented, and compile-verified Rust patterns for ASN.1 BER/DER encoding, SMIv1/SMIv2 data modeling, SNMPv1/v2c/v3 USM wire framing, and RFC 4511 LDAPv3 / RFC 4120 Kerberos v5 ASN.1 verification verified against `rasn = "0.28.15"`, `rasn-smi = "0.28.15"`, and `rasn-snmp = "0.28.15"`.

---

## 1. ASN.1 BER/DER Encoding, 1-Arc OID Guard, Zero-Heap Statics & `#[rasn(...)]` Derive Matrix (`rasn`)

Demonstrates:
- Dot-notation OID parsing with leading-dot normalization (`.trim_start_matches('.')`) and **explicit `arcs.len() >= 2` validation** before calling `ObjectIdentifier::new(arcs)`. In `rasn 0.28.15`, `ObjectIdentifier::new(vec![1])` returns `Some(...)` (only checking `arc0 <= 2` and `arc1 < 40` when `len >= 2`), which later fails inside `rasn::ber::encode` (`BerEncodeErrorKind::InvalidObjectIdentifier`) because ITU-T X.690 §8.19 requires $\ge 2$ arcs to pack `(arc0 * 40) + arc1`.
- Zero-heap compile-time OID construction via `Oid::const_new`, zero-heap static byte strings via `OctetString::from_static`, buffer reuse via `rasn::ber::encode_buf`, and stream remainder decoding via `rasn::ber::decode_with_remainder`.
- Complete `#[derive(AsnType, Encode, Decode)]` attribute showcase (`delegate`, `choice`, `enumerated`, `tag(context|application|universal|private, N)`, `tag(explicit(...))`, `extension_addition`, `default`, `size("...")`, `value("...")`).

```rust
//! Pattern 1: ASN.1 BER/DER encoding, 1-arc OID guard, zero-heap statics, and derive attributes.

use rasn::prelude::*;
use rasn::types::{Integer, ObjectIdentifier, OctetString, Oid};

/// Compile-time zero-heap `sysUpTime.0` OID (`1.3.6.1.2.1.1.3.0`).
pub const SYS_UP_TIME_OID: &Oid = Oid::const_new(&[1, 3, 6, 1, 2, 1, 1, 3, 0]);

/// Compile-time zero-heap `snmpTrapOID.0` OID (`1.3.6.1.6.3.1.1.4.1.0`).
pub const SNMP_TRAP_OID: &Oid = Oid::const_new(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]);

/// Parses a dot-notation OID string (e.g., `"1.3.6.1.2.1.1.1.0"` or `".1.3.6.1.2.1.1.1.0"`)
/// into a validated `rasn::types::ObjectIdentifier`.
///
/// # ITU-T X.660 / X.690 §8.19 Invariants
/// 1. Explicitly requires `arcs.len() >= 2` because `ObjectIdentifier::new(vec![1])` succeeds
///    in `rasn 0.28.15` and then fails inside `rasn::ber::encode` (`InvalidObjectIdentifier`).
/// 2. Root arc (`arc0`) must be in `0..=2`.
/// 3. When `arc0 < 2`, second arc (`arc1`) must be `<= 39`.
pub fn parse_and_validate_oid(oid_str: &str) -> Result<ObjectIdentifier, String> {
    let mut arcs = Vec::new();
    for segment in oid_str.trim_start_matches('.').split('.') {
        let val = segment
            .parse::<u32>()
            .map_err(|_| format!("Invalid numeric OID arc: '{segment}'"))?;
        arcs.push(val);
    }
    if arcs.len() < 2 {
        return Err(format!(
            "ITU-T X.690 §8.19 requires at least 2 OID arcs in '{oid_str}'"
        ));
    }
    ObjectIdentifier::new(arcs).ok_or_else(|| {
        format!("Invalid ITU-T X.660 OID root arc structure in '{oid_str}'")
    })
}

/// Transparent newtype (`#[rasn(delegate)]`) with a value range constraint (`#[rasn(value("..."))]`).
#[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq)]
#[rasn(delegate, value("0..=2147483647"))]
pub struct ConstrainedMessageId(pub u32);

/// Universal `ENUMERATED` (`0x0A`) severity level (`#[rasn(enumerated)]`).
#[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, Default)]
#[rasn(enumerated)]
pub enum TelemetrySeverity {
    /// Informational event (0).
    #[default]
    Info = 0,
    /// Warning condition (1).
    Warning = 1,
    /// Critical fault (2).
    Critical = 2,
}

/// Custom ASN.1 `CHOICE` demonstrating implicit context, application, and explicit tags.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(choice)]
pub enum TelemetryValue {
    /// Implicit context-specific tag 0 (`0x80`): stack-allocated hybrid `Integer`.
    #[rasn(tag(context, 0))]
    SignedMetric(Integer),
    /// Implicit context-specific tag 1 (`0x81`): bounded UTF-8/ASCII label (`SIZE(1..=64)`).
    #[rasn(tag(context, 1), size("1..=64"))]
    Label(OctetString),
    /// Explicit context-specific tag 2 (`0xA2`) wrapping an `[APPLICATION 7]` counter.
    #[rasn(tag(explicit(context, 2)))]
    ExplicitCounter(u64),
}

/// Custom extensible ASN.1 `SEQUENCE` demonstrating `default` and `extension_addition`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
pub struct EnterpriseTelemetryRecord {
    /// Constrained 31-bit message identifier.
    pub record_id: ConstrainedMessageId,
    /// Managed object identifier.
    pub mib_oid: ObjectIdentifier,
    /// Optional-with-default severity (`ENUMERATED`).
    #[rasn(tag(context, 0), default)]
    pub severity: TelemetrySeverity,
    /// Choice payload value.
    pub value: TelemetryValue,
    /// Extensible addition field (`...`) after the base sequence.
    #[rasn(extension_addition, tag(context, 1))]
    pub origin_tag: Option<OctetString>,
}

/// Appends BER-encoded wire bytes of `value` into a reusable `buffer` without allocating a new `Vec`.
pub fn encode_ber_into_buf<T: Encode>(
    value: &T,
    buffer: &mut Vec<u8>,
) -> Result<(), rasn::error::EncodeError> {
    rasn::ber::encode_buf(value, buffer)
}

/// Decodes a value from the head of a BER byte stream and returns the unconsumed remainder slice.
pub fn decode_ber_with_remainder<T: Decode>(
    bytes: &[u8],
) -> Result<(T, &[u8]), rasn::error::DecodeError> {
    rasn::ber::decode_with_remainder(bytes)
}
```

---

## 2. Complete SMIv1 & SMIv2 VarBind Conversion Engine (`rasn-smi`)

Demonstrates the exact structural mapping between high-level variable binding values and `rasn_smi::v1::ObjectSyntax` vs. `rasn_smi::v2::ObjectSyntax`, including:
- **NULL**: `v1::SimpleSyntax::Empty` vs. `v2::VarBindValue::Unspecified`.
- **IPv4 vs. IPv6 (`RFC 4001`)**: 4-byte `IpAddress` (`0x40`, wrapped in `NetworkAddress::Internet` in v1, direct in v2) vs. 16-byte `OctetString` (`0x04`) for IPv6 addresses.
- **Gauge32**: `v1::ApplicationSyntax::Gauge` vs. `v2::ApplicationSyntax::Unsigned`.
- **Counter64 (`0x46`)**: Supported via `v2::ApplicationSyntax::BigCounter(Counter64)` in SNMPv2c/v3, and explicitly rejected with a diagnostic error in SNMPv1.

```rust
//! Pattern 2: Dual-stack SMIv1 and SMIv2 VarBind conversion engine.

use core::net::IpAddr;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1 as smiv1;
use rasn_smi::v2 as smiv2;
use rasn_snmp::v1 as snmpv1;
use rasn_snmp::v2 as snmpv2;

/// High-level typed SNMP variable binding value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnmpTypedValue {
    /// ASN.1 NULL (`0x05 0x00`).
    Null,
    /// Signed integer (`0x02`) — uses stack `IntegerKind::Primitive(isize)` on 64-bit targets.
    Int(i64),
    /// Octet string (`0x04`).
    String(Vec<u8>),
    /// Object Identifier (`0x06`).
    Oid(ObjectIdentifier),
    /// Dual-stack IP address: IPv4 -> 4B `IpAddress` (`0x40`), IPv6 -> 16B `OctetString` (`0x04`, RFC 4001).
    Ip(IpAddr),
    /// 32-bit wrapping counter (`0x41`).
    Counter32(u32),
    /// 32-bit non-wrapping gauge / unsigned (`0x42`).
    Gauge32(u32),
    /// 32-bit TimeTicks in hundredths of a second (`0x43`).
    TimeTicks(u32),
    /// 64-bit high-capacity counter (`0x46`, SMIv2 only).
    Counter64(u64),
}

/// Converts a `(ObjectIdentifier, SnmpTypedValue)` pair into an SNMPv1 `rasn_snmp::v1::VarBind`.
pub fn to_snmpv1_varbind(
    name: ObjectIdentifier,
    val: &SnmpTypedValue,
) -> Result<snmpv1::VarBind, String> {
    let value = match val {
        SnmpTypedValue::Null => smiv1::ObjectSyntax::Simple(smiv1::SimpleSyntax::Empty),
        SnmpTypedValue::Int(i) => {
            smiv1::ObjectSyntax::Simple(smiv1::SimpleSyntax::Number(Integer::from(*i)))
        }
        SnmpTypedValue::String(bytes) => {
            smiv1::ObjectSyntax::Simple(smiv1::SimpleSyntax::String(OctetString::from(bytes.clone())))
        }
        SnmpTypedValue::Oid(oid) => {
            smiv1::ObjectSyntax::Simple(smiv1::SimpleSyntax::Object(oid.clone()))
        }
        SnmpTypedValue::Ip(IpAddr::V4(v4)) => smiv1::ObjectSyntax::ApplicationWide(
            smiv1::ApplicationSyntax::Address(smiv1::NetworkAddress::Internet(smiv1::IpAddress(
                v4.octets().into(),
            ))),
        ),
        SnmpTypedValue::Ip(IpAddr::V6(v6)) => smiv1::ObjectSyntax::Simple(
            smiv1::SimpleSyntax::String(OctetString::from(v6.octets().to_vec())),
        ),
        SnmpTypedValue::Counter32(c) => {
            smiv1::ObjectSyntax::ApplicationWide(smiv1::ApplicationSyntax::Counter(smiv1::Counter(*c)))
        }
        SnmpTypedValue::Gauge32(g) => {
            smiv1::ObjectSyntax::ApplicationWide(smiv1::ApplicationSyntax::Gauge(smiv1::Gauge(*g)))
        }
        SnmpTypedValue::TimeTicks(t) => {
            smiv1::ObjectSyntax::ApplicationWide(smiv1::ApplicationSyntax::Ticks(smiv1::TimeTicks(*t)))
        }
        SnmpTypedValue::Counter64(_) => {
            return Err(
                "Counter64 is not supported in SNMPv1 (introduced in SNMPv2 SMIv2 RFC 2578)"
                    .to_string(),
            );
        }
    };
    Ok(snmpv1::VarBind { name, value })
}

/// Converts a `(ObjectIdentifier, SnmpTypedValue)` pair into an SNMPv2c/v3 `rasn_snmp::v2::VarBind`.
pub fn to_snmpv2_varbind(name: ObjectIdentifier, val: &SnmpTypedValue) -> snmpv2::VarBind {
    let value = match val {
        SnmpTypedValue::Null => snmpv2::VarBindValue::Unspecified,
        SnmpTypedValue::Int(i) => snmpv2::VarBindValue::Value(smiv2::ObjectSyntax::Simple(
            smiv2::SimpleSyntax::Integer(Integer::from(*i)),
        )),
        SnmpTypedValue::String(bytes) => snmpv2::VarBindValue::Value(smiv2::ObjectSyntax::Simple(
            smiv2::SimpleSyntax::String(OctetString::from(bytes.clone())),
        )),
        SnmpTypedValue::Oid(oid) => snmpv2::VarBindValue::Value(smiv2::ObjectSyntax::Simple(
            smiv2::SimpleSyntax::ObjectId(oid.clone()),
        )),
        SnmpTypedValue::Ip(IpAddr::V4(v4)) => snmpv2::VarBindValue::Value(
            smiv2::ObjectSyntax::ApplicationWide(smiv2::ApplicationSyntax::Address(
                smiv1::IpAddress(v4.octets().into()),
            )),
        ),
        SnmpTypedValue::Ip(IpAddr::V6(v6)) => snmpv2::VarBindValue::Value(
            smiv2::ObjectSyntax::Simple(smiv2::SimpleSyntax::String(OctetString::from(
                v6.octets().to_vec(),
            ))),
        ),
        SnmpTypedValue::Counter32(c) => snmpv2::VarBindValue::Value(
            smiv2::ObjectSyntax::ApplicationWide(smiv2::ApplicationSyntax::Counter(smiv1::Counter(*c))),
        ),
        SnmpTypedValue::Gauge32(g) => snmpv2::VarBindValue::Value(
            smiv2::ObjectSyntax::ApplicationWide(smiv2::ApplicationSyntax::Unsigned(smiv1::Gauge(*g))),
        ),
        SnmpTypedValue::TimeTicks(t) => snmpv2::VarBindValue::Value(
            smiv2::ObjectSyntax::ApplicationWide(smiv2::ApplicationSyntax::Ticks(smiv1::TimeTicks(*t))),
        ),
        SnmpTypedValue::Counter64(c) => snmpv2::VarBindValue::Value(
            smiv2::ObjectSyntax::ApplicationWide(smiv2::ApplicationSyntax::BigCounter(
                smiv2::Counter64(*c),
            )),
        ),
    };
    snmpv2::VarBind { name, value }
}
```

---

## 3. SNMPv1 PDU Builder, Generic Trap OID Auto-Mapper & RFC 3584 IPv6 Trap Adaptation (`rasn-snmp::v1`)

Demonstrates:
- Distinct RFC 1157 context tags: `GetRequest` (`0xa0`), `GetNextRequest` (`0xa1`), `GetResponse` (`0xa2`), `SetRequest` (`0xa3`), and `Trap` (`0xa4`), where `v1::Pdu` uses `Integer` fields (`request_id`, `error_status`, `error_index`) and `u64` `ERROR_STATUS_*` constants (`0..=5`).
- Automatic mapping of standard RFC 1157 / RFC 3418 generic trap OIDs (`1.3.6.1.6.3.1.1.5.1` through `.6`) to `generic_trap` `0..=5` (`coldStart`..=`egpNeighborLoss`) with `specific_trap = 0`, while enterprise OIDs map to `generic_trap = 6` (`enterpriseSpecific`) with `specific_trap = 1`.
- RFC 3584 §3.2 dual-stack IPv6 handling: `agent_addr` defaults to `0.0.0.0` (`[0, 0, 0, 0]`) when the emitting host is IPv6, unless overridden by an explicit `AGENTIP`.

```rust
//! Pattern 3: SNMPv1 PDU construction, generic trap auto-mapping, and RFC 3584 IPv6 adaptation.

use core::net::{IpAddr, Ipv4Addr};
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1 as smiv1;
use rasn_snmp::v1 as snmpv1;

/// Maps an OID string to RFC 1157 `(generic_trap, specific_trap)` codes when `explicit_gen_trap` is omitted.
pub fn resolve_snmpv1_trap_codes(
    oid_str: &str,
    explicit_gen_trap: Option<u32>,
    explicit_spec_trap: Option<u32>,
) -> (u32, u32) {
    match explicit_gen_trap {
        Some(g) if (0..=5).contains(&g) => (g, explicit_spec_trap.unwrap_or(0)),
        Some(g) => (g, explicit_spec_trap.unwrap_or(1)),
        None => match oid_str.trim_start_matches('.') {
            "1.3.6.1.6.3.1.1.5.1" => (0, explicit_spec_trap.unwrap_or(0)), // coldStart
            "1.3.6.1.6.3.1.1.5.2" => (1, explicit_spec_trap.unwrap_or(0)), // warmStart
            "1.3.6.1.6.3.1.1.5.3" => (2, explicit_spec_trap.unwrap_or(0)), // linkDown
            "1.3.6.1.6.3.1.1.5.4" => (3, explicit_spec_trap.unwrap_or(0)), // linkUp
            "1.3.6.1.6.3.1.1.5.5" => (4, explicit_spec_trap.unwrap_or(0)), // authenticationFailure
            "1.3.6.1.6.3.1.1.5.6" => (5, explicit_spec_trap.unwrap_or(0)), // egpNeighborLoss
            _ => (6, explicit_spec_trap.unwrap_or(1)),                     // enterpriseSpecific
        },
    }
}

/// Builds and BER-encodes an RFC 1157 SNMPv1 `Trap` PDU (`0xa4`) with RFC 3584 §3.2 IPv6 adaptation.
#[allow(clippy::too_many_arguments)]
pub fn build_snmpv1_trap_packet(
    community: &str,
    enterprise_oid: ObjectIdentifier,
    oid_str_for_mapping: &str,
    src_ip: IpAddr,
    agent_ip_override: Option<Ipv4Addr>,
    gen_trap: Option<u32>,
    spec_trap: Option<u32>,
    uptime_ticks: u32,
    varbinds: Vec<snmpv1::VarBind>,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let agent_octets = match (agent_ip_override, src_ip) {
        (Some(v4), _) => v4.octets(),
        (None, IpAddr::V4(v4)) => v4.octets(),
        (None, IpAddr::V6(_)) => [0, 0, 0, 0], // RFC 3584 §3.2 IPv6 fallback
    };

    let (generic_trap, specific_trap) =
        resolve_snmpv1_trap_codes(oid_str_for_mapping, gen_trap, spec_trap);

    let trap = snmpv1::Trap {
        enterprise: enterprise_oid,
        agent_addr: smiv1::NetworkAddress::Internet(smiv1::IpAddress(agent_octets.into())),
        generic_trap: Integer::from(generic_trap),
        specific_trap: Integer::from(specific_trap),
        time_stamp: smiv1::TimeTicks(uptime_ticks),
        variable_bindings: varbinds,
    };

    let msg = snmpv1::Message {
        version: Integer::from(snmpv1::Message::<()>::VERSION_1),
        community: if community == "public" {
            OctetString::from_static(b"public")
        } else {
            OctetString::from(community.as_bytes().to_vec())
        },
        data: snmpv1::Pdus::Trap(trap),
    };

    rasn::ber::encode(&msg)
}
```

---

## 4. SNMPv2c Bulk Retrieval, Zero-Heap Notification Prepending & Exact `u32` PDU Fields (`rasn-snmp::v2`, `rasn-snmp::v2c`)

Demonstrates:
- Exact `rasn_snmp::v2::Pdu` field types: `pub request_id: i32`, `pub error_status: u32`, `pub error_index: u32`, `pub variable_bindings: VarBindList` (with `v2::Pdu::ERROR_STATUS_*` constants `0..=18` typed as `u32`).
- Zero-heap static OID construction (`ObjectIdentifier::from(Oid::const_new(...))`) when prepending `sysUpTime.0` (`1.3.6.1.2.1.1.3.0`) at index 0 and `snmpTrapOID.0` (`1.3.6.1.6.3.1.1.4.1.0`) at index 1 for both `Trap` (`0xa7`) and `InformRequest` (`0xa6`).
- `GetBulkRequest` (`0xa5`) using `snmpv2::BulkPdu` (`request_id: i32`, `non_repeaters: u32`, `max_repetitions: u32`).

```rust
//! Pattern 4: SNMPv2c Trap/Inform notification prepending and GetBulkRequest encoding.

use rasn::types::{Integer, ObjectIdentifier, OctetString, Oid};
use rasn_smi::v1 as smiv1;
use rasn_smi::v2 as smiv2;
use rasn_snmp::v2 as snmpv2;
use rasn_snmp::v2c as snmpv2c;

/// Prepends `sysUpTime.0` and `snmpTrapOID.0` ahead of `user_varbinds` per RFC 3416 using `Oid::const_new`.
pub fn build_notification_varbinds(
    sys_up_time: u32,
    trap_oid: ObjectIdentifier,
    user_varbinds: Vec<snmpv2::VarBind>,
) -> Vec<snmpv2::VarBind> {
    let sys_up_time_oid = ObjectIdentifier::from(Oid::const_new(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));
    let snmp_trap_oid = ObjectIdentifier::from(Oid::const_new(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]));

    let mut vbs = Vec::with_capacity(2 + user_varbinds.len());
    vbs.push(snmpv2::VarBind {
        name: sys_up_time_oid,
        value: snmpv2::VarBindValue::Value(smiv2::ObjectSyntax::ApplicationWide(
            smiv2::ApplicationSyntax::Ticks(smiv1::TimeTicks(sys_up_time)),
        )),
    });
    vbs.push(snmpv2::VarBind {
        name: snmp_trap_oid,
        value: snmpv2::VarBindValue::Value(smiv2::ObjectSyntax::Simple(
            smiv2::SimpleSyntax::ObjectId(trap_oid),
        )),
    });
    vbs.extend(user_varbinds);
    vbs
}

/// Builds and BER-encodes an SNMPv2c `InformRequest` (`0xa6`) or `Trap` (`0xa7`) message.
pub fn build_snmpv2c_notification(
    community: &str,
    request_id: i32,
    error_status: u32,
    error_index: u32,
    is_inform: bool,
    sys_up_time: u32,
    trap_oid: ObjectIdentifier,
    user_varbinds: Vec<snmpv2::VarBind>,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let pdu = snmpv2::Pdu {
        request_id,
        error_status, // u32 (e.g. snmpv2::Pdu::ERROR_STATUS_NO_ERROR = 0u32)
        error_index,  // u32
        variable_bindings: build_notification_varbinds(sys_up_time, trap_oid, user_varbinds),
    };

    let data = if is_inform {
        snmpv2::Pdus::InformRequest(snmpv2::InformRequest(pdu))
    } else {
        snmpv2::Pdus::Trap(snmpv2::Trap(pdu))
    };

    let msg = snmpv2c::Message {
        version: Integer::from(snmpv2c::Message::<()>::VERSION),
        community: if community == "public" {
            OctetString::from_static(b"public")
        } else {
            OctetString::from(community.as_bytes().to_vec())
        },
        data,
    };

    rasn::ber::encode(&msg)
}

/// Builds and BER-encodes an SNMPv2c `GetBulkRequest` (`0xa5`) message.
pub fn build_snmpv2c_getbulk(
    community: &str,
    request_id: i32,
    non_repeaters: u32,
    max_repetitions: u32,
    query_oids: Vec<ObjectIdentifier>,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let variable_bindings = query_oids
        .into_iter()
        .map(|name| snmpv2::VarBind {
            name,
            value: snmpv2::VarBindValue::Unspecified,
        })
        .collect();

    let bulk = snmpv2::BulkPdu {
        request_id,
        non_repeaters,
        max_repetitions,
        variable_bindings,
    };

    let msg = snmpv2c::Message {
        version: Integer::from(1),
        community: OctetString::from(community.as_bytes().to_vec()),
        data: snmpv2::Pdus::GetBulkRequest(snmpv2::GetBulkRequest(bulk)),
    };

    rasn::ber::encode(&msg)
}
```

---

## 5. SNMPv3 Scoped PDU, Two-Stage USM Serialization & DES-CBC `NoPadding` BER Decryption (`rasn-snmp::v3`)

Demonstrates:
1. **Password & Security Level Validation**: Rejects empty passwords (`""`) to prevent division-by-zero in the 1MB key localization loop, and rejects `noAuthPriv` (`0x02`).
2. **Pre-Sized Zero MAC Placeholder & `encode_security_parameters`**: Populates `USMSecurityParameters.authentication_parameters` with `vec![0u8; auth_len]` (`12`/`24`/`32`/`48`) before the first BER encode and uses `message.encode_security_parameters(rasn::Codec::Ber, &usm_params)` / `message.decode_security_parameters::<snmpv3::USMSecurityParameters>(rasn::Codec::Ber)`.
3. **DES-CBC `NoPadding` BER Decryption Invariant**: Encrypts with `ZeroPadding`, and decrypts with `NoPadding` before calling `rasn::ber::decode::<snmpv3::ScopedPdu>` so that an 8-byte-aligned `ScopedPdu` ending in `0x00` (`INT 0` or `NULLVAL`) never has its trailing BER byte stripped!

```rust
//! Pattern 5: End-to-end SNMPv3 USM key localization, encryption, signing, and NoPadding BER decryption.

use aes::Aes128;
use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
    block_padding::{NoPadding, ZeroPadding},
};
use des::Des;
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use rasn::types::{Integer, OctetString};
use rasn_snmp::v2 as snmpv2;
use rasn_snmp::v3 as snmpv3;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Supported SNMPv3 USM authentication algorithms (RFC 3414 & RFC 7860).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsmAuthProtocol {
    /// HMAC-MD5-96 (12-byte wire tag).
    Md5,
    /// HMAC-SHA-96 (12-byte wire tag).
    Sha1,
    /// HMAC-192-SHA-256 (24-byte wire tag, RFC 7860).
    Sha256,
    /// HMAC-256-SHA-384 (32-byte wire tag, RFC 7860).
    Sha384,
    /// HMAC-384-SHA-512 (48-byte wire tag, RFC 7860).
    Sha512,
}

impl UsmAuthProtocol {
    /// Returns the truncated wire MAC length in octets per RFC 3414 / RFC 7860.
    pub const fn wire_mac_len(self) -> usize {
        match self {
            Self::Md5 | Self::Sha1 => 12,
            Self::Sha256 => 24,
            Self::Sha384 => 32,
            Self::Sha512 => 48,
        }
    }
}

/// Supported SNMPv3 USM privacy algorithms (RFC 3414 & RFC 3826).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsmPrivProtocol {
    /// DES-CBC with RFC 3414 §8.1.1.2 ZeroPadding on encrypt and NoPadding on BER decrypt.
    Des,
    /// AES-128-CFB stream cipher (RFC 3826).
    Aes128,
}

/// Derives a localized USM key (`Kul`) over 1,048,576 bytes of repeated password per RFC 3414 A.2.1.
pub fn localize_usm_key<D: Digest + Default>(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let mut hasher = D::default();
    let mut buf = [0u8; 64];
    let mut cp = 0;
    let mut pw_idx = 0;
    while cp < 1_048_576 {
        for slot in &mut buf {
            *slot = password[pw_idx % password.len()];
            pw_idx += 1;
        }
        hasher.update(buf);
        cp += 64;
    }
    let ku = hasher.finalize();

    let mut hasher2 = D::default();
    hasher2.update(&ku);
    hasher2.update(engine_id);
    hasher2.update(&ku);
    hasher2.finalize().to_vec()
}

/// Dispatches key localization for the selected `UsmAuthProtocol`.
pub fn derive_localized_key(
    proto: UsmAuthProtocol,
    password: &[u8],
    engine_id: &[u8],
) -> Vec<u8> {
    match proto {
        UsmAuthProtocol::Md5 => localize_usm_key::<Md5>(password, engine_id),
        UsmAuthProtocol::Sha1 => localize_usm_key::<Sha1>(password, engine_id),
        UsmAuthProtocol::Sha256 => localize_usm_key::<Sha256>(password, engine_id),
        UsmAuthProtocol::Sha384 => localize_usm_key::<Sha384>(password, engine_id),
        UsmAuthProtocol::Sha512 => localize_usm_key::<Sha512>(password, engine_id),
    }
}

/// Computes the truncated USM HMAC tag over a BER-encoded SNMPv3 message.
pub fn compute_usm_mac(proto: UsmAuthProtocol, auth_key: &[u8], whole_msg: &[u8]) -> Vec<u8> {
    macro_rules! sign_trunc {
        ($digest:ty, $len:expr) => {{
            let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice(auth_key)
                .expect("HMAC accepts keys of any length");
            mac.update(whole_msg);
            mac.finalize().into_bytes()[..$len].to_vec()
        }};
    }
    match proto {
        UsmAuthProtocol::Md5 => sign_trunc!(Md5, 12),
        UsmAuthProtocol::Sha1 => sign_trunc!(Sha1, 12),
        UsmAuthProtocol::Sha256 => sign_trunc!(Sha256, 24),
        UsmAuthProtocol::Sha384 => sign_trunc!(Sha384, 32),
        UsmAuthProtocol::Sha512 => sign_trunc!(Sha512, 48),
    }
}

/// Encrypts a BER-encoded `ScopedPdu` using RFC 3414 DES-CBC (`ZeroPadding`) or RFC 3826 AES-128-CFB.
pub fn encrypt_scoped_pdu(
    priv_proto: UsmPrivProtocol,
    priv_key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt: &[u8; 8],
    plaintext_scoped_pdu: &[u8],
) -> Result<Vec<u8>, String> {
    if priv_key.len() < 16 {
        return Err("Localized privacy key must be at least 16 bytes".to_string());
    }
    match priv_proto {
        UsmPrivProtocol::Des => {
            let des_key = &priv_key[0..8];
            let pre_iv = &priv_key[8..16];
            let mut iv = [0u8; 8];
            for i in 0..8 {
                iv[i] = pre_iv[i] ^ salt[i];
            }
            let enc = cbc::Encryptor::<Des>::new_from_slices(des_key, &iv)
                .map_err(|_| "Invalid DES key/IV length")?;
            let pad_len = if plaintext_scoped_pdu.len().is_multiple_of(8) {
                0
            } else {
                8 - (plaintext_scoped_pdu.len() % 8)
            };
            let mut buf = vec![0u8; plaintext_scoped_pdu.len() + pad_len];
            buf[..plaintext_scoped_pdu.len()].copy_from_slice(plaintext_scoped_pdu);
            let res = enc
                .encrypt_padded::<ZeroPadding>(&mut buf, plaintext_scoped_pdu.len())
                .map_err(|_| "DES ZeroPadding failed")?;
            Ok(res.to_vec())
        }
        UsmPrivProtocol::Aes128 => {
            let aes_key = &priv_key[0..16];
            let mut iv = [0u8; 16];
            iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
            iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
            iv[8..16].copy_from_slice(salt);
            let enc = cfb_mode::Encryptor::<Aes128>::new_from_slices(aes_key, &iv)
                .map_err(|_| "Invalid AES key/IV length")?;
            let mut out = plaintext_scoped_pdu.to_vec();
            enc.encrypt(&mut out);
            Ok(out)
        }
    }
}

/// Decrypts an encrypted `ScopedPdu` and BER-decodes it, using `NoPadding` for DES-CBC
/// so trailing `0x00` bytes inside an 8-byte-aligned BER `ScopedPdu` are never stripped.
pub fn decrypt_and_decode_scoped_pdu(
    priv_proto: UsmPrivProtocol,
    priv_key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt: &[u8; 8],
    ciphertext: &[u8],
) -> Result<snmpv3::ScopedPdu, String> {
    if priv_key.len() < 16 {
        return Err("Localized privacy key must be at least 16 bytes".to_string());
    }
    let mut buf = ciphertext.to_vec();
    match priv_proto {
        UsmPrivProtocol::Des => {
            let des_key = &priv_key[0..8];
            let pre_iv = &priv_key[8..16];
            let mut iv = [0u8; 8];
            for i in 0..8 {
                iv[i] = pre_iv[i] ^ salt[i];
            }
            let dec = cbc::Decryptor::<Des>::new_from_slices(des_key, &iv)
                .map_err(|_| "Invalid DES key/IV length")?;
            let raw_pt = dec
                .decrypt_padded::<NoPadding>(&mut buf)
                .map_err(|_| "DES-CBC NoPadding block decryption failed")?;
            rasn::ber::decode(raw_pt).map_err(|e| format!("ScopedPdu BER decode error: {e:?}"))
        }
        UsmPrivProtocol::Aes128 => {
            let aes_key = &priv_key[0..16];
            let mut iv = [0u8; 16];
            iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
            iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
            iv[8..16].copy_from_slice(salt);
            let dec = cfb_mode::Decryptor::<Aes128>::new_from_slices(aes_key, &iv)
                .map_err(|_| "Invalid AES key/IV length")?;
            dec.decrypt(&mut buf);
            rasn::ber::decode(&buf).map_err(|e| format!("ScopedPdu BER decode error: {e:?}"))
        }
    }
}

/// Builds and BER-encodes a complete SNMPv3 message supporting `noAuthNoPriv`, `authNoPriv`, and `authPriv`.
#[allow(clippy::too_many_arguments)]
pub fn build_snmpv3_usm_packet(
    msg_id: i32,
    is_confirmed_pdu: bool,
    engine_id: &[u8],
    engine_boots: u32,
    engine_time: u32,
    context_name: &str,
    user_name: &str,
    auth: Option<(UsmAuthProtocol, &[u8])>,
    priv_cfg: Option<(UsmPrivProtocol, &[u8])>,
    salt: [u8; 8],
    pdu: snmpv2::Pdus,
) -> Result<Vec<u8>, String> {
    if auth.is_none() && priv_cfg.is_some() {
        return Err("RFC 3412 §6.4 forbids privacy without authentication (noAuthPriv)".to_string());
    }
    if let Some((_, pw)) = auth
        && pw.is_empty()
    {
        return Err("SNMPv3 authentication password cannot be empty".to_string());
    }
    if let Some((_, pw)) = priv_cfg
        && pw.is_empty()
    {
        return Err("SNMPv3 privacy password cannot be empty".to_string());
    }

    let mut flags = 0u8;
    if auth.is_some() {
        flags |= 0x01; // authFlag
    }
    if priv_cfg.is_some() {
        flags |= 0x02; // privFlag
    }
    if is_confirmed_pdu {
        flags |= 0x04; // reportableFlag
    }

    let scoped_pdu = snmpv3::ScopedPdu {
        engine_id: OctetString::from(engine_id.to_vec()),
        name: OctetString::from(context_name.as_bytes().to_vec()),
        data: pdu,
    };

    let scoped_data = if let Some((priv_proto, priv_pw)) = priv_cfg {
        let (auth_proto, _) = auth.expect("Validated auth is present when priv is present");
        let priv_key = derive_localized_key(auth_proto, priv_pw, engine_id);
        let plaintext = rasn::ber::encode(&scoped_pdu)
            .map_err(|e| format!("ScopedPdu BER encode error: {e:?}"))?;
        let ciphertext = encrypt_scoped_pdu(
            priv_proto,
            &priv_key,
            engine_boots,
            engine_time,
            &salt,
            &plaintext,
        )?;
        snmpv3::ScopedPduData::EncryptedPdu(OctetString::from(ciphertext))
    } else {
        snmpv3::ScopedPduData::CleartextPdu(scoped_pdu)
    };

    let auth_len = auth.map(|(p, _)| p.wire_mac_len()).unwrap_or(0);
    let mut usm_params = snmpv3::USMSecurityParameters {
        authoritative_engine_id: OctetString::from(engine_id.to_vec()),
        authoritative_engine_boots: Integer::from(engine_boots),
        authoritative_engine_time: Integer::from(engine_time),
        user_name: OctetString::from(user_name.as_bytes().to_vec()),
        authentication_parameters: OctetString::from(vec![0u8; auth_len]),
        privacy_parameters: OctetString::from(if priv_cfg.is_some() {
            salt.to_vec()
        } else {
            Vec::new()
        }),
    };

    let mut message = snmpv3::Message {
        version: Integer::from(3),
        global_data: snmpv3::HeaderData {
            message_id: Integer::from(msg_id),
            max_size: Integer::from(65507),
            flags: OctetString::from(vec![flags]),
            security_model: Integer::from(3),
        },
        security_parameters: OctetString::default(),
        scoped_data,
    };
    message
        .encode_security_parameters(rasn::Codec::Ber, &usm_params)
        .map_err(|e| format!("USMSecurityParameters BER encode error: {e:?}"))?;

    if let Some((auth_proto, auth_pw)) = auth {
        let auth_key = derive_localized_key(auth_proto, auth_pw, engine_id);
        let pre_auth_wire = rasn::ber::encode(&message)
            .map_err(|e| format!("Pre-auth Message BER encode error: {e:?}"))?;
        let mac = compute_usm_mac(auth_proto, &auth_key, &pre_auth_wire);
        usm_params.authentication_parameters = OctetString::from(mac);
        message
            .encode_security_parameters(rasn::Codec::Ber, &usm_params)
            .map_err(|e| format!("Signed USM BER encode error: {e:?}"))?;
    }

    rasn::ber::encode(&message).map_err(|e| format!("Final SNMPv3 BER encode error: {e:?}"))
}
```

---

## 6. RFC 4511 LDAPv3 BER & RFC 4120 Kerberos v5 DER Wire Verification Schemas (`#[derive(AsnType, Encode, Decode)]`)

### Builder Audit Findings (`src/builders/l7/ldap.rs` & `src/builders/l7/kerberos.rs`)
1. **`src/builders/l7/ldap.rs`**:
   - `build_ldap_payload` currently branches only on `if spec.is_search_req` (`0x63`) vs. default `BindRequest` (`0x60`), ignoring `spec.is_bind_res`, `spec.is_search_entry`, `spec.is_search_done`, `spec.is_unbind_req`, `spec.filter`, and `spec.result_code`.
   - When `spec.is_search_req` is `true`, `build_ldap_payload` emits only 3 of the 8 mandatory RFC 4511 §4.5.1 `SearchRequest` fields (`baseObject`, `scope`, `derefAliases`), omitting `sizeLimit`, `timeLimit`, `typesOnly`, `filter`, and `attributes`. Consequently, strict RFC 4511 `SearchRequest` decoders will reject the truncated 3-field sequence unless the remaining 5 fields are appended.
2. **`src/builders/l7/kerberos.rs`**:
   - `build_kerberos_payload` currently emits raw ASCII `b"KRB5_AS_REQ:<realm>:<cname>"` inside `[APPLICATION 10]` (`0x6A`) instead of an RFC 4120 §5.4.1 DER `SEQUENCE` containing explicit context tags `[1] pvno (5)`, `[2] msg-type (10)`, `[3] padata OPTIONAL`, and `[4] req-body KDC-REQ-BODY` (which requires `[0] kdc-options`, `[2] realm`, `[7] till`, `[8] nonce`, and `[9] etype`).

Use the production `#[derive(AsnType, Encode, Decode)]` schemas below to encode and verify canonical RFC 4511 LDAPv3 BER and RFC 4120 Kerberos v5 DER wire frames:

```rust
//! Pattern 6: Production RFC 4511 LDAPv3 (BER) and RFC 4120 Kerberos v5 (DER) verification schemas.

use rasn::prelude::*;
use rasn::types::{GeneralString, GeneralizedTime, Integer, OctetString};

// ============================================================================
// Part A: RFC 4511 LDAPv3 ASN.1 BER Schema
// ============================================================================

/// RFC 4511 §4.1.1.1 `MessageID ::= INTEGER (0 .. maxInt)` (`maxInt = 2147483647`).
#[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq)]
#[rasn(delegate, value("0..=2147483647"))]
pub struct LdapMessageId(pub u32);

/// RFC 4511 §4.1.9 `LDAPResult` status codes.
#[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq)]
#[rasn(enumerated)]
pub enum LdapResultCode {
    /// Operation succeeded (0).
    Success = 0,
    /// Internal server error (1).
    OperationsError = 1,
    /// Protocol violation (2).
    ProtocolError = 2,
    /// Invalid credentials during Bind (49).
    InvalidCredentials = 49,
}

/// RFC 4511 §4.2 `AuthenticationChoice` inside `BindRequest`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(choice)]
pub enum LdapAuthChoice {
    /// Context-specific primitive tag 0 (`0x80`): cleartext simple password.
    #[rasn(tag(context, 0))]
    Simple(OctetString),
}

/// RFC 4511 §4.2 `BindRequest ::= [APPLICATION 0] SEQUENCE { version, name, authentication }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(tag(application, 0))]
pub struct LdapBindRequest {
    /// Protocol version (`1..=127`, always `3` for LDAPv3).
    #[rasn(value("1..=127"))]
    pub version: u8,
    /// Bind DN (`LDAPDN`).
    pub name: OctetString,
    /// Authentication credentials.
    pub authentication: LdapAuthChoice,
}

/// RFC 4511 §4.2.2 `BindResponse ::= [APPLICATION 1] SEQUENCE { COMPONENTS OF LDAPResult, ... }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(tag(application, 1))]
pub struct LdapBindResponse {
    /// Result code (`ENUMERATED`).
    pub result_code: LdapResultCode,
    /// Matched DN (`LDAPDN`).
    pub matched_dn: OctetString,
    /// Diagnostic message (`LDAPString`).
    pub diagnostic_message: OctetString,
}

/// RFC 4511 §4.5.1.2 `SearchRequest.scope` (`ENUMERATED`).
#[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq)]
#[rasn(enumerated)]
pub enum LdapSearchScope {
    /// Base object only (0).
    BaseObject = 0,
    /// Single level under base (1).
    SingleLevel = 1,
    /// Whole subtree rooted at base (2).
    WholeSubtree = 2,
}

/// RFC 4511 §4.5.1.3 `SearchRequest.derefAliases` (`ENUMERATED`).
#[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq)]
#[rasn(enumerated)]
pub enum LdapDerefAliases {
    /// Never dereference aliases (0).
    NeverDerefAliases = 0,
    /// Dereference while searching (1).
    DerefInSearching = 1,
    /// Dereference finding base object (2).
    DerefFindingBaseObj = 2,
    /// Always dereference (3).
    DerefAlways = 3,
}

/// RFC 4511 §4.5.1.7 `Filter ::= CHOICE { ..., present [7] AttributeDescription, ... }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(choice)]
pub enum LdapFilter {
    /// Equality match `[3] AttributeValueAssertion`.
    #[rasn(tag(context, 3))]
    EqualityMatch {
        /// Attribute description (e.g., `b"cn"`).
        attribute_desc: OctetString,
        /// Assertion value (e.g., `b"admin"`).
        assertion_value: OctetString,
    },
    /// Presence match `[7] AttributeDescription` (`0x87`, e.g., `b"objectClass"` for `(objectClass=*)`).
    #[rasn(tag(context, 7))]
    Present(OctetString),
}

/// Full 8-field RFC 4511 §4.5.1 `SearchRequest ::= [APPLICATION 3] SEQUENCE`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(tag(application, 3))]
pub struct LdapSearchRequest {
    /// 1. `baseObject LDAPDN`.
    pub base_object: OctetString,
    /// 2. `scope ENUMERATED`.
    pub scope: LdapSearchScope,
    /// 3. `derefAliases ENUMERATED`.
    pub deref_aliases: LdapDerefAliases,
    /// 4. `sizeLimit INTEGER (0 .. maxInt)`.
    pub size_limit: u32,
    /// 5. `timeLimit INTEGER (0 .. maxInt)`.
    pub time_limit: u32,
    /// 6. `typesOnly BOOLEAN`.
    pub types_only: bool,
    /// 7. `filter Filter`.
    pub filter: LdapFilter,
    /// 8. `attributes AttributeSelection (SEQUENCE OF LDAPString)`.
    pub attributes: Vec<OctetString>,
}

/// RFC 4511 §4.5.2 `PartialAttribute ::= SEQUENCE { type, vals SET OF AttributeValue }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
pub struct LdapPartialAttribute {
    /// Attribute type name.
    pub attr_type: OctetString,
    /// Attribute values (`SET OF OCTET STRING`).
    pub vals: SetOf<OctetString>,
}

/// RFC 4511 §4.5.2 `SearchResultEntry ::= [APPLICATION 4] SEQUENCE { objectName, attributes }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(tag(application, 4))]
pub struct LdapSearchResultEntry {
    /// Entry DN (`LDAPDN`).
    pub object_name: OctetString,
    /// Entry attributes.
    pub attributes: Vec<LdapPartialAttribute>,
}

/// RFC 4511 §4.5.2 `SearchResultDone ::= [APPLICATION 5] LDAPResult`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(tag(application, 5))]
pub struct LdapSearchResultDone {
    /// Result code (`ENUMERATED`).
    pub result_code: LdapResultCode,
    /// Matched DN (`LDAPDN`).
    pub matched_dn: OctetString,
    /// Diagnostic message (`LDAPString`).
    pub diagnostic_message: OctetString,
}

/// RFC 4511 §4.3 `UnbindRequest ::= [APPLICATION 2] NULL` (`0x42 0x00`).
#[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq)]
#[rasn(delegate, tag(application, 2))]
pub struct LdapUnbindRequest(pub ());

/// RFC 4511 §4.1.1 `LDAPMessage.protocolOp` `CHOICE`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(choice)]
pub enum LdapProtocolOp {
    /// `[APPLICATION 0]` (`0x60`) `BindRequest`.
    BindRequest(LdapBindRequest),
    /// `[APPLICATION 1]` (`0x61`) `BindResponse`.
    BindResponse(LdapBindResponse),
    /// `[APPLICATION 2]` (`0x42`) `UnbindRequest`.
    UnbindRequest(LdapUnbindRequest),
    /// `[APPLICATION 3]` (`0x63`) `SearchRequest`.
    SearchRequest(LdapSearchRequest),
    /// `[APPLICATION 4]` (`0x64`) `SearchResultEntry`.
    SearchResEntry(LdapSearchResultEntry),
    /// `[APPLICATION 5]` (`0x65`) `SearchResultDone`.
    SearchResDone(LdapSearchResultDone),
}

/// RFC 4511 §4.1.1 top-level `LDAPMessage ::= SEQUENCE { messageID, protocolOp, controls }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
pub struct LdapMessage {
    /// Unique non-negative request/response correlation identifier.
    pub message_id: LdapMessageId,
    /// Protocol operation choice.
    pub protocol_op: LdapProtocolOp,
}

/// Decodes an RFC 4511 `LDAPMessage` from BER wire bytes and asserts zero trailing bytes.
pub fn verify_ldap_ber_frame(wire: &[u8]) -> Result<LdapMessage, String> {
    let (msg, remainder) = rasn::ber::decode_with_remainder::<LdapMessage>(wire)
        .map_err(|e| format!("LDAP BER decode error: {e:?}"))?;
    if !remainder.is_empty() {
        return Err(format!("Trailing unconsumed LDAP bytes: {}B", remainder.len()));
    }
    Ok(msg)
}

// ============================================================================
// Part B: RFC 4120 Kerberos v5 ASN.1 DER Schema
// ============================================================================

/// RFC 4120 §5.2.2 `PrincipalName ::= SEQUENCE { [0] name-type Int32, [1] name-string SEQUENCE OF KerberosString }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
pub struct KerberosPrincipalName {
    /// Explicit tag `[0] Int32` (`NT-PRINCIPAL = 1`, `NT-SRV-INST = 2`).
    #[rasn(tag(explicit(context, 0)))]
    pub name_type: i32,
    /// Explicit tag `[1] SEQUENCE OF GeneralString`.
    #[rasn(tag(explicit(context, 1)))]
    pub name_string: Vec<GeneralString>,
}

/// RFC 4120 §5.2.7 `PA-DATA ::= SEQUENCE { [1] padata-type Int32, [2] padata-value OCTET STRING }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
pub struct KerberosPaData {
    /// Explicit tag `[1] Int32`.
    #[rasn(tag(explicit(context, 1)))]
    pub padata_type: i32,
    /// Explicit tag `[2] OCTET STRING`.
    #[rasn(tag(explicit(context, 2)))]
    pub padata_value: OctetString,
}

/// RFC 4120 §5.4.1 `KDC-REQ-BODY ::= SEQUENCE` with mandatory explicit tags `[0]`, `[2]`, `[7]`, `[8]`, `[9]`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
pub struct KerberosKdcReqBody {
    /// `[0] kdc-options KerberosFlags` (minimum 32-bit `BIT STRING`).
    #[rasn(tag(explicit(context, 0)))]
    pub kdc_options: BitString,
    /// `[1] cname PrincipalName OPTIONAL`.
    #[rasn(tag(explicit(context, 1)))]
    pub cname: Option<KerberosPrincipalName>,
    /// `[2] realm Realm` (`GeneralString`).
    #[rasn(tag(explicit(context, 2)))]
    pub realm: GeneralString,
    /// `[3] sname PrincipalName OPTIONAL`.
    #[rasn(tag(explicit(context, 3)))]
    pub sname: Option<KerberosPrincipalName>,
    /// `[7] till KerberosTime` (`GeneralizedTime`, e.g., `"20370913024805Z"`).
    #[rasn(tag(explicit(context, 7)))]
    pub till: GeneralizedTime,
    /// `[8] nonce UInt32`.
    #[rasn(tag(explicit(context, 8)))]
    pub nonce: u32,
    /// `[9] etype SEQUENCE OF Int32` (e.g., `vec![18, 17]` for AES256/AES128-CTS-HMAC-SHA1-96).
    #[rasn(tag(explicit(context, 9)))]
    pub etype: Vec<i32>,
}

/// RFC 4120 §5.4.1 `KDC-REQ ::= SEQUENCE { [1] pvno (5), [2] msg-type, [3] padata OPTIONAL, [4] req-body }`.
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
pub struct KerberosKdcReq {
    /// `[1] pvno INTEGER (5)`.
    #[rasn(tag(explicit(context, 1)))]
    pub pvno: Integer,
    /// `[2] msg-type INTEGER (10 -- AS-REQ, 12 -- TGS-REQ)`.
    #[rasn(tag(explicit(context, 2)))]
    pub msg_type: Integer,
    /// `[3] padata SEQUENCE OF PA-DATA OPTIONAL`.
    #[rasn(tag(explicit(context, 3)))]
    pub padata: Option<Vec<KerberosPaData>>,
    /// `[4] req-body KDC-REQ-BODY`.
    #[rasn(tag(explicit(context, 4)))]
    pub req_body: KerberosKdcReqBody,
}

/// RFC 4120 §5.4.1 `AS-REQ ::= [APPLICATION 10] KDC-REQ` (`0x6A` explicit wrapper around `KDC-REQ` `SEQUENCE`).
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
#[rasn(delegate, tag(explicit(application, 10)))]
pub struct KerberosAsReq(pub KerberosKdcReq);

/// Decodes an RFC 4120 `AS-REQ` (`[APPLICATION 10]`) from DER wire bytes and asserts zero trailing bytes.
pub fn verify_kerberos_as_req_der(wire: &[u8]) -> Result<KerberosAsReq, String> {
    let (as_req, remainder) = rasn::der::decode_with_remainder::<KerberosAsReq>(wire)
        .map_err(|e| format!("Kerberos AS-REQ DER decode error: {e:?}"))?;
    if !remainder.is_empty() {
        return Err(format!(
            "Trailing unconsumed Kerberos DER bytes: {}B",
            remainder.len()
        ));
    }
    Ok(as_req)
}
```
