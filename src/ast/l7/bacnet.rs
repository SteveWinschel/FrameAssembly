//! Building Automation and Control Networks (BACnet/IP, ANSI/ASHRAE 135) AST definitions.
//!
//! This module defines [`BacnetSpec`], the zero-copy AST representation of an ANSI/ASHRAE 135
//! BACnet/IP frame over UDP port 47808 (`0xBAC0`). On the wire, a BACnet/IP packet consists of a
//! 4-byte BACnet Virtual Link Control (BVLC) header (`0x81` type, function `0x0A` Original-Unicast
//! or `0x0B` Original-Broadcast, and 16-bit length), a 2-byte NPDU header (Version `0x01` and
//! control byte), and an APDU encoding unconfirmed services (`Who-Is`, `I-Am`) or confirmed
//! services (`ReadProperty` `0x0C`, `WriteProperty` `0x0F`). Canonical `.fasm` syntax:
//! `BACNET [WHO_IS | I_AM | READ_PROPERTY | WRITE_PROPERTY] [INVOKE_ID <u8>] [OBJECT_TYPE <u16>] [OBJECT_INSTANCE <u32>] [PROPERTY_ID <u32>] [VALUE <u32>]`.

use core::marker::PhantomData;

/// ANSI/ASHRAE 135 BACnet/IP Building Automation protocol specification.
///
/// Syntax mapping: `BACNET [WHO_IS | I_AM | READ_PROPERTY | WRITE_PROPERTY] [INVOKE_ID <u8>] [OBJECT_TYPE <u16>] [OBJECT_INSTANCE <u32>] [PROPERTY_ID <u32>] [VALUE <u32>]`
#[doc(alias = "BACNET")]
#[doc(alias = "ASHRAE 135")]
#[doc(alias = "ISO 16484-5")]
#[doc(alias = "BVLC")]
#[doc(alias = "47808")]
#[doc(alias = "WHO_IS")]
#[doc(alias = "I_AM")]
#[doc(alias = "READ_PROPERTY")]
#[doc(alias = "WRITE_PROPERTY")]
#[doc(alias = "INVOKE_ID")]
#[doc(alias = "OBJECT_TYPE")]
#[doc(alias = "OBJECT_INSTANCE")]
#[doc(alias = "PROPERTY_ID")]
#[doc(alias = "VALUE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BacnetSpec<'a> {
    /// Unconfirmed `Who-Is` (service choice 8) broadcast discovery flag (`WHO_IS`).
    pub is_who_is: bool,
    /// Unconfirmed `I-Am` (service choice 0) device announcement flag (`I_AM`).
    pub is_i_am: bool,
    /// Confirmed `ReadProperty` (service choice 12) flag (`READ_PROPERTY`).
    pub is_read_property: bool,
    /// Confirmed `WriteProperty` (service choice 15) flag (`WRITE_PROPERTY`).
    pub is_write_property: bool,
    /// 8-bit confirmed service Invoke ID (`INVOKE_ID <u8>`, default `1`).
    pub invoke_id: Option<u8>,
    /// 10-bit BACnet Object Type code (`OBJECT_TYPE <u16>`, e.g., `0` Analog Input, `8` Device).
    pub object_type: Option<u16>,
    /// 22-bit BACnet Object Instance number (`OBJECT_INSTANCE <u32>`, default `1`).
    pub object_instance: Option<u32>,
    /// BACnet Property Identifier (`PROPERTY_ID <u32>`, default `85` for `Present_Value`).
    pub property_id: Option<u32>,
    /// Property unsigned integer value for `WriteProperty` (`VALUE <u32>`).
    pub value: Option<u32>,
    /// Lifetime marker preserving uniform `'a` parameterization across L7 specs.
    pub _marker: PhantomData<&'a ()>,
}
