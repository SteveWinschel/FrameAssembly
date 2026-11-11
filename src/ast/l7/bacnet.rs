//! Building Automation and Control Networks (BACnet/IP, ANSI/ASHRAE 135) AST definitions.
//!
//! This module defines [`BacnetSpec`], the zero-copy AST representation of an ANSI/ASHRAE 135
//! BACnet/IP frame over UDP port 47808 (`0xBAC0`). On the wire, a BACnet/IP packet consists of a
//! 4-byte BACnet Virtual Link Control (BVLC) header (`0x81` type, function `0x0A` Original-Unicast
//! or `0x0B` Original-Broadcast, and 16-bit length), a 2-byte NPDU header (Version `0x01` and
//! control byte), and an APDU encoding unconfirmed services (`Who-Is`, `I-Am`) or confirmed
//! services (`ReadProperty` `0x0C`, `WriteProperty` `0x0F`). Canonical `.fasm` syntax:
//! `bacnet [whois | iam | readproperty | writeproperty] [invokeid <u8>] [objecttype <u16>] [objectinstance <u32>] [propertyid <u32>] [value <u32>]`.

use core::marker::PhantomData;

/// ANSI/ASHRAE 135 BACnet/IP Building Automation protocol specification.
///
/// Syntax mapping: `bacnet [whois | iam | readproperty | writeproperty] [invokeid <u8>] [objecttype <u16>] [objectinstance <u32>] [propertyid <u32>] [value <u32>]`
#[doc(alias = "bacnet")]
#[doc(alias = "ASHRAE 135")]
#[doc(alias = "ISO 16484-5")]
#[doc(alias = "BVLC")]
#[doc(alias = "47808")]
#[doc(alias = "whois")]
#[doc(alias = "iam")]
#[doc(alias = "readproperty")]
#[doc(alias = "writeproperty")]
#[doc(alias = "invokeid")]
#[doc(alias = "objecttype")]
#[doc(alias = "objectinstance")]
#[doc(alias = "propertyid")]
#[doc(alias = "value")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BacnetSpec<'a> {
    /// Unconfirmed `Who-Is` (service choice 8) broadcast discovery flag (`whois`).
    pub is_who_is: bool,
    /// Unconfirmed `I-Am` (service choice 0) device announcement flag (`iam`).
    pub is_i_am: bool,
    /// Confirmed `ReadProperty` (service choice 12) flag (`readproperty`).
    pub is_read_property: bool,
    /// Confirmed `WriteProperty` (service choice 15) flag (`writeproperty`).
    pub is_write_property: bool,
    /// 8-bit confirmed service Invoke ID (`invokeid <u8>`, default `1`).
    pub invoke_id: Option<u8>,
    /// 10-bit BACnet Object Type code (`objecttype <u16>`, e.g., `0` Analog Input, `8` Device).
    pub object_type: Option<u16>,
    /// 22-bit BACnet Object Instance number (`objectinstance <u32>`, default `1`).
    pub object_instance: Option<u32>,
    /// BACnet Property Identifier (`propertyid <u32>`, default `85` for `Present_Value`).
    pub property_id: Option<u32>,
    /// Property unsigned integer value for `WriteProperty` (`value <u32>`).
    pub value: Option<u32>,
    /// Lifetime marker preserving uniform `'a` parameterization across L7 specs.
    pub _marker: PhantomData<&'a ()>,
}
