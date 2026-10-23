//! BACNET protocol AST definitions.

use core::marker::PhantomData;

/// ANSI/ASHRAE 135 BACnet Building Automation specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BacnetSpec<'a> {
    /// Who-Is service flag.
    pub is_who_is: bool,
    /// I-Am service flag.
    pub is_i_am: bool,
    /// ReadProperty service flag.
    pub is_read_property: bool,
    /// WriteProperty service flag.
    pub is_write_property: bool,
    /// Invoke ID.
    pub invoke_id: Option<u8>,
    /// Object Type code.
    pub object_type: Option<u16>,
    /// Object Instance number.
    pub object_instance: Option<u32>,
    /// Property Identifier code.
    pub property_id: Option<u32>,
    /// Value.
    pub value: Option<u32>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
