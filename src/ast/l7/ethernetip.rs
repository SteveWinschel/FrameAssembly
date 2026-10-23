//! ETHERNETIP protocol AST definitions.

/// ODVA EtherNet/IP & CIP Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthernetipSpec<'a> {
    /// Encapsulation command name.
    pub cmd: Option<&'a str>,
    /// Session handle.
    pub session_handle: Option<u32>,
    /// Status code.
    pub status: Option<u32>,
    /// Sender context.
    pub context: Option<u64>,
    /// CIP Service code.
    pub cip_service: Option<u8>,
    /// CIP Class code.
    pub cip_class: Option<u16>,
    /// CIP Instance code.
    pub cip_instance: Option<u16>,
    /// CIP Attribute code.
    pub cip_attr: Option<u16>,
}
