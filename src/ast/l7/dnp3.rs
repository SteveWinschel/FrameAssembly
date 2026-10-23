//! DNP3 protocol AST definitions.

/// IEEE 1815-2012 Distributed Network Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dnp3Spec<'a> {
    /// Function name.
    pub func: Option<&'a str>,
    /// Source address.
    pub src: Option<u16>,
    /// Destination address.
    pub dst: Option<u16>,
    /// Object group number.
    pub group: Option<u8>,
    /// Object variation number.
    pub variation: Option<u8>,
    /// CRC override.
    pub crc: Option<u16>,
}
