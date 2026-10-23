//! S7COMM protocol AST definitions.


/// Siemens S7 Communication specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S7commSpec<'a> {
    /// ROSCTR message type name.
    pub rosctr: Option<&'a str>,
    /// PDU Reference.
    pub pdu_ref: Option<u16>,
    /// Function name.
    pub func: Option<&'a str>,
    /// Memory area code.
    pub area: Option<u8>,
    /// Data block number.
    pub db_num: Option<u16>,
    /// Memory address offset.
    pub offset: Option<u32>,
}
