//! MODBUS protocol AST definitions.


/// Modbus Application Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModbusSpec<'a> {
    /// Transaction ID.
    pub txid: Option<u16>,
    /// Protocol ID.
    pub proto_id: Option<u16>,
    /// Unit ID.
    pub unitid: Option<u8>,
    /// Function code name.
    pub func: Option<&'a str>,
    /// Starting register/coil address.
    pub addr: Option<u16>,
    /// Quantity of registers or coils.
    pub count: Option<u16>,
    /// Register or coil value.
    pub value: Option<u16>,
    /// Response flag.
    pub is_response: bool,
}
