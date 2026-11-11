//! Modbus TCP Application Protocol v1.1b3 Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`ModbusSpec`], the zero-copy AST representation of a Modbus Application
//! Protocol (MBAP) frame over TCP or UDP port 502. On the wire, a Modbus TCP ADU begins with a
//! 7-byte MBAP header (16-bit Transaction ID, 16-bit Protocol ID `0x0000`, 16-bit Length, and
//! 8-bit Unit Identifier) followed by a 1-byte Function Code (`0x01` Read Coils, `0x02` Read
//! Discrete Inputs, `0x03` Read Holding Registers, `0x04` Read Input Registers, `0x05` Write
//! Single Coil, `0x06` Write Single Register, `0x10` Write Multiple Registers) and register data.
//! Canonical `.fasm` syntax:
//! `modbus [txid <u16>] [protoid <u16>] [unitid <u8>] [func <str>] [addr <u16>] [count <u16>] [value <u16>] [isresponse]`.

/// Modbus TCP Application Protocol v1.1b3 (MBAP + PDU) specification.
///
/// Syntax mapping: `modbus [txid <u16>] [protoid <u16>] [unitid <u8>] [func <str>] [addr <u16>] [count <u16>] [value <u16>] [isresponse]`
#[doc(alias = "modbus")]
#[doc(alias = "Modbus TCP")]
#[doc(alias = "MBAP")]
#[doc(alias = "502")]
#[doc(alias = "txid")]
#[doc(alias = "protoid")]
#[doc(alias = "unitid")]
#[doc(alias = "func")]
#[doc(alias = "addr")]
#[doc(alias = "count")]
#[doc(alias = "value")]
#[doc(alias = "isresponse")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModbusSpec<'a> {
    /// 16-bit MBAP Transaction Identifier (`txid <u16>`, default `1`).
    pub txid: Option<u16>,
    /// 16-bit MBAP Protocol Identifier (`protoid <u16>`, default `0`).
    pub proto_id: Option<u16>,
    /// 8-bit MBAP Unit Identifier addressing a slave device (`unitid <u8>`, default `1`).
    pub unitid: Option<u8>,
    /// Modbus function code name (`func <str>`, default `"READ_HOLDING_REGISTERS"`).
    pub func: Option<&'a str>,
    /// Starting 16-bit register or coil address (`addr <u16>`, default `0`).
    pub addr: Option<u16>,
    /// Quantity of registers or coils to read or write (`count <u16>`, default `1`).
    pub count: Option<u16>,
    /// Register or coil value for write operations or read responses (`value <u16>`, default `0`).
    pub value: Option<u16>,
    /// Response direction flag (`isresponse`).
    pub is_response: bool,
}
