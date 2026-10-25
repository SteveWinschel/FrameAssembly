//! Modbus TCP Application Protocol v1.1b3 Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`ModbusSpec`], the zero-copy AST representation of a Modbus Application
//! Protocol (MBAP) frame over TCP or UDP port 502. On the wire, a Modbus TCP ADU begins with a
//! 7-byte MBAP header (16-bit Transaction ID, 16-bit Protocol ID `0x0000`, 16-bit Length, and
//! 8-bit Unit Identifier) followed by a 1-byte Function Code (`0x01` Read Coils, `0x02` Read
//! Discrete Inputs, `0x03` Read Holding Registers, `0x04` Read Input Registers, `0x05` Write
//! Single Coil, `0x06` Write Single Register, `0x10` Write Multiple Registers) and register data.
//! Canonical `.fasm` syntax:
//! `MODBUS [TXID <u16>] [PROTO_ID <u16>] [UNITID <u8>] [FUNC <str>] [ADDR <u16>] [COUNT <u16>] [VALUE <u16>] [IS_RESPONSE]`.

/// Modbus TCP Application Protocol v1.1b3 (MBAP + PDU) specification.
///
/// Syntax mapping: `MODBUS [TXID <u16>] [PROTO_ID <u16>] [UNITID <u8>] [FUNC <str>] [ADDR <u16>] [COUNT <u16>] [VALUE <u16>] [IS_RESPONSE]`
#[doc(alias = "MODBUS")]
#[doc(alias = "Modbus TCP")]
#[doc(alias = "MBAP")]
#[doc(alias = "502")]
#[doc(alias = "TXID")]
#[doc(alias = "PROTO_ID")]
#[doc(alias = "UNITID")]
#[doc(alias = "FUNC")]
#[doc(alias = "ADDR")]
#[doc(alias = "COUNT")]
#[doc(alias = "VALUE")]
#[doc(alias = "IS_RESPONSE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModbusSpec<'a> {
    /// 16-bit MBAP Transaction Identifier (`TXID <u16>`, default `1`).
    pub txid: Option<u16>,
    /// 16-bit MBAP Protocol Identifier (`PROTO_ID <u16>`, default `0`).
    pub proto_id: Option<u16>,
    /// 8-bit MBAP Unit Identifier addressing a slave device (`UNITID <u8>`, default `1`).
    pub unitid: Option<u8>,
    /// Modbus function code name (`FUNC <str>`, default `"READ_HOLDING_REGISTERS"`).
    pub func: Option<&'a str>,
    /// Starting 16-bit register or coil address (`ADDR <u16>`, default `0`).
    pub addr: Option<u16>,
    /// Quantity of registers or coils to read or write (`COUNT <u16>`, default `1`).
    pub count: Option<u16>,
    /// Register or coil value for write operations or read responses (`VALUE <u16>`, default `0`).
    pub value: Option<u16>,
    /// Response direction flag (`IS_RESPONSE`).
    pub is_response: bool,
}
