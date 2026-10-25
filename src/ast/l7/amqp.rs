//! Advanced Message Queuing Protocol v0-9-1 (AMQP 0-9-1) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`AmqpSpec`], the zero-copy AST representation of an AMQP 0-9-1 wire frame
//! over TCP port 5672 (or 5671 for AMQPS). On the wire, a session begins with the 8-byte protocol
//! header `AMQP\x00\x00\x09\x01`, followed by general frames consisting of a 1-byte Frame Type
//! (`1` Method, `2` Content Header, `3` Content Body, `8` Heartbeat), a 16-bit Channel number, a
//! 32-bit Payload Size, the class/method arguments, and a trailing `0xCE` frame-end octet.
//! Canonical FrameAssembly `.fasm` syntax models AMQP frames via
//! `AMQP [PROTOCOL_HEADER | CONNECTION_START | CHANNEL_OPEN | BASIC_PUBLISH | BASIC_DELIVER | HEARTBEAT] [CHANNEL <u16>] [EXCHANGE <str>] [ROUTING_KEY <str>]`.

/// Advanced Message Queuing Protocol v0-9-1 (AMQP 0-9-1) specification.
///
/// Syntax mapping: `AMQP [PROTOCOL_HEADER | CONNECTION_START | CHANNEL_OPEN | BASIC_PUBLISH | BASIC_DELIVER | HEARTBEAT] [CHANNEL <u16>] [EXCHANGE <str>] [ROUTING_KEY <str>]`
#[doc(alias = "AMQP")]
#[doc(alias = "AMQP 0-9-1")]
#[doc(alias = "ISO/IEC 19464")]
#[doc(alias = "5672")]
#[doc(alias = "PROTOCOL_HEADER")]
#[doc(alias = "CONNECTION_START")]
#[doc(alias = "CHANNEL_OPEN")]
#[doc(alias = "BASIC_PUBLISH")]
#[doc(alias = "BASIC_DELIVER")]
#[doc(alias = "HEARTBEAT")]
#[doc(alias = "CHANNEL")]
#[doc(alias = "EXCHANGE")]
#[doc(alias = "ROUTING_KEY")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmqpSpec<'a> {
    /// 8-byte `AMQP\x00\x00\x09\x01` protocol header handshake flag (`PROTOCOL_HEADER`).
    pub is_protocol_header: bool,
    /// `Connection.Start` (Class 10, Method 10) frame flag (`CONNECTION_START`).
    pub is_connection_start: bool,
    /// `Channel.Open` (Class 20, Method 10) frame flag (`CHANNEL_OPEN`).
    pub is_channel_open: bool,
    /// `Basic.Publish` (Class 60, Method 40) frame flag (`BASIC_PUBLISH`).
    pub is_basic_publish: bool,
    /// `Basic.Deliver` (Class 60, Method 60) frame flag (`BASIC_DELIVER`).
    pub is_basic_deliver: bool,
    /// AMQP Heartbeat (Frame Type 8) flag (`HEARTBEAT`).
    pub is_heartbeat: bool,
    /// 16-bit virtual channel number (`CHANNEL <u16>`, default `1` or `0` for connection/heartbeat).
    pub channel: Option<u16>,
    /// Target exchange name for `Basic.Publish` / `Basic.Deliver` (`EXCHANGE <str>`).
    pub exchange: Option<&'a str>,
    /// Message routing key string (`ROUTING_KEY <str>`).
    pub routing_key: Option<&'a str>,
}
