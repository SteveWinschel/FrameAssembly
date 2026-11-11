//! Advanced Message Queuing Protocol v0-9-1 (AMQP 0-9-1) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`AmqpSpec`], the zero-copy AST representation of an AMQP 0-9-1 wire frame
//! over TCP port 5672 (or 5671 for AMQPS). On the wire, a session begins with the 8-byte protocol
//! header `amqp\x00\x00\x09\x01`, followed by general frames consisting of a 1-byte Frame Type
//! (`1` Method, `2` Content Header, `3` Content Body, `8` Heartbeat), a 16-bit Channel number, a
//! 32-bit Payload Size, the class/method arguments, and a trailing `0xCE` frame-end octet.
//! Canonical FrameAssembly `.fasm` syntax models AMQP frames via
//! `amqp [protocolheader | connectionstart | channelopen | basicpublish | basicdeliver | heartbeat] [channel <u16>] [exchange <str>] [routingkey <str>]`.

/// Advanced Message Queuing Protocol v0-9-1 (AMQP 0-9-1) specification.
///
/// Syntax mapping: `amqp [protocolheader | connectionstart | channelopen | basicpublish | basicdeliver | heartbeat] [channel <u16>] [exchange <str>] [routingkey <str>]`
#[doc(alias = "amqp")]
#[doc(alias = "AMQP 0-9-1")]
#[doc(alias = "ISO/IEC 19464")]
#[doc(alias = "5672")]
#[doc(alias = "protocolheader")]
#[doc(alias = "connectionstart")]
#[doc(alias = "channelopen")]
#[doc(alias = "basicpublish")]
#[doc(alias = "basicdeliver")]
#[doc(alias = "heartbeat")]
#[doc(alias = "channel")]
#[doc(alias = "exchange")]
#[doc(alias = "routingkey")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmqpSpec<'a> {
    /// 8-byte `amqp\x00\x00\x09\x01` protocol header handshake flag (`protocolheader`).
    pub is_protocol_header: bool,
    /// `Connection.Start` (Class 10, Method 10) frame flag (`connectionstart`).
    pub is_connection_start: bool,
    /// `Channel.Open` (Class 20, Method 10) frame flag (`channelopen`).
    pub is_channel_open: bool,
    /// `Basic.Publish` (Class 60, Method 40) frame flag (`basicpublish`).
    pub is_basic_publish: bool,
    /// `Basic.Deliver` (Class 60, Method 60) frame flag (`basicdeliver`).
    pub is_basic_deliver: bool,
    /// AMQP Heartbeat (Frame Type 8) flag (`heartbeat`).
    pub is_heartbeat: bool,
    /// 16-bit virtual channel number (`channel <u16>`, default `1` or `0` for connection/heartbeat).
    pub channel: Option<u16>,
    /// Target exchange name for `Basic.Publish` / `Basic.Deliver` (`exchange <str>`).
    pub exchange: Option<&'a str>,
    /// Message routing key string (`routingkey <str>`).
    pub routing_key: Option<&'a str>,
}
