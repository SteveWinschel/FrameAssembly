//! AMQP protocol AST definitions.

/// AMQP 0-9-1 specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmqpSpec<'a> {
    /// Protocol header flag.
    pub is_protocol_header: bool,
    /// Connection.Start method flag.
    pub is_connection_start: bool,
    /// Channel.Open method flag.
    pub is_channel_open: bool,
    /// Basic.Publish method flag.
    pub is_basic_publish: bool,
    /// Basic.Deliver method flag.
    pub is_basic_deliver: bool,
    /// Heartbeat frame flag.
    pub is_heartbeat: bool,
    /// Channel number.
    pub channel: Option<u16>,
    /// Exchange name string.
    pub exchange: Option<&'a str>,
    /// Routing key string.
    pub routing_key: Option<&'a str>,
}
