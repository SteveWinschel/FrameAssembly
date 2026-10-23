//! MQTT protocol AST definitions.

/// MQ Telemetry Transport specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MqttSpec<'a> {
    /// Packet type name (e.g. CONNECT, PUBLISH, PINGREQ).
    pub pkt_type: Option<&'a str>,
    /// Client ID string.
    pub client_id: Option<&'a str>,
    /// Topic string.
    pub topic: Option<&'a str>,
    /// Quality of Service (0..=2).
    pub qos: Option<u8>,
    /// Retain flag.
    pub retain: Option<bool>,
    /// Packet Identifier.
    pub pkt_id: Option<u16>,
    /// Keep Alive in seconds.
    pub keepalive: Option<u16>,
    /// Return code for acknowledgments.
    pub return_code: Option<u8>,
}
