//! Message Queuing Telemetry Transport v3.1.1 / v5.0 (MQTT, OASIS) AST definitions.
//!
//! This module defines [`MqttSpec`], the zero-copy AST representation of an OASIS MQTT v3.1.1
//! control packet over TCP port 1883 (or 8883 for MQTTS). On the wire, an MQTT packet consists of
//! a 1-byte Fixed Header (4-bit control packet type `1..=14`, DUP, 2-bit QoS level, and RETAIN
//! flag), a variable-length Remaining Length integer, a type-specific Variable Header (protocol
//! name `"MQTT"`, level `4`, topic string, or 16-bit Packet Identifier), and an application
//! payload. Canonical FrameAssembly `.fasm` syntax models MQTT traffic via
//! `mqtt [connect | connack | publish | puback | subscribe | suback | pingreq | pingresp | disconnect | pkttype <str>] [clientid <str>] [topic <str>] [qos <u8>] [retain] [pktid <u16>] [keepalive <u16>] [returncode <u8>]`.

/// OASIS Message Queuing Telemetry Transport (MQTT v3.1.1 / ISO/IEC 20922) specification.
///
/// Syntax mapping: `mqtt [connect | connack | publish | puback | subscribe | suback | pingreq | pingresp | disconnect | pkttype <str>] [clientid <str>] [topic <str>] [qos <u8>] [retain] [pktid <u16>] [keepalive <u16>] [returncode <u8>]`
#[doc(alias = "mqtt")]
#[doc(alias = "OASIS MQTT")]
#[doc(alias = "ISO/IEC 20922")]
#[doc(alias = "1883")]
#[doc(alias = "connect")]
#[doc(alias = "connack")]
#[doc(alias = "publish")]
#[doc(alias = "puback")]
#[doc(alias = "subscribe")]
#[doc(alias = "suback")]
#[doc(alias = "pingreq")]
#[doc(alias = "pingresp")]
#[doc(alias = "pkttype")]
#[doc(alias = "clientid")]
#[doc(alias = "topic")]
#[doc(alias = "qos")]
#[doc(alias = "retain")]
#[doc(alias = "pktid")]
#[doc(alias = "keepalive")]
#[doc(alias = "returncode")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MqttSpec<'a> {
    /// Control packet type name (`connect`, `connack`, `publish`, `puback`, `subscribe`, `suback`, `pingreq`, `pingresp`).
    pub pkt_type: Option<&'a str>,
    /// Client identifier for `connect` packets (`clientid <str>`, default `"fasm-mqtt"`).
    pub client_id: Option<&'a str>,
    /// Topic filter or publication topic name (`topic <str>`, default `"test/topic"`).
    pub topic: Option<&'a str>,
    /// Quality of Service delivery level `0..=2` (`qos <u8>`).
    pub qos: Option<u8>,
    /// Retain publication flag (`retain`).
    pub retain: Option<bool>,
    /// 16-bit Packet Identifier for `QoS > 0` or `subscribe`/`suback` (`pktid <u16>`).
    pub pkt_id: Option<u16>,
    /// Keep Alive timer in seconds for `connect` packets (`keepalive <u16>`, default `60`).
    pub keepalive: Option<u16>,
    /// Connect return code or SUBACK return code (`returncode <u8>`, default `0`).
    pub return_code: Option<u8>,
}
