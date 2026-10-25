//! Message Queuing Telemetry Transport v3.1.1 / v5.0 (MQTT, OASIS) AST definitions.
//!
//! This module defines [`MqttSpec`], the zero-copy AST representation of an OASIS MQTT v3.1.1
//! control packet over TCP port 1883 (or 8883 for MQTTS). On the wire, an MQTT packet consists of
//! a 1-byte Fixed Header (4-bit control packet type `1..=14`, DUP, 2-bit QoS level, and RETAIN
//! flag), a variable-length Remaining Length integer, a type-specific Variable Header (protocol
//! name `"MQTT"`, level `4`, topic string, or 16-bit Packet Identifier), and an application
//! payload. Canonical FrameAssembly `.fasm` syntax models MQTT traffic via
//! `MQTT [CONNECT | CONNACK | PUBLISH | PUBACK | SUBSCRIBE | SUBACK | PINGREQ | PINGRESP] [CLIENT_ID <str>] [TOPIC <str>] [QOS <u8>] [RETAIN] [PKT_ID <u16>] [KEEPALIVE <u16>] [RETURN_CODE <u8>]`.

/// OASIS Message Queuing Telemetry Transport (MQTT v3.1.1 / ISO/IEC 20922) specification.
///
/// Syntax mapping: `MQTT [CONNECT | CONNACK | PUBLISH | PUBACK | SUBSCRIBE | SUBACK | PINGREQ | PINGRESP] [CLIENT_ID <str>] [TOPIC <str>] [QOS <u8>] [RETAIN] [PKT_ID <u16>] [KEEPALIVE <u16>] [RETURN_CODE <u8>]`
#[doc(alias = "MQTT")]
#[doc(alias = "OASIS MQTT")]
#[doc(alias = "ISO/IEC 20922")]
#[doc(alias = "1883")]
#[doc(alias = "CONNECT")]
#[doc(alias = "CONNACK")]
#[doc(alias = "PUBLISH")]
#[doc(alias = "PUBACK")]
#[doc(alias = "SUBSCRIBE")]
#[doc(alias = "SUBACK")]
#[doc(alias = "PINGREQ")]
#[doc(alias = "PINGRESP")]
#[doc(alias = "CLIENT_ID")]
#[doc(alias = "TOPIC")]
#[doc(alias = "QOS")]
#[doc(alias = "RETAIN")]
#[doc(alias = "PKT_ID")]
#[doc(alias = "KEEPALIVE")]
#[doc(alias = "RETURN_CODE")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MqttSpec<'a> {
    /// Control packet type name (`CONNECT`, `CONNACK`, `PUBLISH`, `PUBACK`, `SUBSCRIBE`, `SUBACK`, `PINGREQ`, `PINGRESP`).
    pub pkt_type: Option<&'a str>,
    /// Client identifier for `CONNECT` packets (`CLIENT_ID <str>`, default `"fasm-mqtt"`).
    pub client_id: Option<&'a str>,
    /// Topic filter or publication topic name (`TOPIC <str>`, default `"test/topic"`).
    pub topic: Option<&'a str>,
    /// Quality of Service delivery level `0..=2` (`QOS <u8>`).
    pub qos: Option<u8>,
    /// Retain publication flag (`RETAIN`).
    pub retain: Option<bool>,
    /// 16-bit Packet Identifier for `QoS > 0` or `SUBSCRIBE`/`SUBACK` (`PKT_ID <u16>`).
    pub pkt_id: Option<u16>,
    /// Keep Alive timer in seconds for `CONNECT` packets (`KEEPALIVE <u16>`, default `60`).
    pub keepalive: Option<u16>,
    /// Connect return code or SUBACK return code (`RETURN_CODE <u8>`, default `0`).
    pub return_code: Option<u8>,
}
