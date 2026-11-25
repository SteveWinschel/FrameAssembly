//! Apache Kafka Binary Wire Protocol (TCP port `9092`) Layer 7 AST definitions.
//!
//! This module defines the [`KafkaSpec`] AST payload specification for Apache Kafka client requests
//! and broker responses over TCP port `9092`. It supports `ApiVersions` (`18`), `Metadata` (`3`),
//! `Produce` (`0` with MessageSet v0 IEEE 802.3 CRC32), `Fetch` (`1`), and `Heartbeat` (`12`)
//! messages alongside correlation IDs, client IDs, topics, partitions, offsets, keys, values,
//! consumer groups, ACKs, and error codes.

/// Apache Kafka binary wire protocol message specification.
///
/// Syntax mapping: `kafka [apiversions|metadata|produce|fetch|heartbeat] [response] [apikey <str|u16>] [version <u16>] [correlationid <i32>] [clientid <str>] [topic <str>] [partition <i32>] [offset <u64>] [key <str>] [value <str>] [group <str>] [errcode <i16>] [acks <i16>]`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[doc(alias = "kafka")]
#[doc(alias = "apiversions")]
#[doc(alias = "produce")]
#[doc(alias = "fetch")]
pub struct KafkaSpec<'a> {
    /// Kafka API selector (`"apiversions"`, `"metadata"`, `"produce"`, `"fetch"`, `"heartbeat"`, or decimal key).
    pub api: Option<&'a str>,
    /// Emits a Kafka `ResponseHeader v0` broker response instead of a `RequestHeader v1` client request.
    pub is_response: bool,
    /// Kafka protocol `api_version` (`0` by default).
    pub api_version: Option<u16>,
    /// Signed 32-bit `correlation_id` pairing requests and responses (defaults to `1`).
    pub correlation_id: Option<i32>,
    /// Request header `client_id` string (defaults to `"frameassembly"`).
    pub client_id: Option<&'a str>,
    /// Target topic name for `Metadata`, `Produce`, or `Fetch` (defaults to `"test-topic"`).
    pub topic: Option<&'a str>,
    /// Target partition index (defaults to `0`).
    pub partition: Option<i32>,
    /// Record offset in `Produce` MessageSet / `base_offset` or `fetch_offset` in `Fetch` (defaults to `0`).
    pub offset: Option<u64>,
    /// Optional record key string inside MessageSet v0 (`None` emits `-1` NULL bytes length).
    pub key: Option<&'a str>,
    /// Record value string inside `Produce` or `Fetch` MessageSet v0 (defaults to `"hello"` on `Produce`).
    pub value: Option<&'a str>,
    /// Consumer group ID for `Heartbeat` (defaults to `"group1"`).
    pub group: Option<&'a str>,
    /// Signed 16-bit broker response `error_code` (`0` = `NONE`).
    pub errcode: Option<i16>,
    /// Required acknowledgments count in `Produce` request (`1` by default, `-1` = all ISR).
    pub acks: Option<i16>,
}
