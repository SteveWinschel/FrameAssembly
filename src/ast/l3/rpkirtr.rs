//! RPKI to Router Protocol (RPKI-RTR, RFC 6810 / RFC 8210) AST definitions.
//!
//! Defines the Resource Public Key Infrastructure cache-to-router synchronization protocol specified
//! in RFC 6810 (version `0`) and RFC 8210 (version `1`) over TCP port `323`. Every RPKI-RTR PDU
//! opens with an 8-byte header containing the 8-bit `Protocol Version` (`version`, default `1`),
//! 8-bit `PDU Type` (`serialnotify` `0`, `serialquery` `1`, `resetquery` `2`, `cacheresponse` `3`,
//! `ipv4prefix` `4`, `ipv6prefix` `6`, `endofdata` `7`, `cachereset` `8`, `errorreport` `10`),
//! 16-bit `Session ID` or `Error Code`, and 32-bit total `Length`, carrying ROA prefix announcements,
//! withdrawals, cache serial numbers, and synchronization timers (`refresh`, `retry`, `expire`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b rpkirtr [serialnotify | serialquery | resetquery | cacheresponse | ipv4prefix | ipv6prefix | endofdata | cachereset | errorreport] [version <0|1>] [sessionid <u16>] [serial <u32>] [announce | withdraw | flags <u8>] [prefix "<cidr>"] [maxlen <u8>] [asn <u32>] [refresh <u32>] [retry <u32>] [expire <u32>] [errcode <u16>] [errmsg "<str>"]`

/// RFC 6810 / RFC 8210 RPKI-RTR Protocol Data Unit (PDU) type discriminator.
#[doc(alias = "RpkiRtrPduType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpkirtrType {
    /// Type `0` (`serialnotify`): Cache notification advertising a new serial number (`12` bytes).
    SerialNotify,
    /// Type `1` (`serialquery`): Router incremental update query with `sessionid` and `serial` (`12` bytes).
    SerialQuery,
    /// Type `2` (`resetquery`): Router full-cache synchronization request (`8` bytes).
    ResetQuery,
    /// Type `3` (`cacheresponse`): Cache acknowledgment preceding prefix transfer (`8` bytes).
    CacheResponse,
    /// Type `4` (`ipv4prefix`): IPv4 Route Origin Authorization announce/withdraw PDU (`20` bytes).
    Ipv4Prefix,
    /// Type `6` (`ipv6prefix`): IPv6 Route Origin Authorization announce/withdraw PDU (`32` bytes).
    Ipv6Prefix,
    /// Type `7` (`endofdata`): End-of-Data marker with `serial` and RFC 8210 intervals (`12`/`24` bytes).
    EndOfData,
    /// Type `8` (`cachereset`): Cache signal indicating incremental updates are unavailable (`8` bytes).
    CacheReset,
    /// Type `10` (`errorreport`): Diagnostic error PDU carrying `errcode` and `errmsg` (`16+` bytes).
    ErrorReport,
}

/// RPKI to Router Protocol (RFC 6810 / RFC 8210) specification over TCP port `323`.
///
/// Syntax mapping: `rpkirtr [serialnotify | serialquery | resetquery | cacheresponse | ipv4prefix | ipv6prefix | endofdata | cachereset | errorreport] [version <0|1>] [sessionid <u16>] [serial <u32>] [announce | withdraw | flags <u8>] [prefix "<cidr>"] [maxlen <u8>] [asn <u32>] [refresh <u32>] [retry <u32>] [expire <u32>] [errcode <u16>] [errmsg "<str>"]`
#[doc(alias = "rpkirtr")]
#[doc(alias = "RPKI-RTR")]
#[doc(alias = "RFC 8210")]
#[doc(alias = "RFC8210")]
#[doc(alias = "RFC 6810")]
#[doc(alias = "323")]
#[doc(alias = "serialnotify")]
#[doc(alias = "serialquery")]
#[doc(alias = "resetquery")]
#[doc(alias = "cacheresponse")]
#[doc(alias = "ipv4prefix")]
#[doc(alias = "ipv6prefix")]
#[doc(alias = "endofdata")]
#[doc(alias = "cachereset")]
#[doc(alias = "errorreport")]
#[doc(alias = "serial")]
#[doc(alias = "maxlen")]
#[doc(alias = "asn")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpkirtrSpec<'a> {
    /// RPKI-RTR protocol version (`version <0|1>`, `0` = RFC 6810, `1` = RFC 8210; default `1`).
    pub version: Option<u8>,
    /// RPKI-RTR PDU type (`resetquery` by default when bare).
    pub pdu_type: Option<RpkirtrType>,
    /// 16-bit cache Session ID (`sessionid <u16>`, default `1`).
    pub session_id: Option<u16>,
    /// 32-bit cache Serial Number (`serial <u32>`, default `1`).
    pub serial: Option<u32>,
    /// Prefix PDU flags byte (`flags <u8>`, `announce` = `1`, `withdraw` = `0`; default `1`).
    pub flags: Option<u8>,
    /// ROA IPv4 or IPv6 CIDR prefix string (`prefix "<cidr>"`, e.g., `"192.0.2.0/24"`).
    pub prefix: Option<&'a str>,
    /// ROA Maximum Prefix Length (`maxlen <u8>`, clamped to `>= prefix_len`).
    pub max_len: Option<u8>,
    /// Origin Autonomous System Number authorized for the prefix (`asn <u32>`, default `65001`).
    pub asn: Option<u32>,
    /// RFC 8210 `End of Data` Refresh Interval in seconds (`refresh <u32>`, default `3600`).
    pub refresh: Option<u32>,
    /// RFC 8210 `End of Data` Retry Interval in seconds (`retry <u32>`, default `600`).
    pub retry: Option<u32>,
    /// RFC 8210 `End of Data` Expire Interval in seconds (`expire <u32>`, default `7200`).
    pub expire: Option<u32>,
    /// 16-bit Error Code for `errorreport` PDUs (`errcode <u16>`, default `2` Corrupt Data).
    pub err_code: Option<u16>,
    /// UTF-8 diagnostic message text for `errorreport` PDUs (`errmsg "<str>"`).
    pub err_msg: Option<&'a str>,
}
