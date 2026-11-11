//! Transport Layer Security (TLS 1.2 / TLS 1.3) (RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2) / RFC 6066 (SNI) / RFC 7301 (ALPN)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Transport Layer Security (TLS 1.2 / TLS 1.3) packets over TCP port 443. On the wire, the protocol uses a 5-byte TLS Record Layer header (8-bit ContentType: `21` Alert, `22` Handshake, `23` ApplicationData; 16-bit Legacy Record Version e.g. `0x0303`; 16-bit Length) encapsulating a 4-byte Handshake header (8-bit HandshakeType: `1` ClientHello, `2` ServerHello, `11` Certificate, `20` Finished; 24-bit Length), 32-byte Random nonce, CipherSuite list (`0x1301` TLS_AES_128_GCM_SHA256, `0x1302` TLS_AES_256_GCM_SHA384), and SNI (`0x0000`) / ALPN (`0x0010`) extensions.
//! Every field in [`TlsSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b tls [clienthello | serverhello | certificate | finished | appdata | alert] [recordversion <u16>] [handshakeversion <u16>] [sni <str>] [ciphersuite <u16>] [alpn <str>]`

/// RFC 8446 Transport Layer Security specification.
///
/// Syntax mapping: `tls [clienthello | serverhello | certificate | finished | appdata | alert] [recordversion <u16>] [handshakeversion <u16>] [sni <str>] [ciphersuite <u16>] [alpn <str>]`
#[doc(alias = "tls")]
#[doc(alias = "TLS13")]
#[doc(alias = "RFC 8446")]
#[doc(alias = "RFC8446")]
#[doc(alias = "RFC 5246")]
#[doc(alias = "clienthello")]
#[doc(alias = "serverhello")]
#[doc(alias = "certificate")]
#[doc(alias = "finished")]
#[doc(alias = "appdata")]
#[doc(alias = "alert")]
#[doc(alias = "recordversion")]
#[doc(alias = "handshakeversion")]
#[doc(alias = "sni")]
#[doc(alias = "alpn")]
#[doc(alias = "ciphersuite")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsSpec<'a> {
    /// ClientHello handshake flag.
    pub is_client_hello: bool,
    /// ServerHello handshake flag.
    pub is_server_hello: bool,
    /// Certificate handshake flag.
    pub is_certificate: bool,
    /// Finished handshake flag.
    pub is_finished: bool,
    /// ApplicationData record flag.
    pub is_app_data: bool,
    /// Alert record flag.
    pub is_alert: bool,
    /// Record layer version.
    pub record_version: Option<u16>,
    /// Handshake protocol version.
    pub handshake_version: Option<u16>,
    /// Server Name Indication hostname.
    pub sni: Option<&'a str>,
    /// Cipher suite identifier.
    pub ciphersuite: Option<u16>,
    /// Application-Layer Protocol Negotiation string.
    pub alpn: Option<&'a str>,
}
