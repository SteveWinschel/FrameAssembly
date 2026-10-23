//! TLS protocol AST definitions.


/// RFC 8446 Transport Layer Security specification.
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
