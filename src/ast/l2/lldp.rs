//! Link Layer Discovery Protocol (LLDP) AST definitions.

/// Link Layer Discovery Protocol (IEEE 802.1AB) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LldpSpec<'a> {
    /// Chassis ID value.
    pub chassis_id: Option<&'a str>,
    /// Port ID value.
    pub port_id: Option<&'a str>,
    /// Time To Live in seconds.
    pub ttl: Option<u16>,
    /// System Name TLV string.
    pub sysname: Option<&'a str>,
    /// System Description TLV string.
    pub sysdesc: Option<&'a str>,
}
