//! SSDP protocol AST definitions.


/// Simple Service Discovery Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsdpSpec<'a> {
    /// M-SEARCH discovery flag.
    pub is_msearch: bool,
    /// NOTIFY advertisement flag.
    pub is_notify: bool,
    /// Host header string.
    pub host_hdr: Option<&'a str>,
    /// MAN header string.
    pub man: Option<&'a str>,
    /// Maximum wait time in seconds (MX).
    pub mx: Option<u8>,
    /// Search Target (ST) string.
    pub st: Option<&'a str>,
    /// Notification Type (NT) string.
    pub nt: Option<&'a str>,
    /// Notification Sub-Type (NTS) string.
    pub nts: Option<&'a str>,
    /// Unique Service Name (USN) string.
    pub usn: Option<&'a str>,
    /// Location URL string.
    pub location: Option<&'a str>,
}
