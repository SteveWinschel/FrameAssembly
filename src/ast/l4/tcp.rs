//! Transmission Control Protocol (TCP) AST definitions.

/// Represents a TCP flag.
///
/// # Examples
/// ```
/// use frameassembly::ast::TcpFlag;
/// let flag = TcpFlag::Syn;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TcpFlag {
    /// SYN flag
    Syn,
    /// ACK flag
    Ack,
    /// FIN flag
    Fin,
    /// RST flag
    Rst,
    /// PSH flag
    Psh,
    /// URG flag
    Urg,
    /// ECE flag
    Ece,
    /// CWR flag
    Cwr,
}

/// TCP header options overrides.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpOptions {
    /// Maximum Segment Size option.
    pub mss: Option<u16>,
    /// Window Scale option.
    pub wscale: Option<u8>,
    /// SACK Permitted option.
    pub sack_perm: bool,
    /// Timestamp Value option.
    pub tsval: Option<u32>,
    /// Timestamp Echo Reply option.
    pub tsecr: Option<u32>,
}
