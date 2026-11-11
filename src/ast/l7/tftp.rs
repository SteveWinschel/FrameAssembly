//! Trivial File Transfer Protocol (TFTP) (RFC 1350 / RFC 2347 (Options) / RFC 2348 (blksize)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Trivial File Transfer Protocol (TFTP) packets over UDP port 69. On the wire, the protocol uses a 2-byte big-endian Opcode header (`1` RRQ Read Request, `2` WRQ Write Request, `3` DATA block transfer, `4` ACK block acknowledgment, `5` ERROR response) followed by NUL-terminated Filename + Mode strings for RRQ/WRQ, 16-bit Block Number + up to 512 bytes of data for DATA/ACK, or 16-bit ErrorCode + NUL-terminated ErrMsg string for ERROR.
//! Every field in [`TftpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b tftp [rrq | wrq | data | ack | error] [filename <str>] [mode <str>] [block <u16>] [errcode <u16>] [errmsg <str>]`

/// RFC 1350 Trivial File Transfer Protocol specification.
///
/// Syntax mapping: `tftp [rrq | wrq | data | ack | error] [filename <str>] [mode <str>] [block <u16>] [errcode <u16>] [errmsg <str>]`
#[doc(alias = "tftp")]
#[doc(alias = "RFC 1350")]
#[doc(alias = "RFC1350")]
#[doc(alias = "rrq")]
#[doc(alias = "wrq")]
#[doc(alias = "data")]
#[doc(alias = "ack")]
#[doc(alias = "error")]
#[doc(alias = "filename")]
#[doc(alias = "mode")]
#[doc(alias = "block")]
#[doc(alias = "errcode")]
#[doc(alias = "errmsg")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TftpSpec<'a> {
    /// Read Request flag.
    pub is_rrq: bool,
    /// Write Request flag.
    pub is_wrq: bool,
    /// Data flag.
    pub is_data: bool,
    /// Acknowledgment flag.
    pub is_ack: bool,
    /// Error flag.
    pub is_error: bool,
    /// Filename string.
    pub filename: Option<&'a str>,
    /// Transfer mode string.
    pub mode: Option<&'a str>,
    /// Block number.
    pub block: Option<u16>,
    /// Error code.
    pub errcode: Option<u16>,
    /// Error message string.
    pub errmsg: Option<&'a str>,
}
