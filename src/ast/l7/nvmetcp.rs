//! NVM Express over Fabrics TCP Transport (NVMe/TCP) Layer 7 AST definitions.
//!
//! This module defines [`NvmetcpSpec`], the zero-copy AST representation of an NVM Express over
//! Fabrics TCP (`NVMe/TCP`) Protocol Data Unit transmitted over TCP port 4420. On the wire,
//! every NVMe/TCP PDU begins with an 8-byte little-endian common header (`PduType`, `Flags`,
//! `HLEN`, `PDO`, `PLEN`), encapsulating `ICReq` (`0x00`), `ICResp` (`0x01`), `H2CTermReq` (`0x02`),
//! `C2HTermReq` (`0x03`), `CapsuleCmd` (`0x04` with 64-byte NVMe SQE), `CapsuleResp` (`0x05` with
//! 16-byte NVMe CQE), `H2CData` (`0x06`), `C2HData` (`0x07`), or `R2T` (`0x09`), with optional
//! CRC-32C header/data digests. Canonical `.frasm` syntax:
//! `nvmetcp [icreq | icresp | read | write | response | h2cdata | c2hdata | r2t | msgtype <str> | cmd <str>] [opcode <u8>] [nsid <u32>] [qid <u16>] [reqid <u16>] [flags <u8>] [status <u16>] [offset <u32>] [count <u32>]`.

/// NVM Express over Fabrics TCP Transport (`NVMe/TCP`) specification.
///
/// Syntax mapping: `nvmetcp [icreq | icresp | read | write | response | h2cdata | c2hdata | r2t | msgtype <str> | cmd <str>] [opcode <u8>] [nsid <u32>] [qid <u16>] [reqid <u16>] [flags <u8>] [status <u16>] [offset <u32>] [count <u32>]`
#[doc(alias = "nvmetcp")]
#[doc(alias = "NVMe/TCP")]
#[doc(alias = "NVMe-oF")]
#[doc(alias = "4420")]
#[doc(alias = "icreq")]
#[doc(alias = "icresp")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "response")]
#[doc(alias = "h2cdata")]
#[doc(alias = "c2hdata")]
#[doc(alias = "r2t")]
#[doc(alias = "msgtype")]
#[doc(alias = "cmd")]
#[doc(alias = "opcode")]
#[doc(alias = "nsid")]
#[doc(alias = "qid")]
#[doc(alias = "reqid")]
#[doc(alias = "flags")]
#[doc(alias = "status")]
#[doc(alias = "offset")]
#[doc(alias = "count")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvmetcpSpec<'a> {
    /// NVMe/TCP PDU type (`icreq`, `icresp`, `read`, `write`, `response`, `h2cdata`, `c2hdata`, `r2t`, `h2cterm`, `c2hterm`, or `msgtype`/`cmd`).
    pub pdu_type: Option<&'a str>,
    /// 8-bit NVMe Submission Queue Entry opcode for `CapsuleCmd` (`opcode <u8>`, default `0x02` Read).
    pub opcode: Option<u8>,
    /// 32-bit NVMe Namespace Identifier (`nsid <u32>`, default `1`).
    pub nsid: Option<u32>,
    /// 16-bit NVMe Submission Queue Identifier in `CapsuleResp` (`qid <u16>`, default `1`).
    pub qid: Option<u16>,
    /// 16-bit NVMe Command Identifier (`CID` / `CCCID`, `reqid <u16>`, default `1`).
    pub req_id: Option<u16>,
    /// 8-bit NVMe/TCP common header flags (`flags <u8>`, `0x01` HDGSTF, `0x02` DDGSTF).
    pub flags: Option<u8>,
    /// 15-bit NVMe Completion Queue status code or Fatal Error Status (`status <u16>`, default `0`).
    pub status: Option<u16>,
    /// 32-bit starting LBA (`SLBA`) or `DATAO`/`R2TO` byte offset (`offset <u32>`, default `0`).
    pub offset: Option<u32>,
    /// 32-bit logical block count (`NLB`, default `8`) or `R2TL` byte length (`count <u32>`, default `4096`).
    pub count: Option<u32>,
}
