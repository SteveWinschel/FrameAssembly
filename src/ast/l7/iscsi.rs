//! Internet Small Computer Systems Interface (iSCSI, RFC 7143) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`IscsiSpec`], the zero-copy AST representation of an RFC 7143 Internet
//! Small Computer Systems Interface (iSCSI) storage PDU transmitted over TCP port 3260. On the
//! wire, every iSCSI PDU begins with a 48-byte big-endian Basic Header Segment (BHS) carrying the
//! immediate flag, 6-bit opcode (`0x03` Login Request, `0x23` Login Response, `0x01` SCSI Command,
//! `0x21` SCSI Response, `0x05` Data-Out, `0x25` Data-In, `0x00` NOP-Out, `0x06` Logout Request),
//! `DataSegmentLength`, 8-byte `LUN`/`ISID`, `InitiatorTaskTag`, `CmdSN`/`StatSN`, and SCSI CDB,
//! followed by an optional 4-byte-aligned DataSegment. Canonical `.frasm` syntax:
//! `iscsi [login | logout | read | write | nop | response | data | text | cmd <str>] [opcode <u8>] [initiator <str>] [target <str>] [lun <u16>] [itt <u32>] [cmdsn <u32>] [statsn <u32>] [status <u8>] [flags <u8>] [offset <u32>]`.

/// RFC 7143 Internet Small Computer Systems Interface (iSCSI) specification.
///
/// Syntax mapping: `iscsi [login | logout | read | write | nop | response | data | text | cmd <str>] [opcode <u8>] [initiator <str>] [target <str>] [lun <u16>] [itt <u32>] [cmdsn <u32>] [statsn <u32>] [status <u8>] [flags <u8>] [offset <u32>]`
#[doc(alias = "iscsi")]
#[doc(alias = "RFC 7143")]
#[doc(alias = "RFC7143")]
#[doc(alias = "RFC 3720")]
#[doc(alias = "3260")]
#[doc(alias = "login")]
#[doc(alias = "logout")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "nop")]
#[doc(alias = "response")]
#[doc(alias = "data")]
#[doc(alias = "text")]
#[doc(alias = "cmd")]
#[doc(alias = "opcode")]
#[doc(alias = "initiator")]
#[doc(alias = "target")]
#[doc(alias = "lun")]
#[doc(alias = "itt")]
#[doc(alias = "cmdsn")]
#[doc(alias = "statsn")]
#[doc(alias = "status")]
#[doc(alias = "flags")]
#[doc(alias = "offset")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IscsiSpec<'a> {
    /// iSCSI PDU command (`login`, `logout`, `read`, `write`, `nop`, `response`, `data`, `text`, or `cmd <str>`).
    pub cmd: Option<&'a str>,
    /// Explicit 8-bit BHS byte-0 opcode override (`opcode <u8>`).
    pub opcode: Option<u8>,
    /// `InitiatorName` IQN for Login Requests (`initiator <str>`).
    pub initiator: Option<&'a str>,
    /// `TargetName` IQN for Login Requests (`target <str>`).
    pub target: Option<&'a str>,
    /// Logical Unit Number (`lun <u16>`, default `0`).
    pub lun: Option<u16>,
    /// 32-bit Initiator Task Tag (`itt <u32>`, default `1`).
    pub itt: Option<u32>,
    /// 32-bit Command Sequence Number (`cmdsn <u32>`, default `1`).
    pub cmdsn: Option<u32>,
    /// 32-bit Status or Expected Status Sequence Number (`statsn <u32>`, default `0`).
    pub statsn: Option<u32>,
    /// 8-bit SCSI status or Login Status-Class code (`status <u8>`, default `0`).
    pub status: Option<u8>,
    /// 8-bit BHS byte-1 opcode-specific flags override (`flags <u8>`).
    pub flags: Option<u8>,
    /// 32-bit logical block address (`READ(10)`/`WRITE(10)`) or `BufferOffset` (`offset <u32>`, default `0`).
    pub offset: Option<u32>,
}
