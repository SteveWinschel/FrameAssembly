//! 4G LTE S1 Application Protocol (S1AP, 3GPP TS 36.413, ITU-T X.691 APER) Layer 7 AST definitions.
//!
//! This module defines the [`S1apSpec`] AST payload specification for S1-MME control-plane
//! signaling between an eNodeB and the EPC Mobility Management Entity (MME) over SCTP port
//! `36412` (PPID `18`). It supports S1 setup, initial UE/NAS transfers, UE context release,
//! error indication, generic procedure codes, UE IDs, PLMN/eNB/TAC, and `naspdu`.

extern crate alloc;

use alloc::vec::Vec;

/// 3GPP TS 36.413 S1AP (S1 Application Protocol) message specification.
///
/// Syntax mapping: `s1ap [s1setuprequest|s1setupresponse|s1setupfailure|initialuemessage|downlinknastransport|uplinknastransport|uecontextreleasecommand|uecontextreleasecomplete|errorindication] [msgtype <str>] [proccode <u8>] [criticality <str>] [mmeueid <u32>] [enbueid <u32>] [plmn <str>] [enbid <u32>] [tac <u16>] [enbname <str>] [naspdu <hex>]`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[doc(alias = "s1ap")]
#[doc(alias = "lte")]
#[doc(alias = "ts36413")]
#[doc(alias = "s1setup")]
pub struct S1apSpec<'a> {
    /// S1AP PDU / procedure selector (`"s1setuprequest"`, `"initialuemessage"`, `"initiating"`, `"successful"`, `"unsuccessful"`, etc.).
    pub pdu_type: Option<&'a str>,
    /// Explicit 8-bit 3GPP TS 36.413 `ProcedureCode` override (`0..=255`).
    pub proc_code: Option<u8>,
    /// Explicit IE/Procedure criticality override (`"reject"`, `"ignore"`, `"notify"`).
    pub criticality: Option<&'a str>,
    /// `MME-UE-S1AP-ID` (`INTEGER (0..4294967295)`).
    pub mme_ue_id: Option<u32>,
    /// `ENB-UE-S1AP-ID` (`INTEGER (0..16777215)`).
    pub enb_ue_id: Option<u32>,
    /// 5- or 6-digit PLMN identity string (e.g., `"00101"` or `"310410"`).
    pub plmn: Option<&'a str>,
    /// 20-bit macro `eNB-ID` (`0..=1048575`).
    pub enb_id: Option<u32>,
    /// 16-bit EPS Tracking Area Code (`TAC`, `0..=65535`).
    pub tac: Option<u16>,
    /// Optional `eNBname` (in `S1SetupRequest`) or `MMEname` (in `S1SetupResponse`).
    pub enb_name: Option<&'a str>,
    /// Embedded EPS `NAS-PDU` payload bytes.
    pub nas_pdu: Option<Vec<u8>>,
}
