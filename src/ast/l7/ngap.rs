//! 5G NG Application Protocol (NGAP, 3GPP TS 38.413, ITU-T X.691 APER) Layer 7 AST definitions.
//!
//! This module defines the [`NgapSpec`] AST payload specification for N2-interface control-plane
//! signaling between a gNodeB and the 5G Access and Mobility Management Function (AMF) over
//! SCTP port `38412` (PPID `60`). It supports named procedures (`ngsetuprequest`, `initialuemessage`,
//! NAS transports, UE context release), generic procedure codes, UE IDs, PLMN/gNB/TAC, and `naspdu`.

extern crate alloc;

use alloc::vec::Vec;

/// 3GPP TS 38.413 NGAP (NG Application Protocol) message specification.
///
/// Syntax mapping: `ngap [ngsetuprequest|ngsetupresponse|ngsetupfailure|initialuemessage|downlinknastransport|uplinknastransport|uecontextreleasecommand|uecontextreleasecomplete|errorindication] [msgtype <str>] [proccode <u8>] [criticality <str>] [amfueid <u64>] [ranueid <u32>] [plmn <str>] [gnbid <u32>] [tac <u32>] [ranname <str>] [naspdu <hex>]`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[doc(alias = "ngap")]
#[doc(alias = "5g")]
#[doc(alias = "ts38413")]
#[doc(alias = "ngsetup")]
pub struct NgapSpec<'a> {
    /// NGAP PDU / procedure selector (`"ngsetuprequest"`, `"initialuemessage"`, `"initiating"`, `"successful"`, `"unsuccessful"`, etc.).
    pub pdu_type: Option<&'a str>,
    /// Explicit 8-bit 3GPP TS 38.413 `ProcedureCode` override (`0..=255`).
    pub proc_code: Option<u8>,
    /// Explicit IE/Procedure criticality override (`"reject"`, `"ignore"`, `"notify"`).
    pub criticality: Option<&'a str>,
    /// `AMF-UE-NGAP-ID` (`INTEGER (0..1099511627775)`).
    pub amf_ue_id: Option<u64>,
    /// `RAN-UE-NGAP-ID` (`INTEGER (0..4294967295)`).
    pub ran_ue_id: Option<u32>,
    /// 5- or 6-digit PLMN identity string (e.g., `"00101"` or `"310410"`).
    pub plmn: Option<&'a str>,
    /// 24-bit gNodeB identifier inside `GlobalGNB-ID` (`0..=16777215`).
    pub gnb_id: Option<u32>,
    /// 24-bit 5GS Tracking Area Code (`TAC`, `0..=16777215`).
    pub tac: Option<u32>,
    /// Optional `RANNodeName` (in `NGSetupRequest`) or `AMFName` (in `NGSetupResponse`).
    pub ran_name: Option<&'a str>,
    /// Embedded 5GS `NAS-PDU` payload bytes.
    pub nas_pdu: Option<Vec<u8>>,
}
