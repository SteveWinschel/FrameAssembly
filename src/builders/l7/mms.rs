//! Manufacturing Message Specification (ISO 9506 / IEC 61850 MMS) wire payload builder.
//!
//! This module implements [`build_mms_payload`], which serializes an [`MmsSpec`] AST
//! specification into an ASN.1 BER ISO 9506 MMS PDU wrapped in RFC 1006 TPKT, ISO 8073 COTP DT,
//! ISO 8327-1 Session (`CN`/`AC` or `GT`+`DT`), ISO 8823 Presentation (`CP`/`CPA` or
//! `User-data`), and optional ISO 8650-1 ACSE (`AARQ`/`AARE`) headers over TCP port 102. It
//! supports `Initiate`, `GetNameList`, `Read`, `Write`, `InformationReport`, and `Conclude`
//! request/response exchanges with VMD-specific or domain-specific IEC 61850 variable naming.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Canonical MMS `Initiate-RequestPDU` (`0xA8`) BER payload.
const MMS_INITIATE_REQ: [u8; 39] = [
    0xA8, 0x26, 0x80, 0x02, 0x7D, 0x00, 0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01, 0x0A,
    0xA4, 0x16, 0x80, 0x01, 0x01, 0x81, 0x03, 0x05, 0xF1, 0x00, 0x82, 0x0C, 0x03, 0xEE, 0x1C,
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xEF, 0x18,
];

/// Canonical MMS `Initiate-ResponsePDU` (`0xA9`) BER payload.
const MMS_INITIATE_RESP: [u8; 39] = [
    0xA9, 0x26, 0x80, 0x02, 0x7D, 0x00, 0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01, 0x0A,
    0xA4, 0x16, 0x80, 0x01, 0x01, 0x81, 0x03, 0x05, 0xF1, 0x00, 0x82, 0x0C, 0x03, 0xEE, 0x1C,
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xEF, 0x18,
];

/// Appends an ASN.1 BER definite-length field (`short` `< 128` or `long` `>= 128`).
fn push_ber_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x84);
        out.extend_from_slice(&(u32::try_from(len).unwrap_or(u32::MAX)).to_be_bytes());
    }
}

/// Encodes an ASN.1 BER TLV into a newly allocated vector.
fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + content.len());
    out.push(tag);
    push_ber_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Encodes a minimal two's-complement ASN.1 BER signed integer TLV with the specified `tag`.
fn encode_ber_int_tag(tag: u8, val: i64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let mut start = 0usize;
    while start < 7 {
        if (bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0)
            || (bytes[start] == 0xFF && (bytes[start + 1] & 0x80) != 0)
        {
            start += 1;
        } else {
            break;
        }
    }
    encode_tlv(tag, &bytes[start..])
}

/// Encodes an ISO 8327-1 Session SPDU parameter or header length (1-octet `< 255` or 3-octet `0xFF`).
fn push_session_len(out: &mut Vec<u8>, len: usize) {
    if len < 255 {
        out.push(len as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    }
}

/// Encodes an MMS `VariableAccessSpecification` (`listOfVariable [0]`) for VMD or domain-specific items.
fn encode_var_access_spec(spec: &MmsSpec<'_>) -> Vec<u8> {
    let obj_name = if spec.domain.is_none() && let Some(item) = spec.item {
        encode_tlv(0x80, item.as_bytes())
    } else {
        let dom = spec.domain.unwrap_or("IED1");
        let itm = spec.item.unwrap_or("LLN0$ST$Mod");
        let mut dom_seq = encode_tlv(0x1A, dom.as_bytes());
        dom_seq.extend_from_slice(&encode_tlv(0x1A, itm.as_bytes()));
        encode_tlv(0xA1, &dom_seq)
    };
    let var_item = encode_tlv(0x30, &encode_tlv(0xA0, &obj_name));
    encode_tlv(0xA0, &var_item)
}

/// Encodes an MMS `Data` element (`integer [5]` or `octet-string [9]` when raw payload is provided).
fn encode_mms_data(spec: &MmsSpec<'_>, payload_bytes: &[u8]) -> Vec<u8> {
    if spec.value.is_none() && !payload_bytes.is_empty() {
        encode_tlv(0x89, payload_bytes)
    } else {
        encode_ber_int_tag(0x85, i64::from(spec.value.unwrap_or(0)))
    }
}

/// Wraps an MMS `Initiate-RequestPDU` or `Initiate-ResponsePDU` inside Session `CN`/`AC`,
/// Presentation `CP`/`CPA`, and ACSE `AARQ`/`AARE`.
fn wrap_initiate_envelope(is_resp: bool) -> Vec<u8> {
    let mms_init = if is_resp {
        MMS_INITIATE_RESP.as_slice()
    } else {
        MMS_INITIATE_REQ.as_slice()
    };

    // ACSE EXTERNAL [UNIVERSAL 8] (0x28): direct-ref OID 2.1.1 (06 02 51 01), indirect-ref 3, single-ASN1
    let mut ext_body = encode_tlv(0x06, &[0x51, 0x01]);
    ext_body.extend_from_slice(&encode_tlv(0x02, &[0x03]));
    ext_body.extend_from_slice(&encode_tlv(0xA0, mms_init));
    let ext = encode_tlv(0x28, &ext_body);

    let acse_app_ctx = encode_tlv(0xA1, &encode_tlv(0x06, &[0x28, 0xCA, 0x22, 0x02, 0x03]));
    let acse_user_info = encode_tlv(0xBE, &ext);

    let acse = if is_resp {
        let mut body = acse_app_ctx;
        body.extend_from_slice(&[0xA2, 0x03, 0x02, 0x01, 0x00]); // result: accepted (0)
        body.extend_from_slice(&[0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00]); // acse-service-user: null
        body.extend_from_slice(&acse_user_info);
        encode_tlv(0x61, &body)
    } else {
        let mut body = acse_app_ctx;
        body.extend_from_slice(&acse_user_info);
        encode_tlv(0x60, &body)
    };

    let mut pdv_body = encode_tlv(0x02, &[0x01]); // presentation-context-id: 1 (ACSE)
    pdv_body.extend_from_slice(&encode_tlv(0xA0, &acse));
    let pres_ud = encode_tlv(0x61, &encode_tlv(0x30, &pdv_body));

    let nmp = if is_resp {
        let res_item = encode_tlv(0x30, &[0x80, 0x01, 0x00, 0x81, 0x02, 0x51, 0x01]);
        let mut res_list = res_item.clone();
        res_list.extend_from_slice(&res_item);
        let mut body = encode_tlv(0x83, &[0x00, 0x00, 0x00, 0x01]);
        body.extend_from_slice(&encode_tlv(0xA5, &res_list));
        body.extend_from_slice(&pres_ud);
        body
    } else {
        // Context 1: ACSE (2.2.1.0.1), Context 3: MMS (1.0.9506.2.1)
        let mut c1 = encode_tlv(0x02, &[0x01]);
        c1.extend_from_slice(&encode_tlv(0x06, &[0x52, 0x01, 0x00, 0x01]));
        c1.extend_from_slice(&encode_tlv(0x30, &encode_tlv(0x06, &[0x51, 0x01])));

        let mut c3 = encode_tlv(0x02, &[0x03]);
        c3.extend_from_slice(&encode_tlv(0x06, &[0x28, 0xCA, 0x22, 0x02, 0x01]));
        c3.extend_from_slice(&encode_tlv(0x30, &encode_tlv(0x06, &[0x51, 0x01])));

        let mut ctx_list = encode_tlv(0x30, &c1);
        ctx_list.extend_from_slice(&encode_tlv(0x30, &c3));

        let mut body = encode_tlv(0x81, &[0x00, 0x00, 0x00, 0x01]);
        body.extend_from_slice(&encode_tlv(0x82, &[0x00, 0x00, 0x00, 0x01]));
        body.extend_from_slice(&encode_tlv(0xA4, &ctx_list));
        body.extend_from_slice(&pres_ud);
        body
    };

    let mut cp_body = encode_tlv(0xA0, &encode_tlv(0x80, &[0x01]));
    cp_body.extend_from_slice(&encode_tlv(0xA2, &nmp));
    let pres_cp = encode_tlv(0x31, &cp_body);

    let mut ses_params = Vec::with_capacity(16 + pres_cp.len());
    ses_params.extend_from_slice(&[
        0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x14, 0x02, 0x00, 0x02,
    ]);
    ses_params.push(0xC1); // User Data PI
    push_session_len(&mut ses_params, pres_cp.len());
    ses_params.extend_from_slice(&pres_cp);

    let mut ses = Vec::with_capacity(4 + ses_params.len());
    ses.push(if is_resp { 0x0E } else { 0x0D }); // AC (14) or CN (13)
    push_session_len(&mut ses, ses_params.len());
    ses.extend_from_slice(&ses_params);
    ses
}

/// Wraps an MMS PDU inside ISO Session `GT`+`DT` and ISO Presentation `User-data` (context ID `3`).
fn wrap_data_transfer(mms_pdu: &[u8]) -> Vec<u8> {
    let mut pdv_body = encode_tlv(0x02, &[0x03]); // presentation-context-id: 3 (MMS)
    pdv_body.extend_from_slice(&encode_tlv(0xA0, mms_pdu));
    let pres_ud = encode_tlv(0x61, &encode_tlv(0x30, &pdv_body));

    let mut ses = Vec::with_capacity(4 + pres_ud.len());
    ses.extend_from_slice(&[0x01, 0x00, 0x01, 0x00]); // Give Tokens + Data Transfer SPDU
    ses.extend_from_slice(&pres_ud);
    ses
}

/// Builds an ISO 9506 / IEC 61850 MMS packet payload over RFC 1006 TPKT and COTP DT.
pub fn build_mms_payload(
    _ctx: &WireContext,
    spec: &MmsSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let default_svc = if spec.domain.is_some()
        || spec.item.is_some()
        || spec.invoke_id.is_some()
        || spec.value.is_some()
    {
        if spec.value.is_some() && !spec.is_response {
            "write"
        } else {
            "read"
        }
    } else {
        "initiate"
    };
    let svc_norm = spec
        .service
        .unwrap_or(default_svc)
        .trim()
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let is_resp = spec.is_response || svc_norm == "INITIATERESP" || svc_norm == "INITACK";
    let invoke_id = encode_ber_int_tag(0x02, i64::from(spec.invoke_id.unwrap_or(1)));

    let osi_body = match svc_norm.as_str() {
        "INIT" | "INITIATE" | "INITIATEREQ" | "INITIATERESP" | "INITACK" => {
            wrap_initiate_envelope(is_resp)
        }
        "CONCLUDE" => {
            let pdu = [if is_resp { 0x8C } else { 0x8B }, 0x00];
            wrap_data_transfer(&pdu)
        }
        "GETNAMELIST" => {
            let pdu = if is_resp {
                let name = spec.domain.or(spec.item).unwrap_or("IED1");
                let list_of_id = encode_tlv(0xA0, &encode_tlv(0x1A, name.as_bytes()));
                let mut gnl_body = list_of_id;
                gnl_body.extend_from_slice(&[0x81, 0x01, 0x00]); // moreFollows: FALSE
                let mut resp = invoke_id;
                resp.extend_from_slice(&encode_tlv(0xA1, &gnl_body));
                encode_tlv(0xA1, &resp)
            } else {
                let (obj_cls_code, scope) = if let Some(dom) = spec.domain {
                    (0x00u8, encode_tlv(0x81, dom.as_bytes()))
                } else {
                    (0x00u8, encode_tlv(0x80, &[]))
                };
                let mut gnl_body = encode_tlv(0xA0, &encode_tlv(0x0A, &[obj_cls_code]));
                gnl_body.extend_from_slice(&encode_tlv(0xA1, &scope));
                let mut req = invoke_id;
                req.extend_from_slice(&encode_tlv(0xA1, &gnl_body));
                encode_tlv(0xA0, &req)
            };
            wrap_data_transfer(&pdu)
        }
        "WRITE" => {
            let pdu = if is_resp {
                let mut resp = invoke_id;
                resp.extend_from_slice(&encode_tlv(0xA5, &[0x81, 0x00])); // success [1] NULL
                encode_tlv(0xA1, &resp)
            } else {
                let mut wr_body = encode_var_access_spec(spec);
                wr_body.extend_from_slice(&encode_tlv(0xA0, &encode_mms_data(spec, payload_bytes)));
                let mut req = invoke_id;
                req.extend_from_slice(&encode_tlv(0xA5, &wr_body));
                encode_tlv(0xA0, &req)
            };
            wrap_data_transfer(&pdu)
        }
        "REPORT" | "INFORMATIONREPORT" => {
            let mut rpt_body = encode_var_access_spec(spec);
            rpt_body.extend_from_slice(&encode_tlv(0xA0, &encode_mms_data(spec, payload_bytes)));
            let pdu = encode_tlv(0xA3, &encode_tlv(0xA0, &rpt_body));
            wrap_data_transfer(&pdu)
        }
        _ => {
            // Default / "READ"
            let pdu = if is_resp {
                let mut resp = invoke_id;
                resp.extend_from_slice(&encode_tlv(
                    0xA4,
                    &encode_tlv(0xA1, &encode_mms_data(spec, payload_bytes)),
                ));
                encode_tlv(0xA1, &resp)
            } else {
                let mut req = invoke_id;
                req.extend_from_slice(&encode_tlv(
                    0xA4,
                    &encode_tlv(0xA1, &encode_var_access_spec(spec)),
                ));
                encode_tlv(0xA0, &req)
            };
            wrap_data_transfer(&pdu)
        }
    };

    let cotp_dt = [0x02u8, 0xF0, 0x80];
    let total_len = u16::try_from(4 + cotp_dt.len() + osi_body.len()).unwrap_or(u16::MAX);
    let mut pkt = Vec::with_capacity(usize::from(total_len));
    pkt.push(0x03);
    pkt.push(0x00);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&cotp_dt);
    pkt.extend_from_slice(&osi_body);
    pkt
}
