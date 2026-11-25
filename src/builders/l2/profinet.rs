//! PROFINET IO Real-Time (`0x8892`) and UDP Context Manager (`34964`) wire frame builder.
//!
//! Synthesizes IEC 61158-6-10 PROFINET IO frames across native Layer 2 Ethernet (`0x8892`,
//! default even on IP-configured hosts) and optional UDP Context Manager (`34964` when
//! `transport udp` is requested). Layer 2 frames emit either Cyclic Real-Time (`FrameID`
//! `0x8000` default + 40-byte IO SDU + 4-byte APDU status `CycleCounter`, `DataStatus`,
//! `TransferStatus`) or Acyclic DCP (`FrameID` `0xFEFC..=0xFEFF`). UDP frames emit RFC/IEC
//! DCE/RPC v4 connectionless `PNIO-CM` Device Control PDUs (`Connect`, `Release`, `Read`,
//! `Write`, `Control`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b profinet [frameid <u16>] [cycle <u16>] [datastatus <u8>] [transferstatus <u8>] [service <str>] [xid <u32>] [request | response] [transport udp]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::{build_ethernet_and_l2, build_ip_packet, build_udp_datagram_with_opts};
use alloc::string::ToString;
use alloc::vec::Vec;

/// DCE/RPC PNIO Device Context Manager interface UUID (`DEA00001-6C97-11D1-8271-00A02442DF7D`, LE mixed-endian).
pub(crate) const PNIO_CM_IF_UUID: [u8; 16] = [
    0x01, 0x00, 0xA0, 0xDE, 0x97, 0x6C, 0xD1, 0x11, 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D,
];

/// DCE/RPC PNIO object UUID (`DEA00000-6C97-11D1-8271-000100000000`, LE mixed-endian).
const PNIO_OBJ_UUID: [u8; 16] = [
    0x00, 0x00, 0xA0, 0xDE, 0x97, 0x6C, 0xD1, 0x11, 0x82, 0x71, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
];

/// Builds a PROFINET IO payload for either native L2 Ethernet (`0x8892`) or UDP CM (`34964`).
pub fn build_profinet_payload(
    ctx: &WireContext,
    spec: &ProfinetSpec,
    payload: &[u8],
) -> Vec<u8> {
    let svc_norm = spec
        .service
        .map(|s| s.trim().to_ascii_uppercase().replace(['_', '-'], ""));

    if ctx.transport == Some(TransportProto::Udp) {
        return build_profinet_cm_udp_payload(spec, svc_norm.as_deref(), payload);
    }

    let is_dcp = matches!(spec.frame_id, Some(0xFEFC..=0xFEFF))
        || matches!(
            svc_norm.as_deref(),
            Some("DCP" | "IDENTIFY" | "GET" | "SET" | "HELLO")
        );

    if is_dcp {
        let service_id: u8 = match svc_norm.as_deref() {
            Some("GET") => 3,
            Some("SET") => 4,
            Some("HELLO") => 6,
            _ => 5, // Identify
        };
        let service_type: u8 = if spec.is_response || spec.frame_id == Some(0xFEFE) {
            1
        } else {
            0
        };
        let frame_id = spec.frame_id.unwrap_or(match (service_id, service_type) {
            (6, _) => 0xFEFC,
            (5, 0) => 0xFEFD,
            (5, _) => 0xFEFE,
            _ => 0xFEFF,
        });
        let xid = spec.xid.unwrap_or(1);
        let resp_delay: u16 = if service_id == 5 && service_type == 0 {
            1
        } else {
            0
        };
        let blocks: Vec<u8> = if payload.is_empty() {
            alloc::vec![0xFF, 0xFF, 0x00, 0x00]
        } else {
            payload.to_vec()
        };
        let mut out = Vec::with_capacity(46.max(12 + blocks.len()));
        out.extend_from_slice(&frame_id.to_be_bytes());
        out.push(service_id);
        out.push(service_type);
        out.extend_from_slice(&xid.to_be_bytes());
        out.extend_from_slice(&resp_delay.to_be_bytes());
        out.extend_from_slice(&(u16::try_from(blocks.len()).unwrap_or(u16::MAX)).to_be_bytes());
        out.extend_from_slice(&blocks);
        if out.len() < 46 {
            out.resize(46, 0);
        }
        return out;
    }

    let frame_id = spec.frame_id.unwrap_or(0x8000);
    let cycle = spec.cycle.unwrap_or(1);
    let data_status = spec.data_status.unwrap_or(0x35);
    let transfer_status = spec.transfer_status.unwrap_or(0x00);

    let sdu_len = if payload.is_empty() { 40 } else { payload.len() };
    let mut out = Vec::with_capacity(6 + sdu_len);
    out.extend_from_slice(&frame_id.to_be_bytes());
    if payload.is_empty() {
        out.resize(2 + 40, 0);
    } else {
        out.extend_from_slice(payload);
    }
    out.extend_from_slice(&cycle.to_be_bytes());
    out.push(data_status);
    out.push(transfer_status);
    out
}

/// Builds a connectionless DCE/RPC v4 `PNIO-CM` UDP payload for port `34964`.
fn build_profinet_cm_udp_payload(
    spec: &ProfinetSpec,
    svc_norm: Option<&str>,
    payload: &[u8],
) -> Vec<u8> {
    let opnum: u16 = match svc_norm {
        Some("CONNECT") => 0,
        Some("READ") => 2,
        Some("WRITE") => 3,
        Some("CONTROL") => 4,
        _ => 1, // Release
    };
    let ptype: u8 = if spec.is_response { 2 } else { 0 };
    let resp_flag: u16 = if spec.is_response { 0x8000 } else { 0x0000 };

    let mut block = Vec::with_capacity(64 + payload.len());
    match opnum {
        0 => {
            if spec.is_response {
                // ARBlockRes (0x8101), length 30
                block.extend_from_slice(&0x8101_u16.to_be_bytes());
                block.extend_from_slice(&30_u16.to_be_bytes());
                block.extend_from_slice(&0x0100_u16.to_be_bytes());
                block.extend_from_slice(&0x0001_u16.to_be_bytes()); // ARType: IOCARSingle
                block.extend_from_slice(&[0x01; 16]); // ARUUID
                block.extend_from_slice(&1_u16.to_be_bytes()); // SessionKey
                block.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // CMResponderMacAdd
                block.extend_from_slice(&34964_u16.to_be_bytes()); // ResponderUDPRTPort
            } else {
                // ARBlockReq (0x0101), length 54
                block.extend_from_slice(&0x0101_u16.to_be_bytes());
                block.extend_from_slice(&54_u16.to_be_bytes());
                block.extend_from_slice(&0x0100_u16.to_be_bytes());
                block.extend_from_slice(&0x0001_u16.to_be_bytes()); // ARType: IOCARSingle
                block.extend_from_slice(&[0x01; 16]); // ARUUID
                block.extend_from_slice(&1_u16.to_be_bytes()); // SessionKey
                block.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // CMInitiatorMacAdd
                block.extend_from_slice(&[0x00; 16]); // CMInitiatorObjectUUID
                block.extend_from_slice(&0_u32.to_be_bytes()); // ARProperties
                block.extend_from_slice(&100_u16.to_be_bytes()); // CMInitiatorActivityTimeoutFactor
                block.extend_from_slice(&34964_u16.to_be_bytes()); // CMInitiatorUDPRTPort
                block.extend_from_slice(&0_u16.to_be_bytes()); // StationNameLength
            }
        }
        2 | 3 => {
            let blk_type = (if opnum == 2 { 0x0009_u16 } else { 0x0008_u16 }) | resp_flag;
            let rec_len = u32::try_from(payload.len()).unwrap_or(0);
            block.extend_from_slice(&blk_type.to_be_bytes());
            block.extend_from_slice(&60_u16.to_be_bytes());
            block.extend_from_slice(&0x0100_u16.to_be_bytes());
            block.extend_from_slice(&1_u16.to_be_bytes()); // SeqNumber
            block.extend_from_slice(&[0x01; 16]); // ARUUID
            block.extend_from_slice(&0_u32.to_be_bytes()); // API
            block.extend_from_slice(&0_u16.to_be_bytes()); // SlotNumber
            block.extend_from_slice(&1_u16.to_be_bytes()); // SubslotNumber
            block.extend_from_slice(&0_u16.to_be_bytes()); // Padding
            block.extend_from_slice(&0x0001_u16.to_be_bytes()); // Index
            let hdr_data_len = if opnum == 2 && !spec.is_response {
                1024
            } else if (opnum == 3 && !spec.is_response) || (opnum == 2 && spec.is_response) {
                rec_len
            } else {
                0
            };
            block.extend_from_slice(&hdr_data_len.to_be_bytes());
            block.extend_from_slice(&[0x00; 24]); // TargetARUUID + RWPadding
            if (opnum == 3 && !spec.is_response) || (opnum == 2 && spec.is_response) {
                block.extend_from_slice(payload);
            }
        }
        4 => {
            // IODControlReq (0x0110) / IODControlRes (0x8110), length 28
            block.extend_from_slice(&(0x0110_u16 | resp_flag).to_be_bytes());
            block.extend_from_slice(&28_u16.to_be_bytes());
            block.extend_from_slice(&0x0100_u16.to_be_bytes());
            block.extend_from_slice(&0_u16.to_be_bytes()); // Reserved
            block.extend_from_slice(&[0x01; 16]); // ARUUID
            block.extend_from_slice(&1_u16.to_be_bytes()); // SessionKey
            block.extend_from_slice(&0_u16.to_be_bytes()); // Reserved
            block.extend_from_slice(&(if spec.is_response { 0x0008_u16 } else { 0x0001_u16 }).to_be_bytes());
            block.extend_from_slice(&0_u16.to_be_bytes()); // ControlBlockProperties
        }
        _ => {
            // IODReleaseReq (0x0104) / IODReleaseRes (0x8104), length 28
            block.extend_from_slice(&(0x0104_u16 | resp_flag).to_be_bytes());
            block.extend_from_slice(&28_u16.to_be_bytes());
            block.extend_from_slice(&0x0100_u16.to_be_bytes());
            block.extend_from_slice(&0_u16.to_be_bytes()); // Reserved
            block.extend_from_slice(&[0x01; 16]); // ARUUID
            block.extend_from_slice(&1_u16.to_be_bytes()); // SessionKey
            block.extend_from_slice(&0_u16.to_be_bytes()); // Reserved
            block.extend_from_slice(&(if spec.is_response { 0x0008_u16 } else { 0x0004_u16 }).to_be_bytes());
            block.extend_from_slice(&0_u16.to_be_bytes()); // ControlBlockProperties
        }
    }

    let block_len = u32::try_from(block.len()).unwrap_or(u32::MAX);
    let mut stub = Vec::with_capacity(20 + block.len());
    if spec.is_response {
        stub.extend_from_slice(&0_u32.to_le_bytes()); // PNIOStatus
    } else {
        stub.extend_from_slice(&1024_u32.to_le_bytes()); // ArgsMaximum
    }
    stub.extend_from_slice(&block_len.to_le_bytes()); // ArgsLength
    stub.extend_from_slice(&1024_u32.to_le_bytes()); // ArrayMaxCount
    stub.extend_from_slice(&0_u32.to_le_bytes()); // Offset
    stub.extend_from_slice(&block_len.to_le_bytes()); // ActualCount
    stub.extend_from_slice(&block);
    if !payload.is_empty()
        && !(opnum == 3 && !spec.is_response)
        && !(opnum == 2 && spec.is_response)
    {
        stub.extend_from_slice(payload);
    }

    let frag_len = u16::try_from(stub.len()).unwrap_or(u16::MAX);
    let mut rpc = Vec::with_capacity(80 + stub.len());
    rpc.push(4); // RPC version 4 (Connectionless)
    rpc.push(ptype);
    rpc.push(0x20); // Flags1: Idempotent/NoFack
    rpc.push(0x00); // Flags2
    rpc.extend_from_slice(&[0x10, 0x00, 0x00]); // DRep: Little-Endian ASCII IEEE
    rpc.push(0x00); // Serial High
    rpc.extend_from_slice(&PNIO_OBJ_UUID);
    rpc.extend_from_slice(&PNIO_CM_IF_UUID);

    // Encode deterministic Activity UUID preserving XID / FrameID / DataStatus / TransferStatus
    rpc.extend_from_slice(&spec.xid.unwrap_or(1).to_le_bytes());
    rpc.extend_from_slice(&spec.frame_id.unwrap_or(0x8000).to_be_bytes());
    rpc.push(spec.data_status.unwrap_or(0x35));
    rpc.push(spec.transfer_status.unwrap_or(0x00));
    rpc.extend_from_slice(&[0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);

    rpc.extend_from_slice(&0_u32.to_le_bytes()); // ServerBootTime
    rpc.extend_from_slice(&1_u32.to_le_bytes()); // InterfaceVersion
    rpc.extend_from_slice(&u32::from(spec.cycle.unwrap_or(1)).to_le_bytes()); // SequenceNumber
    rpc.extend_from_slice(&opnum.to_le_bytes()); // Opnum
    rpc.extend_from_slice(&0_u16.to_le_bytes()); // InterfaceHint
    rpc.extend_from_slice(&0_u16.to_le_bytes()); // ActivityHint
    rpc.extend_from_slice(&frag_len.to_le_bytes()); // FragmentLength
    rpc.extend_from_slice(&0_u16.to_le_bytes()); // FragmentNumber
    rpc.push(0); // AuthProto
    rpc.push(0); // SerialLow
    rpc.extend_from_slice(&stub);
    rpc
}

/// Builds a complete PROFINET wire frame (native L2 `0x8892` by default, or UDP `34964` on `transport udp`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if `transport udp` is requested without matching IPv4/IPv6 endpoints.
pub fn build_profinet_frame(
    ctx: &WireContext,
    spec: &ProfinetSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let body = build_profinet_payload(ctx, spec, payload);
    if ctx.transport == Some(TransportProto::Udp) {
        if ctx.src_ip.is_unspecified() || ctx.dst_ip.is_unspecified() {
            return Err(CompilerError::BackendError(
                "PROFINET with 'transport udp' requires IP addresses on both endpoints"
                    .to_string(),
            ));
        }
        let dport = if ctx.dst_port == 0 { 34964 } else { ctx.dst_port };
        let udp = build_udp_datagram_with_opts(
            ctx.src_ip,
            ctx.dst_ip,
            ctx.src_port,
            dport,
            &body,
            ctx.l4,
        )?;
        let ip_pkt = build_ip_packet(ctx.src_ip, ctx.dst_ip, 17, ctx.l3, &udp)?;
        let ethertype = if ctx.src_ip.is_ipv4() { 0x0800 } else { 0x86DD };
        return Ok(build_ethernet_and_l2(
            ctx.src_mac,
            ctx.dst_mac,
            ctx.l2,
            ethertype,
            &ip_pkt,
        ));
    }

    let dst_mac = ctx.l2.dst_mac.unwrap_or(ctx.dst_mac);
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0x8892,
        &body,
    ))
}
