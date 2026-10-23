//! BACNET industrial OT protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an ANSI/ASHRAE 135 BACnet/IP packet payload with BVLC and NPDU headers.
pub fn build_bacnet_payload(
    _ctx: &WireContext,
    spec: &BacnetSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut apdu = Vec::new();
    let is_broadcast = spec.is_who_is || (!spec.is_i_am && !spec.is_read_property && !spec.is_write_property);

    if spec.is_read_property {
        // Confirmed-Request APDU (Type 0)
        apdu.push(0x00); // PDU Type 0: Confirmed-REQ
        apdu.push(0x05); // Max Seg / Max Resp (1476 octets)
        apdu.push(spec.invoke_id.unwrap_or(1)); // Invoke ID
        apdu.push(0x0C); // Service Choice: ReadProperty (12)

        let obj_type = spec.object_type.unwrap_or(8); // Device (8)
        let obj_inst = spec.object_instance.unwrap_or(1234);
        let obj_id = ((obj_type as u32) << 22) | (obj_inst & 0x3FFFFF);
        apdu.extend_from_slice(&[0x0C]); // Context Tag 0 (ObjectIdentifier, len 4)
        apdu.extend_from_slice(&obj_id.to_be_bytes());
        apdu.extend_from_slice(&[0x19]); // Context Tag 1 (PropertyIdentifier, len 1)
        apdu.push(spec.property_id.unwrap_or(85) as u8); // 85: Present_Value
    } else if spec.is_i_am {
        // Unconfirmed-Request APDU (Type 1): I-Am (Service Choice 0)
        apdu.push(0x10);
        apdu.push(0x00);
        let obj_inst = spec.object_instance.unwrap_or(1234);
        let obj_id = (8u32 << 22) | (obj_inst & 0x3FFFFF);
        apdu.extend_from_slice(&[0xC4]); // Application Tag 12: ObjectIdentifier
        apdu.extend_from_slice(&obj_id.to_be_bytes());
        apdu.extend_from_slice(&[0x22, 0x04, 0x00]); // Max APDU length accepted: 1024
        apdu.extend_from_slice(&[0x91, 0x00]); // Segmentation supported: no-segmentation (0)
        apdu.extend_from_slice(&[0x21, 0x01]); // Vendor ID: 1
    } else {
        // Default: Who-Is Unconfirmed-Request APDU (Type 1): Who-Is (Service Choice 8)
        apdu.push(0x10); // Unconfirmed-REQ
        apdu.push(0x08); // Service Choice: Who-Is (8)
    }

    if !payload_bytes.is_empty() {
        apdu.extend_from_slice(payload_bytes);
    }

    let npdu = [0x01, 0x00]; // Version 1, Control 0 (no network routing)
    let total_len = (4 + npdu.len() + apdu.len()) as u16;

    let bvlc_func = if is_broadcast {
        0x0B // Original-Broadcast-NPDU
    } else {
        0x0A // Original-Unicast-NPDU
    };

    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.push(0x81); // BVLC Type: BACnet/IP (0x81)
    pkt.push(bvlc_func);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&npdu);
    pkt.extend_from_slice(&apdu);
    pkt
}
