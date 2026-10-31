# Layer 7 Industrial Control Systems (ICS), SCADA & OT Reference

FrameAssembly implements native wire builders for **6 industrial, building-automation, electrical substation, and factory PLC protocols**, enabling IEC 62443 firewall testing, Purdue Level 1–3.5 zone verification, and OT IDS rule validation without physical controllers.

| Protocol | Keyword | Default Port | Standard | Supported Operations & Modifiers |
| :--- | :--- | :--- | :--- | :--- |
| **Modbus TCP** | `MODBUS` | TCP `502` | Modbus v1.1b3 | `FUNC "<name>"`, `TXID <u16>`, `PROTO_ID <u16>`, `UNITID <u8>`, `ADDR <u16>`, `COUNT <u16>`, `VALUE <u16>`, `IS_RESPONSE` |
| **BACnet/IP** | `BACNET` | UDP `47808` | ANSI/ASHRAE 135 | `WHO_IS`, `I_AM`, `READ_PROPERTY`, `WRITE_PROPERTY`, `INVOKE_ID <u8>`, `OBJECT_TYPE <u16>`, `OBJECT_INSTANCE <u32>`, `PROPERTY_ID <u32>`, `VALUE <u32>` |
| **DNP3** | `DNP3` | TCP `20000` | IEEE 1815-2012 | `FUNC "<name>"`, `SRC <u16>`, `DST <u16>`, `SEQ <u8>`, `GROUP <u8>`, `VARIATION <u8>`, `CRC <u16>` |
| **Siemens S7comm**| `S7COMM` | TCP `102` | RFC 1006 / ISO 8073| `ROSCTR "<JOB\|ACK\|ACK_DATA\|USERDATA>"`, `FUNC "<SETUP_COMM\|READ_VAR\|WRITE_VAR\|PLC_CONTROL>"`, `PDU_REF <u16>`, `AREA <u8>`, `DB_NUM <u16>`, `OFFSET <u32>`, `COUNT <u16>` |
| **EtherNet/IP** | `ETHERNETIP`| TCP `44818` | ODVA CIP | `CMD "<name>"`, `SESSION_HANDLE <u32>`, `STATUS <u32>`, `CONTEXT <u64>`, `CIP_SERVICE <u8>`, `CIP_CLASS <u16>`, `CIP_INSTANCE <u16>`, `CIP_ATTR <u16>` |
| **OPC UA Binary**| `OPCUA` | TCP `4840` | IEC 62541 | `MSG_TYPE "<HEL\|ACK\|ERR\|OPN\|CLO\|MSG>"`, `CHUNK_TYPE "<F\|C\|A>"`, `SECURE_CHANNEL_ID <u32>`, `TOKEN_ID <u32>`, `SEQ_NUM <u32>`, `REQID <u32>`, `ENDPOINT_URL "<url>"`, `NODE_ID "<str>"` |

---

## 1. Modbus TCP (`MODBUS` — TCP Port 502)

Encapsulates Modbus function codes inside a 7-byte MBAP header (`TXID`, `PROTO_ID 0x0000`, computed `Length`, and `UNITID`).
* **`FUNC` values:** `"READ_COILS"` (`0x01`), `"READ_DISCRETE_INPUTS"` (`0x02`), `"READ_HOLDING_REGISTERS"` (`0x03` default), `"READ_INPUT_REGISTERS"` (`0x04`), `"WRITE_SINGLE_COIL"` (`0x05`), `"WRITE_SINGLE_REGISTER"` (`0x06`), `"WRITE_MULTIPLE_REGISTERS"` (`0x10`).
* **Directionality:** Omit `IS_RESPONSE` for HMI Master requests; add `IS_RESPONSE` for PLC Slave replies.

```frameassembly
host scada_hmi   { ip 192.168.100.10 }
host turbine_plc { ip 192.168.100.50 }

flow modbus_polling_cycle(hmi, plc) {
    hmi -> plc modbus func "READ_HOLDING_REGISTERS" txid 101 unitid 1 addr 40001 count 4 wait 2ms
    hmi <- plc modbus func "READ_HOLDING_REGISTERS" txid 101 unitid 1 count 4 is_response wait 5ms
    hmi -> plc modbus func "WRITE_SINGLE_REGISTER" txid 102 unitid 1 addr 40010 value 1500 wait 2ms
    hmi <- plc modbus func "WRITE_SINGLE_REGISTER" txid 102 unitid 1 addr 40010 value 1500 is_response
}

compile {
    modbus_polling_cycle(scada_hmi, turbine_plc)
}
```

---

## 2. BACnet/IP (`BACNET` — UDP Port 47808)

Encodes BVLC (`0x81`), NPDU (`0x01`), and APDU layers for building management and HVAC controllers:
* **Services:** `WHO_IS` (broadcast BVLC `0x0B`), `I_AM`, `READ_PROPERTY` (default), `WRITE_PROPERTY`.
* **Object & Property IDs:** `OBJECT_TYPE <u16>` (`0`=Analog Input, `1`=Analog Output, `2`=Analog Value, `3`=Binary Input, `4`=Binary Output, `8`=Device), `OBJECT_INSTANCE <u32>`, `PROPERTY_ID <u32>` (`85`=Present Value, `77`=Object Name, `111`=Status Flags), `VALUE <u32>`, `INVOKE_ID <u8>`.

```frameassembly
host bms_server  { ip 10.120.1.10 }
host chiller_ahu { ip 10.120.1.50 }

flow bacnet_hvac_control(bms, ahu) {
    bms -> ahu bacnet who_is wait 2ms
    bms <- ahu bacnet i_am object_type 8 object_instance 1010 wait 5ms
    bms -> ahu bacnet read_property invoke_id 10 object_type 0 object_instance 1 property_id 85 wait 2ms
    bms <- ahu bacnet read_property invoke_id 10 object_type 0 object_instance 1 property_id 85 value 68 wait 5ms
    bms -> ahu bacnet write_property invoke_id 11 object_type 2 object_instance 2 property_id 85 value 72
}

compile {
    bacnet_hvac_control(bms_server, chiller_ahu)
}
```

---

## 3. Distributed Network Protocol v3 (`DNP3` — TCP Port 20000)

Serializes IEEE 1815 `0x0564` Data Link headers, Transport headers, Application Object headers (`GROUP`, `VARIATION`), and automatic little-endian IEEE 1815 CRC-16 checksums across both the 8-byte header and every 16-byte data block (with optional `CRC <u16>` override for dissector fuzz/negative testing).
* **`FUNC` values:** `"CONFIRM"`, `"READ"`, `"WRITE"`, `"SELECT"`, `"OPERATE"`, `"DIRECT_OPERATE"`, `"RESPONSE"`, `"UNSOLICITED_RESPONSE"`.

```frameassembly
host dms_master     { ip 10.200.1.1 }
host substation_rtu { ip 10.200.1.50 }

flow dnp3_breaker_control(master, rtu) {
    // Class 0 integrity poll (Group 60 Variation 1)
    master -> rtu dnp3 func "READ" src 1 dst 50 seq 1 group 60 variation 1 wait 3ms
    master <- rtu dnp3 func "RESPONSE" src 50 dst 1 seq 1 group 30 variation 1 wait 5ms

    // CROB Relay Select-Before-Operate sequence (Group 12 Variation 1)
    master -> rtu dnp3 func "SELECT" src 1 dst 50 seq 2 group 12 variation 1 wait 2ms
    master <- rtu dnp3 func "RESPONSE" src 50 dst 1 seq 2 group 12 variation 1 wait 2ms
    master -> rtu dnp3 func "OPERATE" src 1 dst 50 seq 3 group 12 variation 1 wait 2ms
    master <- rtu dnp3 func "RESPONSE" src 50 dst 1 seq 3 group 12 variation 1
}

compile {
    dnp3_breaker_control(dms_master, substation_rtu)
}
```

---

## 4. Factory PLCs: Siemens S7 (`S7COMM`), EtherNet/IP (`ETHERNETIP`) & OPC UA (`OPCUA`)

* **`S7COMM` (TCP 102):** TPKT + ISO COTP + `0x32` S7 PDU (10-byte header on `"JOB"`/`"USERDATA"`, 12-byte header with 2-byte error status on `"ACK"`/`"ACK_DATA"`). Modifiers: `ROSCTR "<JOB|ACK|ACK_DATA|USERDATA>"`, `FUNC "<SETUP_COMM|READ_VAR|WRITE_VAR|PLC_CONTROL>"`, `PDU_REF <u16>`, `AREA <u8>` (`0x84`=DB, `0x83`=Merker, `0x81`=Inputs, `0x82`=Outputs), `DB_NUM <u16>`, `OFFSET <u32>`, `COUNT <u16>`.
* **`ETHERNETIP` (TCP 44818):** 24-byte little-endian encapsulation header + Common Packet Format (CPF) + logical EPATH (`Class`/`Instance`/`Attribute`). Modifiers: `CMD "<NOP|LIST_SERVICES|LIST_IDENTITY|LIST_INTERFACES|REGISTER_SESSION|UNREGISTER_SESSION|SEND_RR_DATA|SEND_UNIT_DATA>"`, `SESSION_HANDLE <u32>`, `STATUS <u32>`, `CONTEXT <u64>`, `CIP_SERVICE <u8>` (`0x0e`=Get_Attribute_Single, `0x10`=Set_Attribute_Single), `CIP_CLASS <u16>`, `CIP_INSTANCE <u16>`, `CIP_ATTR <u16>`.
* **`OPCUA` (TCP 4840):** IEC 62541 binary chunks: `MSG_TYPE "<HEL|ACK|ERR|OPN|CLO|MSG>"`, `CHUNK_TYPE "<F|C|A>"`, `SECURE_CHANNEL_ID <u32>`, `TOKEN_ID <u32>`, `SEQ_NUM <u32>`, `REQID <u32>`, `ENDPOINT_URL "<url>"`, `NODE_ID "<str>"`.

```frameassembly
host eng_station { ip 10.80.10.5 }
host cell_plc    { ip 10.80.10.20 }

flow multi_vendor_factory_cell(eng, plc) {
    // 1. Siemens S7comm Setup & DB1 Read/Write
    eng -> plc s7comm rosctr "JOB" func "SETUP_COMM" pdu_ref 100 wait 2ms
    eng <- plc s7comm rosctr "ACK_DATA" func "SETUP_COMM" pdu_ref 100 wait 2ms
    eng -> plc s7comm rosctr "JOB" func "READ_VAR" pdu_ref 101 area 0x84 db_num 1 offset 0 count 8 wait 2ms
    eng <- plc s7comm rosctr "ACK_DATA" func "READ_VAR" pdu_ref 101 count 8 wait 5ms

    // 2. ODVA EtherNet/IP Session Registration & CIP Assembly Read
    eng -> plc ethernetip cmd "REGISTER_SESSION" session_handle 1001 wait 2ms
    eng <- plc ethernetip cmd "REGISTER_SESSION" session_handle 1001 status 0 wait 2ms
    eng -> plc ethernetip cmd "SEND_RR_DATA" session_handle 1001 cip_service 0x0e cip_class 0x04 cip_instance 100 cip_attr 3 wait 5ms

    // 3. OPC UA Binary Hello, OpenSecureChannel, Read Node, and Close
    eng -> plc opcua msg_type "HEL" chunk_type "F" endpoint_url "opc.tcp://10.80.10.20:4840/plc" wait 2ms
    eng <- plc opcua msg_type "ACK" chunk_type "F" wait 2ms
    eng -> plc opcua msg_type "OPN" chunk_type "F" secure_channel_id 10 seq_num 1 reqid 1 wait 2ms
    eng -> plc opcua msg_type "MSG" chunk_type "F" secure_channel_id 10 token_id 1 seq_num 2 reqid 2 node_id "ns=2;s=Cell01.SpindleRPM" wait 2ms
    eng -> plc opcua msg_type "CLO" chunk_type "F" secure_channel_id 10 token_id 1 seq_num 3 reqid 3
}

compile {
    multi_vendor_factory_cell(eng_station, cell_plc)
}
```