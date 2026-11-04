# Layer 7 — Industrial Control Systems (ICS) & SCADA/OT

[**Use Cases**](#ot-and-ics-security-testing-use-cases) • [**Protocol Matrix**](#ot-protocol-summary-matrix-6-protocols) • [**Modbus/TCP**](#modbustcp-modbus) • [**DNP3**](#ieee-1815-dnp3-dnp3) • [**Siemens S7comm**](#siemens-s7comm-s7comm) • [**BACnet/IP**](#bacnetip-bacnet) • [**EtherNet/IP**](#odva-ethernetip-ethernetip) • [**OPC UA**](#opc-ua-binary-opcua) • [**Docs Hub**](README.md)

Testing IT firewall rules is forgiving: if you fat-finger a rule, someone complains that Jira is slow. Testing OT/ICS firewall policies and NDR sensors on a live plant floor is less fun—nobody lets you fire unauthorized `Write Single Register` or Siemens `PLC_CONTROL` stop commands at a running S7-1500 or substation RTU just to verify that your new conduit ACL works, and buying €20,000 worth of DIN-rail PLCs for your desk usually gets vetoed by finance.

FrameAssembly compiles wire-accurate **`Modbus/TCP`**, **`DNP3`**, **`S7comm`**, **`BACnet/IP`**, **`EtherNet/IP`**, and **`OPC UA`** `.pcap` / `.pcapng` captures offline in unprivileged user space -> complete with automatic TCP `SEQ`/`ACK` tracking, IEEE 1815 `DNP3` per-chunk CRCs, and 802.1Q `VLAN` / `PCP` priority tags. Feed the output straight into **Suricata**, **Zeek**, **Wireshark** / **`tshark`**, **Claroty** / **Nozomi** / **Dragos** sensors, or **`tcpreplay`** without risking an unplanned factory shutdown :)

## OT and ICS Security Testing Use Cases

### 1. Verify Read-Only Polling vs. Unauthorized PLC Write Blocks (`Modbus/TCP` & `S7comm`)
Most IEC 62443 zone conduits allow an HMI or historian to poll registers (`READ_HOLDING_REGISTERS` / S7 `READ_VAR`) while blocking register writes (`WRITE_SINGLE_REGISTER` / `WRITE_VAR`) and CPU run-state changes (`PLC_CONTROL`) from engineering or IT subnets. Because industrial DPI firewalls drop mid-stream packets that lack a valid 3-way handshake, FrameAssembly tracks the TCP sequence math automatically:

```frameassembly
host scada_hmi { ip 172.22.10.10 mac 00:1b:21:10:00:0a }
host rogue_eng { ip 172.22.99.66 mac 00:50:56:99:00:66 }
host line_plc  { ip 172.22.10.50 mac 00:0e:8c:10:00:32 }

flow modbus_and_s7_dpi_audit(hmi, rogue, plc) {
    // Allowed baseline: HMI polls 4 Modbus holding registers on VLAN 110 (802.1p PCP 6)
    hmi -> plc vlan 110 pcp 6 tcp syn srcport 50502 dstport 502 win 64240 mss 1460 wait 1ms
    hmi <- plc vlan 110 pcp 6 tcp syn ack win 64240 mss 1460 wait 1ms
    hmi -> plc vlan 110 pcp 6 tcp ack wait 1ms
    hmi -> plc vlan 110 pcp 6 modbus read_holding_registers txid 1 unitid 1 addr 100 count 4 wait 2ms
    hmi <- plc vlan 110 pcp 6 modbus read_holding_registers txid 1 unitid 1 count 4 value 1500 is_response wait 2ms

    // Policy violation 1: Rogue host attempts Modbus Write Single Register (Function 0x06)
    rogue -> plc vlan 110 modbus write_single_register txid 99 unitid 1 addr 100 value 0xffff wait 2ms
    rogue <- plc vlan 110 tcp rst ack wait 1ms

    // Policy violation 2: Rogue host negotiates ISO-on-TCP S7comm (port 102) and sends WRITE_VAR + PLC_CONTROL
    rogue -> plc vlan 110 tcp syn srcport 50102 dstport 102 win 64240 mss 1460 wait 1ms
    rogue <- plc vlan 110 tcp syn ack win 64240 mss 1460 wait 1ms
    rogue -> plc vlan 110 tcp ack wait 1ms
    rogue -> plc vlan 110 s7comm rosctr "JOB" setup_comm pdu_ref 1 wait 1ms
    rogue <- plc vlan 110 s7comm rosctr "ACK_DATA" setup_comm pdu_ref 1 wait 1ms
    rogue -> plc vlan 110 s7comm rosctr "JOB" write_var pdu_ref 2 area "DB" db_num 1 offset 0 count 4 hexpayload "deadbeef" wait 2ms
    rogue -> plc vlan 110 s7comm rosctr "JOB" plc_control pdu_ref 3 payload "P_PROGRAM"
}

compile { modbus_and_s7_dpi_audit(scada_hmi, rogue_eng, line_plc) }
```

```console
$ frameassembly plc_dpi.fasm -o plc_dpi.pcap && suricata -r plc_dpi.pcap -k none
```

### 2. Test Substation SCADA Rules Without Computing DNP3 CRCs by Hand (`DNP3`)
Crafting IEEE 1815 `DNP3` packets manually in hex editors or Python scripts is pure misery: DNP3 requires a reflected `0xA653` 16-bit CRC in little-endian byte order on the 10-byte Data Link header **and** after every 16-byte chunk of transport/application data—get one bit wrong and Wireshark or your substation firewall silently discards the frame. FrameAssembly calculates every DNP3 header and chunk CRC automatically (and still lets you pass `crc 0xdead` when you *want* to test malformed-frame drops):

```frameassembly
host scada_master { ip 10.210.1.10 mac 00:1b:21:d2:01:0a }
host substation   { ip 10.210.1.55 mac 00:a0:f4:d2:01:37 }

flow dnp3_substation_check(master, rtu) {
    master -> rtu tcp syn srcport 52000 dstport 20000 win 64240 mss 1460 wait 1ms
    master <- rtu tcp syn ack win 64240 mss 1460 wait 1ms
    master -> rtu tcp ack wait 1ms

    // Class data integrity poll (Group 60, Variation 1) + Analog Input response (Group 30)
    master -> rtu dnp3 read src 1 dst 10 group 60 variation 1 wait 2ms
    master <- rtu dnp3 func "RESPONSE" src 10 dst 1 group 30 variation 1 hexpayload "0100dc05" wait 3ms

    // Select-Before-Operate (SBO) breaker control sequence on CROB (Group 12, Variation 1)
    master -> rtu dnp3 select src 1 dst 10 group 12 variation 1 wait 2ms
    master <- rtu dnp3 func "RESPONSE" src 10 dst 1 group 12 variation 1 wait 2ms
    master -> rtu dnp3 operate src 1 dst 10 group 12 variation 1 wait 2ms
    master <- rtu dnp3 confirm src 10 dst 1 wait 1ms

    // Intentional bad Data Link CRC for firewall frame-integrity drop testing
    master -> rtu dnp3 direct_operate src 1 dst 10 group 12 variation 1 crc 0xdead
}

compile { dnp3_substation_check(scada_master, substation) }
```

```console
$ frameassembly substation.fasm -o substation.pcap && tshark -r substation.pcap -Y dnp3 -V
```

### 3. Audit Building Management, CIP Manufacturing Cells & IDMZ Historians (`BACnet/IP`, `EtherNet/IP`, `OPC UA`)
Modern facilities mix UDP broadcast building controls (`BACnet/IP`), Rockwell/ODVA CIP explicit messaging (`EtherNet/IP`), and cross-zone historian conduits (`OPC UA`). You can synthesize all three into a single regression `.pcap` to validate VLAN segmentation and IDMZ firewall conduits before a maintenance window:

```frameassembly
host bms_srv      { ip 192.168.40.10  mac 00:1b:21:40:00:0a }
host hvac_ctrl    { ip 192.168.40.85  mac 00:40:ae:40:00:55 }
host cell_scanner { ip 172.22.30.10   mac 00:00:bc:30:00:0a }
host cip_drive    { ip 172.22.30.25   mac 00:00:bc:30:00:19 }
host historian    { ip 172.22.200.100 mac 00:50:56:c8:00:64 }

flow bms_and_factory_conduit(bms, hvac, scanner, drive, hist) {
    // BACnet/IP Who-Is discovery + Present_Value (property 85) setpoint write on UDP 47808
    bms -> hvac bacnet who_is wait 2ms
    bms <- hvac bacnet i_am object_type 8 object_instance 4085 wait 2ms
    bms -> hvac bacnet read_property invoke_id 1 object_type 0 object_instance 1 property_id 85 wait 2ms
    bms -> hvac bacnet write_property invoke_id 2 object_type 1 object_instance 1 property_id 85 value 72 wait 2ms

    // ODVA EtherNet/IP session registration + CIP Get_Attribute_Single on TCP 44818
    scanner -> drive tcp syn srcport 54818 dstport 44818 win 64240 mss 1460 wait 1ms
    scanner <- drive tcp syn ack win 64240 mss 1460 wait 1ms
    scanner -> drive tcp ack wait 1ms
    scanner -> drive ethernetip register_session context 0x0102030405060708 wait 1ms
    scanner <- drive ethernetip register_session session_handle 0x00001001 status 0 context 0x0102030405060708 wait 1ms
    scanner -> drive ethernetip send_rr_data session_handle 0x00001001 cip_service 0x0e cip_class 1 cip_instance 1 cip_attr 7 wait 2ms

    // IEC 62443 IDMZ conduit: OPC UA Binary HEL/ACK/OPN handshake + NodeId poll on TCP 4840
    scanner -> hist vlan 200 pcp 4 tcp syn srcport 54840 dstport 4840 win 64240 mss 1460 wait 1ms
    scanner <- hist vlan 200 pcp 4 tcp syn ack win 64240 mss 1460 wait 1ms
    scanner -> hist vlan 200 pcp 4 tcp ack wait 1ms
    scanner -> hist vlan 200 pcp 4 opcua msg_type "HEL" chunk_type "F" endpoint_url "opc.tcp://172.22.200.100:4840" wait 1ms
    scanner <- hist vlan 200 pcp 4 opcua msg_type "ACK" chunk_type "F" wait 1ms
    scanner -> hist vlan 200 pcp 4 opcua msg_type "OPN" chunk_type "F" secure_channel_id 42 token_id 1 seq_num 1 reqid 1 wait 1ms
    scanner -> hist vlan 200 pcp 4 opcua msg_type "MSG" chunk_type "F" secure_channel_id 42 token_id 1 seq_num 2 reqid 2 node_id "Drive01.OutputRPM" payload "1485"
}

compile { bms_and_factory_conduit(bms_srv, hvac_ctrl, cell_scanner, cip_drive, historian) }
```

```console
$ frameassembly show ot_conduit.fasm
$ frameassembly ot_conduit.fasm -o ot_conduit.pcap && sudo tcpreplay -i eth0 ot_conduit.pcap
```

## OT Protocol Summary Matrix (6 Protocols)

| Protocol | Keyword | Default L4 & Port | Dual-Transport Override | Wire Framing & Checksums Handled Automatically |
| :--- | :--- | :--- | :--- | :--- |
| **Modbus/TCP** | `modbus` | TCP `502` | `transport udp` | 7-byte MBAP header + Function `0x01..0x06, 0x10` + byte-counted `is_response` PDU |
| **DNP3** | `dnp3` | TCP `20000` | `transport udp` | 10B `0x0564` Data Link + `0xC0` Transport + App header + IEEE 1815 `0xA653` CRC-16 per 16B chunk |
| **Siemens S7comm** | `s7comm` | TCP `102` | TCP only (RFC 1006) | 4B TPKT v3 + 3B COTP DT Data (`0x02f080`) + 10/12B `0x32` S7 header + `S7ANY` bit-shifted pointers |
| **BACnet/IP** | `bacnet` | UDP `47808` | UDP (`0xBAC0`) | 4B BVLC (`0x81`, `0x0A` unicast / `0x0B` broadcast) + 2B NPDU + packed 32-bit ObjectIdentifier APDU |
| **EtherNet/IP** | `ethernetip` | TCP `44818` | `transport udp` (`dstport 2222`) | 24-byte little-endian Encapsulation Header + CPF items (`0x0000`, `0x00B2`) + CIP EPATH segments |
| **OPC UA Binary** | `opcua` | TCP `4840` | TCP (`UACP`) | 8-byte little-endian UACP header (`HEL`/`ACK`/`OPN`/`CLO`/`MSG`/`ERR`) + SecureChannel & String `NodeId` |

## Detailed Syntax Reference

### Modbus/TCP (`modbus`)
* **Default Transport:** TCP port `502` (add `transport udp` for Modbus over UDP `502`).
* **Syntax:**
  `modbus [read_coils | read_discrete_inputs | read_holding_registers | read_input_registers | write_single_coil | write_single_register | write_multiple_registers | func "<name>"] [txid <u16>] [proto_id <u16>] [unitid <u8>] [addr <u16>] [count <u16>] [value <u16>] [is_response] [transport udp]`
* **Defaults & Reply Mechanics:** Defaults to `read_holding_registers` (`0x03`), `txid 1`, `proto_id 0`, `unitid 1`, `addr 0`, `count 1`, `value 0`. Add `is_response` on `<-` PLC replies to switch from the 4-byte `[addr, count]` request layout to a byte-counted `[byte_count, register_values...]` response PDU.

### IEEE 1815 DNP3 (`dnp3`)
* **Default Transport:** TCP port `20000` (add `transport udp` for DNP3 over UDP `20000`).
* **Syntax:**
  `dnp3 [confirm | read | write | select | operate | direct_operate | unsolicited_response | func "<RESPONSE|...>"] [src <u16>] [dst <u16>] [group <u8>] [variation <u8>] [crc <u16>] [transport udp]`
* **Defaults & Reply Mechanics:** Defaults to `read` (Function `1`), little-endian Data Link `src 100` and `dst 1`, and Object `group 60` / `variation 1` (Qualifier `0x06`) when group or variation is specified. For outstation responses (Function `129`), write `func "RESPONSE"`. Omit `crc` for valid IEEE 1815 frames, or set `crc <u16>` to deliberately corrupt the Data Link header CRC.

### Siemens S7comm (`s7comm`)
* **Default Transport:** TCP port `102` (ISO-on-TCP per RFC 1006).
* **Syntax:**
  `s7comm [setup_comm | read_var | write_var | plc_control | func "<name>"] [rosctr "<JOB|ACK|ACK_DATA|USERDATA>"] [pdu_ref <u16>] [area <u8|"<DB|MK|PE|PA|CT|TM>">] [db_num <u16>] [offset <u32>] [count <u16>]`
* **Defaults & Reply Mechanics:** Defaults to `rosctr "JOB"` (`0x01`), `setup_comm` (`0xF0`), and `pdu_ref 1`. On `ACK` (`0x02`) and `ACK_DATA` (`0x03`) frames, FrameAssembly automatically expands the 10-byte S7 header to 12 bytes with `error_class` and `error_code`. On `read_var` / `write_var`, `area` accepts symbolic names (`"DB"` / `0x84` Data Blocks, `"MK"` / `"M"` `0x83` Merkers, `"PE"` / `"I"` `0x81` Inputs, `"PA"` / `"Q"` `0x82` Outputs, `"CT"` / `"C"` `0x1C` Counters, `"TM"` / `"T"` `0x1D` Timers) and bit-shifts `offset << 3` into the 10-byte `S7ANY` pointer automatically.

### BACnet/IP (`bacnet`)
* **Default Transport:** UDP port `47808` (`0xBAC0`).
* **Syntax:**
  `bacnet [who_is | i_am | read_property | write_property] [invoke_id <u8>] [object_type <u16>] [object_instance <u32>] [property_id <u32>] [value <u32>]`
* **Defaults & Wire Behavior:** Defaults to `who_is` using BVLC function `0x0B` (`Original-Broadcast-NPDU`); `i_am`, `read_property` (`0x0C`), and `write_property` (`0x0F`) automatically switch BVLC to `0x0A` (`Original-Unicast-NPDU`). `object_type` defaults to `8` (`Device`; use `0` Analog Input, `1` Analog Output, `2` Analog Value), `object_instance` defaults to `1234`, and `property_id` defaults to `85` (`Present_Value`). Do not attach TCP flags to `bacnet` statements.

### ODVA EtherNet/IP (`ethernetip`)
* **Default Transport:** TCP port `44818` (for implicit I/O over UDP, combine `transport udp dstport 2222`).
* **Syntax:**
  `ethernetip [list_identity | list_services | list_interfaces | register_session | unregister_session | send_rr_data | send_unit_data | cmd "<NOP|...>"] [session_handle <u32>] [status <u32>] [context <u64>] [cip_service <u8>] [cip_class <u16>] [cip_instance <u16>] [cip_attr <u16>] [transport udp]`
* **Defaults & Wire Behavior:** Defaults to `list_identity` (`0x0063`), or automatically upgrades to `send_rr_data` (`0x006F`) with Common Packet Format (`CPF`) Unconnected Data (`0x00B2`) whenever `cip_service` (default `0x0E` `Get_Attribute_Single`), `cip_class` (default `1` Identity Object), `cip_instance` (default `1`), or `cip_attr` is present.

### OPC UA Binary (`opcua`)
* **Default Transport:** TCP port `4840`.
* **Syntax:**
  `opcua [msg_type "<HEL|ACK|OPN|CLO|MSG|ERR>"] [chunk_type "<F|C|A>"] [secure_channel_id <u32>] [token_id <u32>] [seq_num <u32>] [reqid <u32>] [endpoint_url "<url>"] [node_id "<id>"]`
* **Defaults & Wire Behavior:** Defaults to `msg_type "HEL"` (or `"MSG"` if `node_id` is supplied without `endpoint_url`) and `chunk_type "F"` (Final). `HEL` and `ACK` populate 64 KB receive/send buffer negotiation fields, while `OPN`, `CLO`, `MSG`, and `ERR` encode little-endian `secure_channel_id`, `token_id`, `seq_num`, `reqid`, and namespace-0 String `NodeId` headers.

## Related Guides

* [**Practical Use-Case Cookbook (`docs/use_cases.md`)**](use_cases.md) — End-to-end firewall ACL, IDS, and NetOps recipes.
* [**Topologies & Dual-Stack (`docs/topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Multi-zone Purdue conduits, VLAN/QinQ trunks, and IPv4/IPv6 reuse.
* [**Layer 2 Switching & VLANs (`docs/l2_protocols.md`)**](l2_protocols.md) — 802.1Q `VLAN`, 802.1p `PCP` QoS markings, `RSTP`, and `LLDP` for industrial rings.