# Layer 7 Industrial Control Systems (ICS), SCADA & OT Reference

Nobody in their right mind tests a new industrial firewall rule or OT intrusion detection sensor by firing write commands at a live spinning turbine or substation breaker relay—and building a physical lab rack of Rockwell, Siemens, and DNP3 outstations costs a small fortune. FrameAssembly solves that with a few lines of `.fasm` code and two CLI commands:

```bash
# 1. Compile the .fasm code into a deterministic, checksum-valid .pcap capture
frameassembly ot_conduit.fasm -o ot_conduit.pcap

# 2. Replay the capture onto the test interface (or inspect ot_conduit.pcap in Wireshark / Suricata / Zeek)
sudo tcpreplay -i eth0 ot_conduit.pcap
```

This guide covers all **6 built-in Industrial Control System (ICS), building-automation, electrical substation, and factory PLC protocols**:
**`MODBUS`**, **`BACNET`**, **`DNP3`**, **`S7COMM`**, **`ETHERNETIP`**, and **`OPCUA`**.

OT security engineers, industrial firewall administrators, and SCADA system integrators use these protocols to validate:
- **Purdue Model (ISA-95 / IEC 62443) Zone & Conduit Firewalls:** Verify that deep packet inspection (DPI) policies between Level 3 (Site Operations / Historian), Level 2 (Supervisory HMI), and Level 1 (PLCs / RTUs / IEDs) allow read-only polling while blocking unauthorized register/coil writes or PLC STOP commands.
- **OT Intrusion Detection & Asset Discovery Sensors:** Validate dissectors and alert rules in Dragos, Claroty, Nozomi Networks, Cisco Cyber Vision, Palo Alto App-ID, Fortinet OT Security, Zeek, and Suricata—without risking live factory controllers or physical substation relays.

---

## Quick ICS / OT Protocol & Purdue Zone Matrix

Every protocol below works with **zero mandatory modifiers** (emitting a complete, standards-compliant default frame on its IANA port) or with explicit field overrides.

| Protocol | Keyword | Default Port | Standard | Typical Purdue Levels | Primary OT Firewall & IDS Inspection Fields |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Modbus TCP** | `MODBUS` | TCP `502` | Modbus v1.1b3 | Level 2 HMI $\leftrightarrow$ Level 1 PLC | `UNITID`, Function Code (`0x01..0x04` Read vs. `0x05/0x06/0x10` Write), Register `ADDR` & `COUNT` |
| **BACnet/IP** | `BACNET` | UDP `47808` (`0xBAC0`) | ANSI/ASHRAE 135 | BMS Server $\leftrightarrow$ HVAC / Chiller | BVLC Unicast/Broadcast, `WHO_IS`/`I_AM`, `READ_PROPERTY` vs. `WRITE_PROPERTY`, `OBJECT_TYPE` |
| **DNP3** | `DNP3` | TCP / UDP `20000` | IEEE 1815-2012 | Utility DMS $\leftrightarrow$ Substation RTU | Data Link `SRC`/`DST`, Function (`READ` vs. `SELECT`/`OPERATE`/`DIRECT_OPERATE`), `GROUP`/`VARIATION`, CRC-16 |
| **Siemens S7comm**| `S7COMM` | TCP `102` | RFC 1006 / ISO 8073| Eng. Workstation $\leftrightarrow$ S7 PLC | `ROSCTR` (`JOB` vs. `ACK_DATA`), `FUNC` (`READ_VAR` vs. `WRITE_VAR`/`PLC_CONTROL`), `AREA`, `DB_NUM` |
| **EtherNet/IP** | `ETHERNETIP`| TCP `44818` | ODVA CIP | Cell Controller $\leftrightarrow$ Logix PLC | Encapsulation `CMD` (`REGISTER_SESSION`, `SEND_RR_DATA`), `CIP_SERVICE`, `CIP_CLASS`/`INSTANCE`/`ATTR` |
| **OPC UA Binary**| `OPCUA` | TCP `4840` | IEC 62541-6 | Level 3.5 IDMZ Historian $\leftrightarrow$ Server| UACP `MSG_TYPE` (`HEL`, `ACK`, `OPN`, `MSG`, `CLO`), `SECURE_CHANNEL_ID`, `ENDPOINT_URL`, `NODE_ID` |

---

## 1. Modbus TCP (`MODBUS` — Default: TCP Port `502`)

A classic Purdue Level 2-to-Level 1 conduit policy permits HMI read polling (Function Codes `0x01..0x04`) on TCP port `502` while blocking unauthorized coil or holding-register writes (`0x05`, `0x06`, `0x10`). Instead of wiring up a Modbus simulator and a physical PLC, you can script both read polls and write attempts in `.fasm` code. On the wire, `MODBUS` wraps a Modbus Protocol Data Unit (PDU: 1-byte Function Code + register address/count/value fields) inside a 7-byte **MBAP (Modbus Application Protocol) header**:
- Bytes `0..2`: 16-bit big-endian Transaction Identifier (`TXID`)
- Bytes `2..4`: 16-bit Protocol Identifier (`PROTO_ID`, `0x0000` for standard Modbus)
- Bytes `4..6`: 16-bit computed byte `Length` (Unit ID byte + PDU length)
- Byte `6`: 8-bit Slave Unit Identifier (`UNITID`)

### 1.1 `MODBUS` Modifiers

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Func** | `READ_COILS` \| `READ_DISCRETE_INPUTS` \| `READ_HOLDING_REGISTERS` \| `READ_INPUT_REGISTERS` \| `WRITE_SINGLE_COIL` \| `WRITE_SINGLE_REGISTER` \| `WRITE_MULTIPLE_REGISTERS` | `READ_HOLDING_REGISTERS` | Bare keyword setting the 1-byte Modbus Function Code |
| **`FUNC`** | `FUNC "<name>"` | `"READ_HOLDING_REGISTERS"`| Explicit function name string (same 7 values as above) |
| **`TXID`** | `TXID <0..65535>` | `1` | 16-bit MBAP Transaction Identifier correlating master requests and slave replies |
| **`PROTO_ID`** | `PROTO_ID <0..65535>` | `0` (`0x0000`) | 16-bit MBAP Protocol Identifier (`0` = standard Modbus TCP) |
| **`UNITID`** | `UNITID <0..255>` | `1` | 8-bit Unit Identifier (slave station address behind a Modbus TCP-to-RTU gateway) |
| **`ADDR`** | `ADDR <0..65535>` | `0` | 16-bit starting coil or register reference address |
| **`COUNT`** | `COUNT <0..65535>` | `1` | Quantity of coils or 16-bit registers to read/write |
| **`VALUE`** | `VALUE <0..65535>` | `0` | 16-bit coil/register value written in requests or returned in `IS_RESPONSE` frames |
| **`IS_RESPONSE`** | `IS_RESPONSE` | Off (Master Request) | Formats the PDU as a PLC Slave response (encoding `ByteCount = COUNT * 2` followed by `COUNT` big-endian `VALUE` words) |

### 1.2 Supported Modbus Function Codes

| Function Name / Keyword | Hex / Dec Code | Access Type | Typical OT Firewall Policy |
| :--- | :--- | :--- | :--- |
| `READ_COILS` | `0x01` (`1`) | Read (1-bit Coils) | Permitted from HMI / Historian |
| `READ_DISCRETE_INPUTS` | `0x02` (`2`) | Read (1-bit Contacts) | Permitted from HMI / Historian |
| `READ_HOLDING_REGISTERS` | `0x03` (`3`) | Read (16-bit R/W Regs) | Permitted from HMI / Historian (Default) |
| `READ_INPUT_REGISTERS` | `0x04` (`4`) | Read (16-bit Analog In) | Permitted from HMI / Historian |
| `WRITE_SINGLE_COIL` | `0x05` (`5`) | Write (1-bit Actuator) | Restricted to authorized Level 2 Operator HMI |
| `WRITE_SINGLE_REGISTER` | `0x06` (`6`) | Write (16-bit Setpoint) | Restricted to authorized Level 2 Operator HMI |
| `WRITE_MULTIPLE_REGISTERS`| `0x10` (`16`) | Bulk Write (16-bit Regs)| Blocked from Level 3/IDMZ; audited on Level 2 |

### Compilable Example: Modbus TCP HMI Polling & Setpoint Write Cycle

```frameassembly
host scada_hmi   { ip 192.168.100.10 mac 00:1b:21:64:00:0a }
host turbine_plc { ip 192.168.100.50 mac 00:80:f4:64:00:32 }

flow modbus_hmi_to_plc(hmi, plc) {
    // 1. Read 4 Holding Registers (0x03) starting at address 40001
    hmi -> plc modbus read_holding_registers txid 101 unitid 1 addr 40001 count 4 wait 2ms
    hmi <- plc modbus read_holding_registers txid 101 unitid 1 count 4 value 1480 is_response wait 5ms

    // 2. Read 2 Analog Input Registers (0x04) at address 30010
    hmi -> plc modbus func "READ_INPUT_REGISTERS" txid 102 unitid 1 addr 30010 count 2 wait 2ms
    hmi <- plc modbus func "READ_INPUT_REGISTERS" txid 102 unitid 1 count 2 value 725 is_response wait 5ms

    // 3. Write Single Holding Register (0x06) to update governor RPM setpoint
    hmi -> plc modbus write_single_register txid 103 unitid 1 addr 40010 value 1500 wait 2ms
    hmi <- plc modbus write_single_register txid 103 unitid 1 addr 40010 value 1500 is_response
}

compile {
    modbus_hmi_to_plc(scada_hmi, turbine_plc)
}
```

---

## 2. BACnet/IP (`BACNET` — Default: UDP Port `47808` / `0xBAC0`)

Building Management Systems (BMS), data-center chillers, and HVAC controllers speak BACnet/IP over UDP port `47808` (`0xBAC0`). To test campus segmentation between BMS workstations and field controllers without touching the building's air conditioning, write the discovery and property exchange in `.fasm` code. `BACNET` builds ANSI/ASHRAE 135 Building Automation and Control Networks frames over UDP port `47808` (`0xBAC0`), packing:
1. **4-byte BVLC (BACnet Virtual Link Control) Header:** Type `0x81` (`BACnet/IP`), Function `0x0B` (`Original-Broadcast-NPDU` for `WHO_IS`) or `0x0A` (`Original-Unicast-NPDU` for `I_AM`, `READ_PROPERTY`, and `WRITE_PROPERTY`), and 16-bit total length.
2. **2-byte NPDU (Network Layer) Header:** Protocol Version `0x01`, Control `0x00`.
3. **APDU (Application Layer):** Encodes unconfirmed discovery (`Who-Is` / `I-Am`) or confirmed property access (`ReadProperty` / `WriteProperty`) with a packed 32-bit `ObjectIdentifier` (`(object_type << 22) | (object_instance & 0x3FFFFF)`), context-tagged `PropertyIdentifier`, and application-tagged unsigned integer `PropertyValue`.

### 2.1 `BACNET` Modifiers

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`WHO_IS`** | `WHO_IS` | Default if none set | Unconfirmed-Request APDU (`0x10`, Service `0x08` `Who-Is`) over BVLC Broadcast (`0x0B`) |
| **`I_AM`** | `I_AM` | Off | Unconfirmed-Request APDU (`0x10`, Service `0x00` `I-Am`) announcing Device Object ID |
| **`READ_PROPERTY`** | `READ_PROPERTY` | Off | Confirmed-Request APDU (`0x00`, Service `0x0C` `ReadProperty`) over BVLC Unicast (`0x0A`) |
| **`WRITE_PROPERTY`** | `WRITE_PROPERTY` | Auto if `VALUE` set | Confirmed-Request APDU (`0x00`, Service `0x0F` `WriteProperty`) writing `VALUE` |
| **`INVOKE_ID`** | `INVOKE_ID <0..255>` | `1` | 8-bit APDU correlation Invoke ID for `READ_PROPERTY` and `WRITE_PROPERTY` |
| **`OBJECT_TYPE`** | `OBJECT_TYPE <0..1023>` | `8` (`Device`) | 10-bit BACnet Object Type (`0` = Analog Input, `1` = Analog Output, `2` = Analog Value, `3` = Binary Input, `4` = Binary Output, `5` = Binary Value, `8` = Device) |
| **`OBJECT_INSTANCE`**| `OBJECT_INSTANCE <0..4194303>` | `1234` | 22-bit BACnet Object Instance number (`0..4194303`) |
| **`PROPERTY_ID`** | `PROPERTY_ID <number>` | `85` (`Present_Value`)| BACnet Property Identifier (`85` = `Present_Value`, `77` = `Object_Name`, `111` = `Status_Flags`, `28` = `Description`) |
| **`VALUE`** | `VALUE <number>` | Omitted | Application-tagged 32-bit unsigned integer property value |

### Compilable Example: BACnet/IP BMS Discovery, Sensor Read & Chiller Setpoint Write

```frameassembly
host bms_workstation { ip 10.120.1.10 }
host hvac_controller { ip 10.120.1.50 }

flow bacnet_building_automation(bms, ahu) {
    // 1. Broadcast Who-Is discovery and unicast I-Am reply for Device #1010
    bms -> ahu bacnet who_is wait 2ms
    bms <- ahu bacnet i_am object_type 8 object_instance 1010 wait 5ms

    // 2. Read Present_Value (85) of Analog Input #1 (Supply Air Temp)
    bms -> ahu bacnet read_property invoke_id 10 object_type 0 object_instance 1 property_id 85 wait 2ms
    bms <- ahu bacnet read_property invoke_id 10 object_type 0 object_instance 1 property_id 85 value 58 wait 5ms

    // 3. Write Present_Value (85) = 72 to Analog Value #2 (Zone Temp Setpoint)
    bms -> ahu bacnet write_property invoke_id 11 object_type 2 object_instance 2 property_id 85 value 72
}

compile {
    bacnet_building_automation(bms_workstation, hvac_controller)
}
```

---

## 3. Distributed Network Protocol v3 (`DNP3` — Default: TCP / UDP Port `20000`)

Crafting IEEE 1815 DNP3 packets by hand is notoriously painful because DNP3 requires a reflected CRC-16 (`0xA653`) on the 10-byte Data Link header *and* a separate CRC-16 after every 16-byte chunk of application data—get one bit wrong and Wireshark or your substation firewall drops the frame as corrupted. FrameAssembly computes every DNP3 CRC-16 automatically from `.fasm` code, letting you simulate Class 0 integrity polls (`READ`) and Control Relay Output Block (`CROB` Group `12`) `SELECT` / `OPERATE` breaker sequences for electrical substations, water treatment plants, and oil/gas RTUs:
1. **10-byte Data Link Layer Header:** Start bytes `0x0564`, `Length`, Control byte `0xC4`, 16-bit little-endian `DST` and `SRC` outstation addresses, and a 16-bit little-endian **IEEE 1815 DNP3 CRC-16** (reflected polynomial `0xA653`, initial `0x0000`, inverted remainder).
2. **1-byte Transport Header (`0xC0`):** `FIN = 1`, `FIR = 1`, `SEQ = 0`.
3. **Application Layer & Object Header:** Application Control (`0xC0`), 1-byte Function Code, Object `GROUP` and `VARIATION`, Qualifier `0x06` (all objects), and automatic 16-bit DNP3 CRC-16 appended after every 16-byte user data block.

### 3.1 `DNP3` Modifiers

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Func** | `CONFIRM` \| `READ` \| `WRITE` \| `SELECT` \| `OPERATE` \| `DIRECT_OPERATE` \| `UNSOLICITED_RESPONSE` | `READ` | Bare keyword setting the DNP3 Application Function Code |
| **`FUNC`** | `FUNC "<name>"` | `"READ"` | Explicit function string (`"CONFIRM"` `0`, `"READ"` `1`, `"WRITE"` `2`, `"SELECT"` `3`, `"OPERATE"` `4`, `"DIRECT_OPERATE"` `5`, `"RESPONSE"` `129`, `"UNSOLICITED_RESPONSE"` `130`) |
| **`SRC`** | `SRC <0..65535>` | `100` | 16-bit little-endian Data Link source address (Master or Outstation ID) |
| **`DST`** | `DST <0..65535>` | `1` | 16-bit little-endian Data Link destination address |
| **`GROUP`** | `GROUP <0..255>` | `60` (if set) | DNP3 Object Group (`1` Binary Input, `10` Binary Output, `12` CROB Control Relay, `30` Analog Input, `40` Analog Output, `60` Class 0/1/2/3 Data) |
| **`VARIATION`** | `VARIATION <0..255>` | `1` (if set) | DNP3 Object Variation (`1` = Class 0 / 32-bit with flags, `2` = Class 1, `3` = Class 2, `4` = Class 3) |
| **`CRC`** | `CRC <0..65535>` | Auto-computed | Overrides the 16-bit Data Link header CRC (useful for testing IDS checksum-anomaly rules) |

### Compilable Example: Substation Class 0 Poll & Select-Before-Operate Breaker Trip

```frameassembly
host dms_master     { ip 10.200.1.1  mac 00:1b:21:c8:01:01 }
host substation_rtu { ip 10.200.1.50 mac 00:a0:c9:c8:01:32 }

flow dnp3_substation_control(master, rtu) {
    // 1. Class 0 Integrity Poll (Group 60 Variation 1) and Analog Input Response (Group 30 Variation 1)
    master -> rtu dnp3 read src 1 dst 50 group 60 variation 1 wait 3ms
    master <- rtu dnp3 func "RESPONSE" src 50 dst 1 group 30 variation 1 wait 5ms

    // 2. Control Relay Output Block (CROB Group 12 Variation 1) Select-Before-Operate sequence
    master -> rtu dnp3 select src 1 dst 50 group 12 variation 1 wait 2ms
    master <- rtu dnp3 func "RESPONSE" src 50 dst 1 group 12 variation 1 wait 2ms
    master -> rtu dnp3 operate src 1 dst 50 group 12 variation 1 wait 2ms
    master <- rtu dnp3 func "RESPONSE" src 50 dst 1 group 12 variation 1 wait 2ms
    master -> rtu dnp3 confirm src 1 dst 50
}

compile {
    dnp3_substation_control(dms_master, substation_rtu)
}
```

---

## 4. Siemens SIMATIC S7comm (`S7COMM` — Default: TCP Port `102`)

Validating deep packet inspection rules for Siemens SIMATIC S7-300/400/1200/1500 PLCs—such as allowing `READ_VAR` (`0x04`) on Data Blocks while alerting on `WRITE_VAR` (`0x05`) or `PLC_CONTROL` (`0x28`) over TCP port `102`—normally requires Siemens TIA Portal and hardware controllers. In `.fasm` code, `S7COMM` builds complete Siemens SIMATIC PLC communication frames over ISO-on-TCP (RFC 1006, TCP port `102`):
1. **4-byte TPKT Header:** Version `3`, Reserved `0`, 16-bit big-endian total packet length.
2. **3-byte ISO 8073 COTP Header:** `0x02 0xF0 0x80` (`DT Data` TPDU with `EOT = 1`).
3. **10-byte / 12-byte S7 Header:** Magic byte `0x32`, `ROSCTR` (`0x01` `JOB`, `0x02` `ACK`, `0x03` `ACK_DATA`, `0x07` `USERDATA`), 16-bit `PDU_REF`, parameter/data lengths, and a 2-byte error class/code field on `ACK`/`ACK_DATA` replies.
4. **S7 Parameter Block:** Encodes `SETUP_COMM` (`0xF0`, 480-byte PDU size negotiation), `READ_VAR` (`0x04`) / `WRITE_VAR` (`0x05`) with a 10-byte `S7ANY` memory pointer (`AREA`, `DB_NUM`, bit-shifted `OFFSET << 3`, and `COUNT`), or `PLC_CONTROL` (`0x28`).

### 4.1 `S7COMM` Modifiers

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Func** | `SETUP_COMM` \| `READ_VAR` \| `WRITE_VAR` \| `PLC_CONTROL` | `SETUP_COMM` | Bare keyword setting the S7 Parameter Function Code |
| **`FUNC`** | `FUNC "<name>"` | `"SETUP_COMM"` | Explicit S7 function string (`"SETUP_COMM"` `0xF0`, `"READ_VAR"` `0x04`, `"WRITE_VAR"` `0x05`, `"PLC_CONTROL"` `0x28`) |
| **`ROSCTR`** | `ROSCTR "<type>"` | `"JOB"` | Remote Operating Service Control (`"JOB"` `0x01` request, `"ACK"` `0x02`, `"ACK_DATA"` `0x03` response, `"USERDATA"` `0x07`) |
| **`PDU_REF`** | `PDU_REF <0..65535>` | `1` | 16-bit PDU Reference number matching `JOB` requests with `ACK_DATA` replies |
| **`AREA`** | `AREA <0..255\|"<name>">` | `0x84` (`DB`) | PLC memory area (`0x84` / `"DB"` Data Blocks, `0x83` / `"MK"` Merker flags, `0x81` / `"PE"` Process Inputs, `0x82` / `"PA"` Process Outputs) |
| **`DB_NUM`** | `DB_NUM <0..65535>` | `1` | Data Block number (`DB1`, `DB10`, etc.) when `AREA` is `0x84` |
| **`OFFSET`** | `OFFSET <number>` | `0` | Byte offset within the memory area (automatically multiplied by 8 into a 24-bit S7 bit address) |
| **`COUNT`** | `COUNT <0..65535>` | `1` | Number of bytes to read or write |
| **`PAYLOAD`** | `PAYLOAD "<text>"` | Empty | S7 data block payload for `WRITE_VAR` or `ACK_DATA` frames |

### Compilable Example: Siemens S7comm Session Setup, Data Block Read & Write

```frameassembly
host tia_portal { ip 10.80.10.5  mac 00:1b:21:50:0a:05 }
host s7_1500    { ip 10.80.10.20 mac 00:0e:8c:50:0a:14 }

flow siemens_s7_plc_polling(eng, plc) {
    // 1. Negotiate S7 communication PDU size (SETUP_COMM 0xF0)
    eng -> plc s7comm rosctr "JOB" setup_comm pdu_ref 100 wait 2ms
    eng <- plc s7comm rosctr "ACK_DATA" setup_comm pdu_ref 100 wait 2ms

    // 2. Read 16 bytes from Data Block DB1 starting at byte offset 0
    eng -> plc s7comm rosctr "JOB" read_var pdu_ref 101 area 0x84 db_num 1 offset 0 count 16 wait 2ms
    eng <- plc s7comm rosctr "ACK_DATA" read_var pdu_ref 101 count 16 payload "S7_DB1_TELEMETRY" wait 5ms

    // 3. Write 4 bytes to Data Block DB10 at byte offset 8
    eng -> plc s7comm rosctr "JOB" write_var pdu_ref 102 area 0x84 db_num 10 offset 8 count 4 payload "VAL1" wait 2ms
    eng <- plc s7comm rosctr "ACK_DATA" write_var pdu_ref 102
}

compile {
    siemens_s7_plc_polling(tia_portal, s7_1500)
}
```

---

## 5. ODVA EtherNet/IP & CIP (`ETHERNETIP` — Default: TCP Port `44818`)

Rockwell Automation / Allen-Bradley ControlLogix and CompactLogix environments use ODVA EtherNet/IP over TCP port `44818` to discover assets (`ListIdentity`), register sessions, and read/write Common Industrial Protocol (CIP) objects. Rather than capturing live Studio 5000 traffic on the plant floor, you can express the encapsulation command and CIP EPATH (`Class` / `Instance` / `Attribute`) in `.fasm` code. `ETHERNETIP` builds ODVA EtherNet/IP frames with:
1. **24-byte Little-Endian Encapsulation Header:** 16-bit `Command`, 16-bit `Length`, 32-bit `SessionHandle`, 32-bit `Status`, 64-bit `SenderContext`, and 32-bit `Options`.
2. **Common Packet Format (CPF) & CIP EPATH:** For `SEND_RR_DATA` (`0x006F`) and `SEND_UNIT_DATA` (`0x0070`) packets (or whenever any `CIP_*` modifier is specified), FrameAssembly automatically constructs a 2-item CPF body (`Null Address Item 0x0000` + `Unconnected Data Item 0x00B2`) containing the CIP Service code and logical EPATH segments (`0x20 <Class>`, `0x24 <Instance>`, and optional `0x30 <Attribute>`).

### 5.1 `ETHERNETIP` Modifiers

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **Shorthand Cmd** | `LIST_IDENTITY` \| `LIST_SERVICES` \| `LIST_INTERFACES` \| `REGISTER_SESSION` \| `UNREGISTER_SESSION` \| `SEND_RR_DATA` \| `SEND_UNIT_DATA` | `LIST_IDENTITY` (or `SEND_RR_DATA` if `CIP_*` set) | Bare keyword setting the 16-bit little-endian Encapsulation Command |
| **`CMD`** | `CMD "<name>"` | Auto-selected | Explicit command string (`"NOP"` `0x0000`, `"LIST_SERVICES"` `0x0004`, `"LIST_IDENTITY"` `0x0063`, `"LIST_INTERFACES"` `0x0064`, `"REGISTER_SESSION"` `0x0065`, `"UNREGISTER_SESSION"` `0x0066`, `"SEND_RR_DATA"` `0x006F`, `"SEND_UNIT_DATA"` `0x0070`) |
| **`SESSION_HANDLE`** | `SESSION_HANDLE <number>` | `0` | 32-bit little-endian session handle assigned by `REGISTER_SESSION` |
| **`STATUS`** | `STATUS <number>` | `0` (`Success`) | 32-bit encapsulation status (`0x0000` Success, `0x0001` Invalid command, `0x0064` Invalid session handle) |
| **`CONTEXT`** | `CONTEXT <64-bit_id>` | `0` | 64-bit little-endian `SenderContext` correlation value |
| **`CIP_SERVICE`** | `CIP_SERVICE <0..255>` | `0x0E` (`Get_Attr_Single`) | 8-bit CIP service code (`0x01` `Get_Attributes_All`, `0x0E` `Get_Attribute_Single`, `0x10` `Set_Attribute_Single`, `0x4C` `Read_Tag`, `0x4D` `Write_Tag`) |
| **`CIP_CLASS`** | `CIP_CLASS <0..65535>` | `1` (`Identity`) | CIP Object Class ID (`0x01` Identity, `0x02` Message Router, `0x04` Assembly, `0x06` Connection Manager, `0x6B` Symbol) |
| **`CIP_INSTANCE`** | `CIP_INSTANCE <0..65535>` | `1` | CIP Object Instance ID (e.g., Assembly Instance `100` or `150`) |
| **`CIP_ATTR`** | `CIP_ATTR <0..65535>` | Omitted | Optional 3rd logical EPATH segment (`0x30 <attr>`, e.g., `3` for Assembly Data attribute) |

### Compilable Example: EtherNet/IP Device Discovery, Session Registration & CIP Assembly Read

```frameassembly
host factory_scada { ip 10.80.20.5  }
host logix_plc     { ip 10.80.20.30 }

flow ethernetip_cip_session(scada, plc) {
    // 1. Asset discovery via ListIdentity (0x0063)
    scada -> plc ethernetip list_identity context 0x0001000200030004 wait 1ms
    scada <- plc ethernetip list_identity status 0 context 0x0001000200030004 wait 2ms

    // 2. Register an explicit messaging session (0x0065)
    scada -> plc ethernetip register_session context 100 wait 1ms
    scada <- plc ethernetip register_session session_handle 0x0001a2b3 status 0 context 100 wait 2ms

    // 3. Read CIP Assembly Object (Class 0x04, Instance 100, Attribute 3) via SendRRData (0x006F)
    scada -> plc ethernetip send_rr_data session_handle 0x0001a2b3 context 101 cip_service 0x0e cip_class 0x04 cip_instance 100 cip_attr 3 wait 2ms
    scada <- plc ethernetip send_rr_data session_handle 0x0001a2b3 status 0 context 101 payload "CIP_ASSEMBLY_100_DATA" wait 5ms

    // 4. Cleanly unregister session (0x0066)
    scada -> plc ethernetip unregister_session session_handle 0x0001a2b3 context 102
}

compile {
    ethernetip_cip_session(factory_scada, logix_plc)
}
```

---

## 6. OPC Unified Architecture Binary (`OPCUA` — Default: TCP Port `4840`)

In IEC 62443 architectures, the conduit across the Level 3.5 Industrial DMZ (IDMZ) between plant-floor servers and enterprise historians almost always runs OPC UA Binary (`opc.tcp`) on TCP port `4840`. To test IDMZ firewall conduits and `NodeId` inspection rules without standing up an OPC UA server/client pair, `OPCUA` builds IEC 62541-6 OPC UA Connection Protocol (`UACP`) binary messages over TCP port `4840`:
- **8-byte UACP Header:** 3-byte ASCII `MessageType` (`HEL`, `ACK`, `ERR`, `OPN`, `CLO`, `MSG`), 1-byte `ChunkType` (`'F'` Final, `'C'` Intermediate, `'A'` Aborted), and 32-bit little-endian `MessageSize`.
- **Connection & SecureChannel Bodies:** `HEL` and `ACK` frames automatically populate the 20-byte receive/send buffer negotiation fields (64 KB buffers, 16 MB max message, 5,000 max chunks) plus length-prefixed `ENDPOINT_URL`. `OPN`, `MSG`, and `CLO` frames encode 32-bit little-endian `SECURE_CHANNEL_ID`, `TOKEN_ID`, `SEQ_NUM`, `REQID`, and string `NODE_ID` descriptors.

### 6.1 `OPCUA` Modifiers

| Modifier | Syntax | Default | Wire Behavior & Notes |
| :--- | :--- | :--- | :--- |
| **`MSG_TYPE`** | `MSG_TYPE "<HEL\|ACK\|OPN\|MSG\|CLO\|ERR>"` | `"HEL"` (or `"MSG"` if `NODE_ID` set) | 3-byte ASCII UACP message type |
| **`CHUNK_TYPE`** | `CHUNK_TYPE "<F\|C\|A>"` | `"F"` (`Final`) | 1-byte chunk indicator (`"F"` Final chunk, `"C"` Continuation chunk, `"A"` Abort) |
| **`ENDPOINT_URL`** | `ENDPOINT_URL "<url>"` | Omitted | Length-prefixed discovery URL in `HEL` messages (e.g., `"opc.tcp://10.80.30.20:4840/freeopcua"`) |
| **`SECURE_CHANNEL_ID`**| `SECURE_CHANNEL_ID <number>`| `1` | 32-bit little-endian SecureChannel ID in `OPN`, `MSG`, and `CLO` frames |
| **`TOKEN_ID`** | `TOKEN_ID <number>` | `1` | 32-bit little-endian Security Token ID |
| **`SEQ_NUM`** | `SEQ_NUM <number>` | `1` | 32-bit little-endian chunk Sequence Number |
| **`REQID`** | `REQID <number>` | `1` | 32-bit little-endian client Request ID |
| **`NODE_ID`** | `NODE_ID "<text>"` | Omitted | Encodes a String NodeId (`0x03` mask) in `MSG` service calls (e.g., `"ns=2;s=Boiler1.Pressure"`) |

### Compilable Example: OPC UA Binary Lifecycle (`HEL` $\rightarrow$ `ACK` $\rightarrow$ `OPN` $\rightarrow$ `MSG` $\rightarrow$ `CLO`)

```frameassembly
host idmz_historian { ip 10.80.30.5  }
host opcua_server   { ip 10.80.30.20 }

flow opcua_historian_collection(hist, srv) {
    // 1. UACP Hello (HEL) and Acknowledge (ACK) buffer size negotiation
    hist -> srv opcua msg_type "HEL" chunk_type "F" endpoint_url "opc.tcp://10.80.30.20:4840/plant/server" wait 2ms
    hist <- srv opcua msg_type "ACK" chunk_type "F" wait 2ms

    // 2. OpenSecureChannel (OPN) request and response
    hist -> srv opcua msg_type "OPN" chunk_type "F" secure_channel_id 10 token_id 1 seq_num 1 reqid 1 wait 2ms
    hist <- srv opcua msg_type "OPN" chunk_type "F" secure_channel_id 10 token_id 1 seq_num 1 reqid 1 wait 2ms

    // 3. Read NodeId telemetry via MSG chunks
    hist -> srv opcua msg_type "MSG" chunk_type "F" secure_channel_id 10 token_id 1 seq_num 2 reqid 2 node_id "ns=2;s=Line01.ExtruderTempC" wait 2ms
    hist <- srv opcua msg_type "MSG" chunk_type "F" secure_channel_id 10 token_id 1 seq_num 2 reqid 2 node_id "ns=2;s=Line01.ExtruderTempC" payload "OPCUA_DATA_VALUE_215.4C" wait 5ms

    // 4. CloseSecureChannel (CLO)
    hist -> srv opcua msg_type "CLO" chunk_type "F" secure_channel_id 10 token_id 1 seq_num 3 reqid 3
}

compile {
    opcua_historian_collection(idmz_historian, opcua_server)
}
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — `.fasm` file anatomy, automatic defaults vs. explicit overrides, and step-by-step Wireshark workflows.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — Practical firewall ACL, IDS/IPS, and OT/SCADA testing recipes.
- [**Layer 2 Switching & Data-Link Protocols (`l2_protocols.md`)**](l2_protocols.md) — Pair OT polling with `VLAN`, `PCP` priority tagging, `STP`/`RSTP`, and `LLDP`.
- [**Layer 4 Transport Protocols (`l4_transports.md`)**](l4_transports.md) — Shared 4-tuple `TCP` state tracking and `transport udp` switching for `MODBUS`, `DNP3`, and `ETHERNETIP`.
- [**Layer 7 Mail, Directory, Storage, Databases & Message Brokers (`l7_mail_auth_storage_db.md`)**](l7_mail_auth_storage_db.md) — Combine PLC/SCADA telemetry with `MQTT`, `COAP`, `AMQP`, and historian databases (`POSTGRES`, `MYSQL`).
- [**Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Includes a full IEC 62443 Substation & Industrial DMZ multi-protocol conduit topology.
- [**`.fasm` File Format & Media Type Specification (`fasm-specification.md`)**](fasm-specification.md) — Normative `text/vnd.frameassembly` media type specification, lexical rules, and `.fasm` extension disambiguation.
