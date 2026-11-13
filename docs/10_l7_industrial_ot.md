# Layer 7 — Industrial Control Systems (ICS) & SCADA/OT

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

[**PLC Polling vs. Writes**](#1-plc-read-polling-vs-blocked-register-writes-modbus-s7comm) • [**Substation SBO**](#2-substation-select-before-operate-without-hand-computed-crcs-dnp3) • [**BMS, CIP & IDMZ**](#3-building-automation-cip-cells-and-idmz-historians-bacnet-ethernetip-opcua)

Testing IT firewall rules is forgiving: fat-finger a rule and someone complains that Jira is slow. Testing OT/ICS firewall policies and NDR sensors on a live plant floor is a different sport. Fire a `writesingleregister` at a running line, or an S7 `plccontrol` stop at a running S7-1500, just to confirm your new conduit ACL works, and people in hardhats will walk over to your desk. Buying €20,000 worth of DIN-rail PLCs to test on instead usually gets vetoed by finance.

FrameAssembly compiles **`modbus`**, **`dnp3`**, **`s7comm`**, **`bacnet`**, **`ethernetip`**, and **`opcua`** traffic into `.pcap` / `.pcapng` files, with automatic TCP `SEQ`/`ACK` tracking, IEEE 1815 DNP3 per-chunk CRCs, and 802.1Q `vlan` / `pcp` priority tags. Feed the output to **Suricata**, **Zeek**, **Wireshark** / **`tshark`**, **Claroty** / **Nozomi** / **Dragos** sensors, or **`tcpreplay`**. The factory keeps running, and nobody has to explain an unplanned shutdown to the plant manager.

## 1. PLC Read Polling vs. Blocked Register Writes (`modbus`, `s7comm`)

Most IEC 62443 zone conduits let an HMI or historian poll registers (`readholdingregisters`, S7 `readvar`) while blocking register writes (`writesingleregister`, `writevar`) and CPU run-state changes (`plccontrol`) from engineering or IT subnets. Industrial DPI firewalls also drop mid-stream packets that lack a valid three-way handshake, so the TCP sequence math is tracked for you.

The Modbus baseline, followed by the write the firewall is supposed to refuse:

```frameassembly
host scada_hmi { ip 172.22.10.10 mac 00:1b:21:10:00:0a }
host rogue_eng { ip 172.22.99.66 mac 00:50:56:99:00:66 }
host line_plc  { ip 172.22.10.50 mac 00:0e:8c:10:00:32 }

flow modbus_policy_check(hmi, rogue, plc) {
    // Allowed: the HMI polls 4 holding registers on VLAN 110 (802.1p PCP 6)
    hmi -> plc vlan 110 pcp 6 tcp syn srcport 50502 dstport 502 win 64240 mss 1460 wait 1ms
    hmi <- plc vlan 110 pcp 6 tcp syn ack win 64240 mss 1460 wait 1ms
    hmi -> plc vlan 110 pcp 6 tcp ack wait 1ms
    hmi -> plc vlan 110 pcp 6 modbus readholdingregisters txid 1 unitid 1 addr 100 count 4 wait 2ms
    hmi <- plc vlan 110 pcp 6 modbus readholdingregisters txid 1 unitid 1 count 4 value 1500 isresponse wait 2ms
    // Violation: a rogue host writes Single Register (function 0x06)
    rogue -> plc vlan 110 modbus writesingleregister txid 99 unitid 1 addr 100 value 0xffff wait 2ms
    rogue <- plc vlan 110 tcp rst ack
}

compile { modbus_policy_check(scada_hmi, rogue_eng, line_plc) }
```

Same rogue host, now over ISO-on-TCP (port 102), writing a data block and then telling the CPU to stop:

```frameassembly
host rogue_eng { ip 172.22.99.66 mac 00:50:56:99:00:66 }
host line_plc  { ip 172.22.10.50 mac 00:0e:8c:10:00:32 }

flow s7_stop_attempt(rogue, plc) {
    rogue -> plc vlan 110 tcp syn srcport 50102 dstport 102 win 64240 mss 1460 wait 1ms
    rogue <- plc vlan 110 tcp syn ack win 64240 mss 1460 wait 1ms
    rogue -> plc vlan 110 tcp ack wait 1ms
    rogue -> plc vlan 110 s7comm rosctr "job" setupcomm pduref 1 wait 1ms
    rogue <- plc vlan 110 s7comm rosctr "ackdata" setupcomm pduref 1 wait 1ms
    rogue -> plc vlan 110 s7comm rosctr "job" writevar pduref 2 area "db" dbnum 1 offset 0 count 4 hexpayload "deadbeef" wait 2ms
    rogue -> plc vlan 110 s7comm rosctr "job" plccontrol pduref 3 payload "P_PROGRAM"
}

compile { s7_stop_attempt(rogue_eng, line_plc) }
```

```console
$ frameassembly plc_dpi.frasm plc_dpi.pcap && suricata -r plc_dpi.pcap -k none
```

| Keyword | Port & override | Modifiers | Defaults & wire behavior |
| :--- | :--- | :--- | :--- |
| **`modbus`** (Modbus/TCP) | TCP `502`; `transport udp` for UDP `502` | `readcoils` \| `readdiscreteinputs` \| `readholdingregisters` \| `readinputregisters` \| `writesinglecoil` \| `writesingleregister` \| `writemultipleregisters` \| `func "<name>"`, `txid <u16>`, `protoid <u16>`, `unitid <u8>`, `addr <u16>`, `count <u16>`, `value <u16>`, `isresponse`, `transport udp` | 7-byte MBAP header plus function code `0x01..0x06` or `0x10`. Defaults to `readholdingregisters` (`0x03`), `txid 1`, `protoid 0`, `unitid 1`, `addr 0`, `count 1`, `value 0`. Add `isresponse` on `<-` PLC replies to switch from the 4-byte `[addr, count]` request layout to a byte-counted `[byte_count, register_values...]` response. |
| **`s7comm`** (Siemens S7) | TCP `102` only (ISO-on-TCP, RFC 1006) | `setupcomm` \| `readvar` \| `writevar` \| `plccontrol` \| `func "<name>"`, `rosctr "<job\|ack\|ackdata\|userdata>"`, `pduref <u16>`, `area <u8\|"<db\|mk\|pe\|pa\|ct\|tm>">`, `dbnum <u16>`, `offset <u32>`, `count <u16>` | 4-byte TPKT v3, 3-byte COTP DT Data (`0x02f080`), then a `0x32` S7 header. Defaults to `rosctr "job"` (`0x01`), `setupcomm` (`0xF0`), `pduref 1`. On `"ack"` (`0x02`) and `"ackdata"` (`0x03`) the 10-byte S7 header grows to 12 bytes with `error_class` and `error_code`. On `readvar` / `writevar`, `area` takes symbolic names (`"db"` / `0x84` Data Blocks, `"mk"` / `"m"` `0x83` Merkers, `"pe"` / `"i"` `0x81` Inputs, `"pa"` / `"q"` `0x82` Outputs, `"ct"` / `"c"` `0x1C` Counters, `"tm"` / `"t"` `0x1D` Timers), and `offset << 3` is bit-shifted into the 10-byte `S7ANY` pointer for you. |

## 2. Substation Select-Before-Operate Without Hand-Computed CRCs (`dnp3`)

Crafting IEEE 1815 `dnp3` frames in a hex editor is pure misery. DNP3 wants a reflected `0xA653` 16-bit CRC, little-endian, on the 10-byte Data Link header **and** after every 16 bytes of transport/application data. Get one bit wrong and Wireshark, or your substation firewall, quietly discards the frame and tells you nothing. FrameAssembly computes every header and chunk CRC, and still lets you pass `crc 0xdead` when you *want* to test malformed-frame drops.

A class poll, then a breaker control sequence (Select-Before-Operate on a CROB, Group 12 Variation 1):

```frameassembly
host scada_master { ip 10.210.1.10 mac 00:1b:21:d2:01:0a }
host substation   { ip 10.210.1.55 mac 00:a0:f4:d2:01:37 }

flow dnp3_sbo(master, rtu) {
    master -> rtu tcp syn srcport 52000 dstport 20000 win 64240 mss 1460 wait 1ms
    master <- rtu tcp syn ack win 64240 mss 1460 wait 1ms
    master -> rtu tcp ack wait 1ms
    master -> rtu dnp3 read src 1 dst 10 group 60 variation 1 wait 2ms
    master <- rtu dnp3 func "response" src 10 dst 1 group 30 variation 1 hexpayload "0100dc05" wait 3ms
    master -> rtu dnp3 select src 1 dst 10 group 12 variation 1 wait 2ms
    master <- rtu dnp3 func "response" src 10 dst 1 group 12 variation 1 wait 2ms
    master -> rtu dnp3 operate src 1 dst 10 group 12 variation 1 wait 2ms
    master <- rtu dnp3 confirm src 10 dst 1
}

compile { dnp3_sbo(scada_master, substation) }
```

And one deliberately corrupted Data Link CRC, for frame-integrity drop testing:

```frameassembly
host scada_master { ip 10.210.1.10 mac 00:1b:21:d2:01:0a }
host substation   { ip 10.210.1.55 mac 00:a0:f4:d2:01:37 }

flow dnp3_bad_crc(master, rtu) {
    master -> rtu dnp3 directoperate src 1 dst 10 group 12 variation 1 crc 0xdead
}

compile { dnp3_bad_crc(scada_master, substation) }
```

```console
$ frameassembly substation.frasm substation.pcap && tshark -r substation.pcap -Y dnp3 -V
```

| Keyword | Port & override | Modifiers | Defaults & wire behavior |
| :--- | :--- | :--- | :--- |
| **`dnp3`** (IEEE 1815) | TCP `20000`; `transport udp` for UDP `20000` | `confirm` \| `read` \| `write` \| `select` \| `operate` \| `directoperate` \| `unsolicitedresponse` \| `func "<response\|...>"`, `src <u16>`, `dst <u16>`, `group <u8>`, `variation <u8>`, `crc <u16>`, `transport udp` | 10-byte `0x0564` Data Link header, `0xC0` transport byte, application header, and `0xA653` CRC-16 after every 16-byte chunk. Defaults to `read` (function `1`), little-endian Data Link `src 100` and `dst 1`, and object `group 60` / `variation 1` (qualifier `0x06`) when group or variation is given. Outstation responses (function `129`) are written `func "response"`. Omit `crc` for valid frames, or set `crc <u16>` to corrupt the Data Link header CRC on purpose. |

## 3. Building Automation, CIP Cells, and IDMZ Historians (`bacnet`, `ethernetip`, `opcua`)

Modern facilities mix UDP-broadcast building controls (`bacnet`), Rockwell/ODVA CIP explicit messaging (`ethernetip`), and cross-zone historian conduits (`opcua`). Each gets its own small capture, so a failing VLAN or IDMZ rule points at exactly one protocol.

BACnet discovery, a property read, and a setpoint write against the HVAC controller. No TCP flags here: `bacnet` is UDP all the way down.

```frameassembly
host bms_srv   { ip 192.168.40.10 mac 00:1b:21:40:00:0a }
host hvac_ctrl { ip 192.168.40.85 mac 00:40:ae:40:00:55 }

flow bacnet_setpoint(bms, hvac) {
    bms -> hvac bacnet whois wait 2ms
    bms <- hvac bacnet iam objecttype 8 objectinstance 4085 wait 2ms
    bms -> hvac bacnet readproperty invokeid 1 objecttype 0 objectinstance 1 propertyid 85 wait 2ms
    bms -> hvac bacnet writeproperty invokeid 2 objecttype 1 objectinstance 1 propertyid 85 value 72
}

compile { bacnet_setpoint(bms_srv, hvac_ctrl) }
```

EtherNet/IP session registration, then a CIP `Get_Attribute_Single` on TCP 44818:

```frameassembly
host cell_scanner { ip 172.22.30.10 mac 00:00:bc:30:00:0a }
host cip_drive    { ip 172.22.30.25 mac 00:00:bc:30:00:19 }

flow cip_read(scanner, drive) {
    scanner -> drive tcp syn srcport 54818 dstport 44818 win 64240 mss 1460 wait 1ms
    scanner <- drive tcp syn ack win 64240 mss 1460 wait 1ms
    scanner -> drive tcp ack wait 1ms
    scanner -> drive ethernetip registersession context 0x0102030405060708 wait 1ms
    scanner <- drive ethernetip registersession sessionhandle 0x00001001 status 0 context 0x0102030405060708 wait 1ms
    scanner -> drive ethernetip sendrrdata sessionhandle 0x00001001 cipservice 0x0e cipclass 1 cipinstance 1 cipattr 7
}

compile { cip_read(cell_scanner, cip_drive) }
```

The IDMZ conduit: an OPC UA Binary HEL/ACK/OPN handshake, then a `NodeId` read, tagged VLAN 200 with PCP 4.

```frameassembly
host cell_scanner { ip 172.22.30.10   mac 00:00:bc:30:00:0a }
host historian    { ip 172.22.200.100 mac 00:50:56:c8:00:64 }

flow idmz_opcua(scanner, hist) {
    scanner -> hist vlan 200 pcp 4 tcp syn srcport 54840 dstport 4840 win 64240 mss 1460 wait 1ms
    scanner <- hist vlan 200 pcp 4 tcp syn ack win 64240 mss 1460 wait 1ms
    scanner -> hist vlan 200 pcp 4 tcp ack wait 1ms
    scanner -> hist vlan 200 pcp 4 opcua msgtype "hel" chunktype "f" endpointurl "opc.tcp://172.22.200.100:4840" wait 1ms
    scanner <- hist vlan 200 pcp 4 opcua msgtype "ack" chunktype "f" wait 1ms
    scanner -> hist vlan 200 pcp 4 opcua msgtype "opn" chunktype "f" securechannelid 42 tokenid 1 seqnum 1 reqid 1 wait 1ms
    scanner -> hist vlan 200 pcp 4 opcua msgtype "msg" chunktype "f" securechannelid 42 tokenid 1 seqnum 2 reqid 2 nodeid "Drive01.OutputRPM" payload "1485"
}

compile { idmz_opcua(cell_scanner, historian) }
```

```console
$ frameassembly show ot_conduit.frasm
$ frameassembly ot_conduit.frasm ot_conduit.pcap && sudo tcpreplay -i eth0 ot_conduit.pcap
$ frameassembly reverse ot_conduit.pcap ot_conduit_reversed.frasm
```

| Keyword | Port & override | Modifiers | Defaults & wire behavior |
| :--- | :--- | :--- | :--- |
| **`bacnet`** (BACnet/IP) | UDP `47808` (`0xBAC0`) | `whois` \| `iam` \| `readproperty` \| `writeproperty`, `invokeid <u8>`, `objecttype <u16>`, `objectinstance <u32>`, `propertyid <u32>`, `value <u32>` | 4-byte BVLC (`0x81`), 2-byte NPDU, packed 32-bit ObjectIdentifier APDU. Defaults to `whois` with BVLC function `0x0B` (Original-Broadcast-NPDU). `iam`, `readproperty` (`0x0C`), and `writeproperty` (`0x0F`) switch BVLC to `0x0A` (Original-Unicast-NPDU). `objecttype` defaults to `8` (Device; `0` Analog Input, `1` Analog Output, `2` Analog Value), `objectinstance` to `1234`, `propertyid` to `85` (Present_Value). Do not attach TCP flags to `bacnet` statements. |
| **`ethernetip`** (ODVA EtherNet/IP) | TCP `44818`; `transport udp` (combine with `dstport 2222` for implicit I/O) | `nop` \| `listidentity` \| `listservices` \| `listinterfaces` \| `registersession` \| `unregistersession` \| `sendrrdata` \| `sendunitdata` \| `cmd "<nop\|...>"`, `sessionhandle <u32>`, `status <u32>`, `context <u64>`, `cipservice <u8>`, `cipclass <u16>`, `cipinstance <u16>`, `cipattr <u16>`, `transport udp` | 24-byte little-endian Encapsulation Header, CPF items (`0x0000`, `0x00B2`), CIP EPATH segments. Defaults to `listidentity` (`0x0063`). Any of `cipservice` (default `0x0E`, Get_Attribute_Single), `cipclass` (default `1`, Identity Object), `cipinstance` (default `1`), or `cipattr` upgrades it to `sendrrdata` (`0x006F`) with CPF Unconnected Data (`0x00B2`). |
| **`opcua`** (OPC UA Binary) | TCP `4840` only (UACP) | `msgtype "<hel\|ack\|opn\|clo\|msg\|err>"`, `chunktype "<f\|c\|a>"`, `securechannelid <u32>`, `tokenid <u32>`, `seqnum <u32>`, `reqid <u32>`, `endpointurl "<url>"`, `nodeid "<id>"` | 8-byte little-endian UACP header (`HEL` / `ACK` / `OPN` / `CLO` / `MSG` / `ERR`). Defaults to `msgtype "hel"` (or `"msg"` when `nodeid` is given without `endpointurl`) and `chunktype "f"` (Final). `"hel"` and `"ack"` fill the 64 KB receive/send buffer negotiation fields. `"opn"`, `"clo"`, `"msg"`, and `"err"` encode little-endian `securechannelid`, `tokenid`, `seqnum`, `reqid`, and a namespace-0 String `NodeId`. |
