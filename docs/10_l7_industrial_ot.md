# Layer 7 — Industrial Control Systems (ICS) & SCADA/OT

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

[**PLC Polling vs. Writes**](#1-plc-read-polling-vs-blocked-register-writes-modbus-s7comm) • [**Substation SBO**](#2-substation-select-before-operate-without-hand-computed-crcs-dnp3) •
[**BMS, CIP & IDMZ**](#3-building-automation-cip-cells-and-idmz-historians-bacnet-ethernetip-opcua)

Testing IT firewall rules is forgiving: fat-finger a rule and someone complains that Jira is slow. Testing OT/ICS firewall policies and NDR sensors on a live plant floor is a different
sport. Fire a `writesingleregister` at a running line, or an S7 `plccontrol` stop at a running S7-1500, just to confirm your new conduit ACL works, and people in hardhats will walk over
to your desk. Buying €20,000 worth of DIN-rail PLCs to test on instead usually gets vetoed by finance.

FrameAssembly compiles **`modbus`**, **`dnp3`**, **`s7comm`**, **`bacnet`**, **`ethernetip`**, and **`opcua`** traffic into `.pcap` / `.pcapng` files, with automatic TCP `SEQ`
/`ACK` tracking, IEEE 1815 DNP3 per-chunk CRCs, and 802.1Q `vlan` / `pcp` priority tags. Feed the output to **Suricata**, **Zeek**, **Wireshark** / **`tshark`**, **Claroty** /
**Nozomi** / **Dragos** sensors, or **`tcpreplay`**. The factory keeps running, and nobody has to explain an unplanned shutdown to the plant manager.

## 1. PLC Read Polling vs. Blocked Register Writes (`modbus`, `s7comm`)

Most IEC 62443 zone conduits let an HMI or historian poll registers (`readholdingregisters`, S7 `readvar`) while blocking register writes (`writesingleregister`, `writevar`) and CPU
run-state changes (`plccontrol`) from engineering or IT subnets. Industrial DPI firewalls also drop mid-stream packets that lack a valid three-way handshake, so the TCP sequence math is
tracked for you.

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
| **`modbus`** | TCP/UDP `502` | `readcoils`, `readdiscreteinputs`, `readholdingregisters`, `readinputregisters`, `writesinglecoil`, `writesingleregister`, `writemultipleregisters` | 7B MBAP |
| **`modbus`** *(fields)* | `func`, `transport udp` | `txid`, `protoid`, `unitid`, `addr`, `count`, `value`, `isresponse` | Default `readholdingregisters`; add `isresponse` on PLC replies |
| **`s7comm`** | TCP `102` (ISO-on-TCP) | `setupcomm`, `readvar`, `writevar`, `plccontrol`, `func`, `rosctr "<job\|ack\|ackdata\|userdata>"`, `pduref <u16>` | TPKT v3 + COTP + `0x32` S7 hdr |
| **`s7comm`** *(fields)* | `dbnum`, `offset`, `count` | `area`: `"db"` (`0x84`), `"mk"` (`0x83`), `"pe"` (`0x81`), `"pa"` (`0x82`), `"ct"` (`0x1C`), `"tm"` (`0x1D`) | `offset << 3` in `S7ANY` |

## 2. Substation Select-Before-Operate Without Hand-Computed CRCs (`dnp3`)

Crafting IEEE 1815 `dnp3` frames in a hex editor is pure misery. DNP3 wants a reflected `0xA653` 16-bit CRC, little-endian, on the 10-byte Data Link header **and** after every 16 bytes
of transport/application data. Get one bit wrong and Wireshark, or your substation firewall, quietly discards the frame and tells you nothing. FrameAssembly computes every header and
chunk CRC, and still lets you pass `crc 0xdead` when you *want* to test malformed-frame drops.

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
| **`dnp3`** | TCP `20000`; `transport udp` | `confirm`, `read`, `write`, `select`, `operate`, `directoperate`, `unsolicitedresponse`, `func "<response\|...>"` | 10B `0x0564` hdr + `0xA653` CRC-16 |
| **`dnp3`** *(fields)* | `src <u16>`, `dst <u16>` | `group <u8>`, `variation <u8>`, `crc <u16>`, `transport udp` | Default `read`, `src 100`, `dst 1`; set `crc` to corrupt CRC |

## 3. Building Automation, CIP Cells, and IDMZ Historians (`bacnet`, `ethernetip`, `opcua`)

Modern facilities mix UDP-broadcast building controls (`bacnet`), Rockwell/ODVA CIP explicit messaging (`ethernetip`), and cross-zone historian conduits (`opcua`). Each gets its own
small capture, so a failing VLAN or IDMZ rule points at exactly one protocol.

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
| **`bacnet`** | UDP `47808` (`0xBAC0`) | `whois`, `iam`, `readproperty`, `writeproperty`, `invokeid`, `objecttype`, `objectinstance`, `propertyid`, `value` | BVLC `0x81` (`0x0B`/`0x0A`) |
| **`ethernetip`** | TCP/UDP `44818` | `nop`, `listidentity`, `listservices`, `listinterfaces`, `registersession`, `unregistersession`, `sendrrdata`, `sendunitdata`, `cmd` | 24B Encap hdr |
| **`ethernetip`** *(CIP)* | `dstport 2222` (I/O) | `sessionhandle`, `status`, `context`, `cipservice`, `cipclass`, `cipinstance`, `cipattr`, `transport udp` | CIP EPATH (`0x00B2`) |
| **`opcua`** | TCP `4840` (UACP) | `msgtype "<hel\|ack\|opn\|clo\|msg\|err>"`, `chunktype "<f\|c\|a>"`, `securechannelid`, `tokenid`, `seqnum`, `reqid`, `endpointurl`, `nodeid` | 8B LE UACP hdr |
