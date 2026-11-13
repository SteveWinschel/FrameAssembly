# Layer 7 — Core Infrastructure, Time, AAA & Flow Telemetry

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

Rule number one of networking: it's always DNS. The runner-up is DHCP, usually because someone plugged a home router with DHCP enabled into a conference-room jack and half of floor three is now on 192.168.1.x. Both rules are hard to test on purpose, because the only reliable way to generate the evidence is to cause the outage.

The protocols on this page are the plumbing that every other service depends on: names, leases, clocks, logins, logs, and flow records. Each section below takes one operational problem, shows a short `flow(a, b)` you can reuse, and ends with one cheat-sheet table for the keywords involved. Everything compiles to a `.pcap` you can hand to Suricata, Zeek, Wireshark, or a collector through `tcpreplay`.

```console
$ frameassembly show infra_check.frasm
$ frameassembly infra_check.frasm infra_check.pcap && sudo tcpreplay -i eth0 infra_check.pcap
```

SNMP lives in [06_l7_snmp.md](06_l7_snmp.md). `ssh`, `telnet`, `tftp`, `ftp`, and `whois` live in [08_l7_web_and_cloud.md](08_l7_web_and_cloud.md).

## 1. DNS Sinkholes, Zone Transfers, DHCP Snooping and mDNS

### Catch a Rogue DHCP Server

DHCP snooping only earns its keep the day an untrusted port answers a `discover`. Plugging in a rogue server to prove it works is how you blackhole the office subnet. The capture below has the legitimate DORA exchange, then a second `offer` from a host that has no business handing out leases:

```frameassembly
host client { ip 192.168.20.100 mac 00:50:56:20:00:64 }
host dhcp1  { ip 192.168.20.1   mac 00:50:56:20:00:01 }
host rogue  { ip 192.168.20.66  mac 00:0c:29:20:00:66 }

flow dora_with_rogue_offer(c, s, r) {
    c -> s dhcp discover xid 0x10203040 chaddr 00:50:56:20:00:64 hostname "eng-ws-01" wait 2ms
    c <- s dhcp offer xid 0x10203040 yiaddr 192.168.20.100 siaddr 192.168.20.1 chaddr 00:50:56:20:00:64 subnetmask 255.255.255.0 router 192.168.20.1 dnsserver 192.168.20.1 leasetime 86400 wait 1ms
    c <- r dhcp offer xid 0x10203040 yiaddr 192.168.20.100 siaddr 192.168.20.66 chaddr 00:50:56:20:00:64 subnetmask 255.255.255.0 router 192.168.20.66 dnsserver 192.168.20.66 leasetime 600 wait 2ms
    c -> s dhcp request xid 0x10203040 ciaddr 192.168.20.100 yiaddr 192.168.20.100 chaddr 00:50:56:20:00:64 hostname "eng-ws-01" wait 2ms
    c <- s dhcp ack xid 0x10203040 yiaddr 192.168.20.100 siaddr 192.168.20.1 chaddr 00:50:56:20:00:64 subnetmask 255.255.255.0 router 192.168.20.1 dnsserver 192.168.20.1 leasetime 86400
}

compile { dora_with_rogue_offer(client, dhcp1, rogue) }
```

Ports switch to `68` and `67` on their own. The IPv6 version uses `solicit`, `advertise`, `request`, and `reply` on `546` and `547`:

```frameassembly
host client_v6 { ip 2001:db8:20::100 mac 00:50:56:62:00:64 }
host infra_v6  { ip 2001:db8:20::1   mac 00:50:56:62:00:01 }

flow dhcpv6_sarr(c6, s6) {
    c6 -> s6 dhcp solicit xid 0xabcdef chaddr 00:50:56:62:00:64 wait 2ms
    c6 <- s6 dhcp advertise xid 0xabcdef chaddr 00:50:56:62:00:64 wait 2ms
    c6 -> s6 dhcp request xid 0xabcdef chaddr 00:50:56:62:00:64 wait 2ms
    c6 <- s6 dhcp reply xid 0xabcdef chaddr 00:50:56:62:00:64
}

compile { dhcpv6_sarr(client_v6, infra_v6) }
```

### Test a DNS Sinkhole

A response policy zone is supposed to answer `NXDOMAIN` for the ransomware domain and `NOERROR` for the git server. Editing `bind` zone files to find out is a poor use of an afternoon. Use `rcode 3` for NXDOMAIN, `5` for REFUSED, and `ansttl` for the cache lifetime of a good answer:

```frameassembly
host client_v4 { ip 192.168.20.100 mac 00:50:56:20:00:64 }
host resolver  { ip 192.168.20.1   mac 00:50:56:20:00:01 }

flow sinkhole_check(c, s) {
    c -> s dns query txid 1010 qname "git.corp.example.com" qtype "a" wait 1ms
    c <- s dns response txid 1010 qname "git.corp.example.com" qtype "a" rdata "192.168.20.55" rcode 0 ansttl 300 wait 2ms
    c -> s dns query txid 1011 qname "ransom-beacon.bad.example" qtype "a" wait 1ms
    c <- s dns response txid 1011 qname "ransom-beacon.bad.example" qtype "a" rcode 3 wait 2ms
}

compile { sinkhole_check(client_v4, resolver) }
```

### Trigger an AXFR Alert

An unauthorized zone transfer runs over TCP port 53. Add `transport tcp` to the `dns` statement and the compiler prepends the 2-byte message length that RFC 1035 requires on TCP. The handshake lines are ordinary `tcp` statements, and the `dns` line shares their sequence numbers:

```frameassembly
host client_v4 { ip 192.168.20.100 mac 00:50:56:20:00:64 }
host resolver  { ip 192.168.20.1   mac 00:50:56:20:00:01 }

flow axfr_attempt(c, s) {
    c -> s tcp syn srcport 53100 dstport 53 win 64240 mss 1460 wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wait 1ms
    c -> s tcp ack wait 1ms
    c -> s transport tcp dns query txid 1012 qname "corp.example.com" qtype "axfr" wait 2ms
}

compile { axfr_attempt(client_v4, resolver) }
```

### Discover Printers with mDNS

Bonjour and Avahi announcements go to `224.0.0.251` (IPv4) or `ff02::fb` (IPv6), with the matching multicast MAC. You do not set any of that, and the `mdns` statement takes the same modifiers as `dns`. This is the packet to send when you are asked why the floor 3 printer is invisible from floor 4:

```frameassembly
host laptop  { ip 192.168.20.100 mac 00:50:56:20:00:64 }
host printer { ip 192.168.20.80  mac 00:50:56:20:00:80 }

flow printer_discovery(c, p) {
    c -> p mdns query txid 0 qname "_ipp._tcp.local" qtype "ptr" wait 2ms
    c <- p mdns response txid 0 qname "_ipp._tcp.local" qtype "ptr" rdata "floor3-printer._ipp._tcp.local" ansttl 120
}

compile { printer_discovery(laptop, printer) }
```

The same keywords work over IPv6. An `aaaa` lookup and an `_ssh._tcp` mDNS query to `ff02::fb`:

```frameassembly
host client_v6 { ip 2001:db8:20::100 mac 00:50:56:62:00:64 }
host infra_v6  { ip 2001:db8:20::1   mac 00:50:56:62:00:01 }

flow dns_and_mdns_v6(c6, s6) {
    c6 -> s6 dns query txid 2020 qname "git.corp.example.com" qtype "aaaa" wait 1ms
    c6 <- s6 dns response txid 2020 qname "git.corp.example.com" qtype "aaaa" rdata "2001:db8:20::55" ansttl 300 wait 2ms
    c6 -> s6 mdns query txid 0 qname "_ssh._tcp.local" qtype "ptr"
}

compile { dns_and_mdns_v6(client_v6, infra_v6) }
```

### Cheat-Sheet: `dns`, `mdns`, `dhcp`

| Protocol | Flags / Types | Key Modifiers | Wire Behavior and Defaults |
| :--- | :--- | :--- | :--- |
| **`dns`** | `query` (default), `response` | `txid <u16>`, `qname "<domain>"`, `qtype "<type>"`, `rdata "<val>"`, `rcode <0..15>`, `ansttl <u32>`, `transport tcp` | `UDP 53`, or `TCP 53` with a 2-byte length prefix under `transport tcp`. `qtype`: `"a"`, `"aaaa"`, `"cname"`, `"ns"`, `"ptr"`, `"mx"`, `"txt"`, `"soa"`, `"srv"`, `"axfr"`, `"any"`. `rcode`: `0` NOERROR, `2` SERVFAIL, `3` NXDOMAIN, `5` REFUSED. Answer names are compressed (`0xC00C`). |
| **`mdns`** | `query` (default), `response` | Same as `dns`: `txid`, `qname`, `qtype`, `rdata`, `rcode`, `ansttl` | `UDP 5353`, sent to `224.0.0.251` (IPv4) or `ff02::fb` (IPv6) with RFC multicast MACs (`01:00:5e:00:00:fb`, `33:33:00:00:00:fb`) |
| **`dhcp`** | v4: `discover`, `offer`, `request`, `ack`, `release`. v6: `solicit`, `advertise`, `request`, `reply`, `release` | `xid <u32>`, `chaddr <mac>`, `ciaddr <ipv4>`, `yiaddr <ipv4>`, `siaddr <ipv4>`, `subnetmask <ipv4>`, `router <ipv4>`, `dnsserver <ipv4>`, `hostname "<str>"`, `leasetime <u32>` | v4: 236-byte BOOTP, magic cookie `0x63825363`, TLV options, ports `68` and `67`. v6: RFC 8415 with an Option 1 DUID-LL, ports `546` and `547`. `chaddr` defaults to the sender's MAC. |

`query` and `response` are standalone flags. The domain always goes in `qname "<domain>"`, never `dns query "example.com"`. On `dhcp`, `xid <u32>` sets the BOOTP or DHCPv6 transaction ID.

## 2. NTP Kiss-o'-Death and IEEE 1588 PTP Without a Rooftop GPS Clock

### Make a Client Deal with Kiss-o'-Death

A stratum 0 reply with the reference ID `"RATE"` tells a client to back off. Whether your clients and monitoring actually do that is easier to learn from a capture than from an incident. The first reply below is a healthy stratum 1 `"GPS"` answer, the second is the Kiss-o'-Death:

```frameassembly
host switch_a { ip 10.158.0.50 mac 00:1c:73:00:01:50 }
host ntp_gm   { ip 10.158.0.1  mac 00:1c:73:00:01:01 }

flow ntp_kiss_of_death(sw, gm) {
    sw -> gm dscp 46 ntp li 0 vn 4 mode 3 stratum 2 poll 6 precision -18 refid "INIT" txtimestamp 0xe9b0000100000000 wait 1ms
    sw <- gm dscp 46 ntp li 0 vn 4 mode 4 stratum 1 poll 6 precision -24 refid "GPS" txtimestamp 0xe9b0000100001000 wait 5ms
    sw <- gm dscp 46 ntp li 3 vn 4 mode 4 stratum 0 poll 6 precision -24 refid "RATE" txtimestamp 0xe9b0000200000000 wait 5ms
}

compile { ntp_kiss_of_death(switch_a, ntp_gm) }
```

### Check PTP Queueing Without a Grandmaster

A hardware IEEE 1588 grandmaster costs more than the switch you are testing. This flow replays a two-step PTP cycle on VLAN 158 with `pcp 5` and `dscp 46`, so you can see whether the switches put Event traffic (`sync`, `delayreq` on UDP `319`) and General traffic (`announce`, `followup`, `delayresp` on UDP `320`) into the strict-priority queue:

```frameassembly
host grandmaster { ip 10.158.0.1  mac 00:1c:73:00:01:01 }
host boundary_sw { ip 10.158.0.50 mac 00:1c:73:00:01:50 }

flow ptp_two_step(gm, sw) {
    gm -> sw vlan 158 pcp 5 dscp 46 ptp announce  domain 24 seqid 500 clockid "GM-CLK01" wait 500us
    gm -> sw vlan 158 pcp 5 dscp 46 ptp sync      domain 24 seqid 501 clockid "GM-CLK01" wait 100us
    gm -> sw vlan 158 pcp 5 dscp 46 ptp followup  domain 24 seqid 501 clockid "GM-CLK01" wait 200us
    sw -> gm vlan 158 pcp 5 dscp 46 ptp delayreq  domain 24 seqid 501 clockid "SW-CLK50" wait 200us
    gm -> sw vlan 158 pcp 5 dscp 46 ptp delayresp domain 24 seqid 501 clockid "GM-CLK01"
}

compile { ptp_two_step(grandmaster, boundary_sw) }
```

Leave `clockid` out and the `ClockIdentity` is derived as an EUI-64 from the sender's MAC.

### Cheat-Sheet: `ntp`, `ptp`

| Protocol | Sub-Keywords / Modes | Modifiers | Wire Notes and Defaults |
| :--- | :--- | :--- | :--- |
| **`ntp`** | `mode <0..7>` (`3` client default, `4` server, `5` broadcast) | `li <0..3>`, `vn <1..4>`, `stratum <0..16>`, `poll <u8>`, `precision <i8>`, `refid "<4char>"`, `txtimestamp <u64>` | 48-byte RFC 5905 frame on `UDP 123`. `stratum 0` is Kiss-o'-Death (`"RATE"`), `1` is primary (`"GPS"`, `"PPS"`). |
| **`ptp`** | `sync` (default), `delayreq`, `followup`, `delayresp`, `announce` (or `msgtype "<type>"`) | `domain <0..255>`, `seqid <u16>`, `clockid "<8char>"` | 44-byte IEEE 1588v2 frame. `UDP 319` for `sync` and `delayreq`, `UDP 320` for `followup`, `delayresp`, and `announce`. |

## 3. 802.1X `radius` Policies and `tacacs` `cmd=reload` Audits

### Walk Through an 802.1X Login

Supplicant certificates make NAC testing slow. Here the switch sends an `accessrequest`, gets an `accesschallenge`, retries, receives an `accessaccept` with a framed IP, and sends accounting. `radius` goes to UDP `1812` for authentication and moves to `1813` on its own for accounting:

```frameassembly
host access_sw  { ip 10.60.1.10  mac 00:50:56:60:00:10 }
host aaa_server { ip 10.60.1.200 mac 00:50:56:60:02:00 }

flow nac_login(nas, aaa) {
    nas -> aaa radius accessrequest id 10 user "alice@corp.example" nasip 10.60.1.10 servicetype 2 wait 2ms
    nas <- aaa radius accesschallenge id 10 user "alice@corp.example" wait 2ms
    nas -> aaa radius accessrequest id 11 user "alice@corp.example" nasip 10.60.1.10 servicetype 2 wait 2ms
    nas <- aaa radius accessaccept id 11 user "alice@corp.example" framedip 10.60.20.55 servicetype 2 wait 5ms
    nas -> aaa radius accountingrequest id 12 user "alice@corp.example" nasip 10.60.1.10 framedip 10.60.20.55 wait 2ms
    nas <- aaa radius accountingresponse id 12
}

compile { nac_login(access_sw, aaa_server) }
```

On IPv6 paths `nasip` and `framedip` switch to the NAS-IPv6-Address (95, RFC 3162) and Framed-IPv6-Address (168, RFC 6911) attributes, instead of the IPv4 ones (4 and 8):

```frameassembly
host sw_v6  { ip 2001:db8:60::10 }
host aaa_v6 { ip 2001:db8:60::200 }

flow radius_ipv6_avps(nas6, aaa6) {
    nas6 -> aaa6 radius accessrequest id 20 user "bob@corp.example" nasip 2001:db8:60::10 servicetype 2 wait 2ms
    nas6 <- aaa6 radius accessaccept  id 20 user "bob@corp.example" framedip 2001:db8:60:20::55
}

compile { radius_ipv6_avps(sw_v6, aaa_v6) }
```

### Audit a TACACS+ `reload`

Somebody should be paged when a router gets a `reload`. The proof does not require typing `reload` on a jump box. `tacacs` rides on TCP port 49, so the flow opens the connection first, then sends login, a privileged command authorization, and the accounting record. `flags` defaults to `0x01` (unencrypted), which lets Wireshark display the commands:

```frameassembly
host access_sw  { ip 10.60.1.10  mac 00:50:56:60:00:10 }
host aaa_server { ip 10.60.1.200 mac 00:50:56:60:02:00 }

flow tacacs_reload_audit(nas, aaa) {
    nas -> aaa tcp syn srcport 51049 dstport 49 win 64240 mss 1460 wait 1ms
    nas <- aaa tcp syn ack win 65535 mss 1460 wait 1ms
    nas -> aaa tcp ack wait 1ms
    nas -> aaa tacacs authen seq 1 flags 1 sessionid 900101 user "netadmin" data "tty0" wait 2ms
    nas <- aaa tacacs authen seq 2 flags 1 sessionid 900101 user "netadmin" data "PASS" wait 2ms
    nas -> aaa tacacs author seq 1 flags 1 sessionid 900102 user "netadmin" data "cmd=configure;cmd-arg=terminal" wait 2ms
    nas <- aaa tacacs author seq 2 flags 1 sessionid 900102 user "netadmin" payload "AUTHOR_STATUS_PASS_ADD" wait 2ms
    nas -> aaa tacacs acct seq 1 flags 1 sessionid 900103 user "netadmin" data "task_id=42;service=shell;cmd=reload"
}

compile { tacacs_reload_audit(access_sw, aaa_server) }
```

### Cheat-Sheet: `radius`, `tacacs`

| Protocol | Packet Types | Modifiers | Wire Notes and Defaults |
| :--- | :--- | :--- | :--- |
| **`radius`** | `accessrequest` (default), `accessaccept`, `accessreject`, `accesschallenge`, `accountingrequest`, `accountingresponse` (or `code "<name>"`) | `id <u8>`, `user "<str>"`, `nasip <ip>`, `servicetype <u32>`, `framedip <ip>` | `UDP 1812` (auth), `UDP 1813` (accounting). `servicetype`: `1` Login, `2` Framed (802.1X), `6` Administrative. |
| **`tacacs`** | `authen` (default), `author`, `acct` (or `type <authen\|author\|acct>`) | `seq <u8>`, `flags <u8>`, `sessionid <u32>`, `user "<str>"`, `data "<str>"`, `payload "<str>"` | `TCP 49`. `flags` defaults to `0x01`, unencrypted. |

## 4. `syslog` and Flow Telemetry: `netflow`, `ipfix`, `sflow`

### Feed the SIEM Parser

Checking a Grok pattern or a Splunk alert should not require waiting for a router to fail. `syslog` computes `<PRI>` as `(facility * 8) + severity`. The first message goes over UDP `514`. The second is the same sort of event over reliable TCP `514` (`transport tcp` after a handshake):

```frameassembly
host core_exporter { ip 10.250.10.1   mac 00:50:56:fa:00:01 }
host telemetry_col { ip 10.250.10.100 mac 00:50:56:fa:01:00 }

flow syslog_udp_and_tcp(rtr, col) {
    rtr -> col syslog facility 16 severity 4 hostname "core-rtr-01" app "bgpd" procid "1842" msgid "BGP-4-MAXPFX" msg "Neighbor 198.51.100.1 prefix count 85000 exceeds 80% threshold" wait 1ms
    rtr -> col tcp syn srcport 51514 dstport 514 win 65535 mss 1460 wait 1ms
    rtr <- col tcp syn ack win 65535 mss 1460 wait 1ms
    rtr -> col tcp ack wait 1ms
    rtr -> col transport tcp syslog facility 10 severity 5 hostname "core-rtr-01" app "sshd" procid "4410" msgid "SEC_LOGIN" msg "Accepted publickey for netadmin from 10.254.0.10 port 54122 ssh2" wait 2ms
}

compile { syslog_udp_and_tcp(core_exporter, telemetry_col) }
```

### Feed the Flow Collector

ElastiFlow, Akvorado, `pmacct`, `nfcapd`, and Splunk all want to see an elephant flow. A router's active timeout will give you one eventually. This gives you one now, in three export formats: NetFlow v5 on UDP `2055`, IPFIX on `4739`, and sFlow v5 on `6343`:

```frameassembly
host core_exporter { ip 10.250.10.1   mac 00:50:56:fa:00:01 }
host telemetry_col { ip 10.250.10.100 mac 00:50:56:fa:01:00 }

flow elephant_flow_exports(rtr, col) {
    rtr -> col netflow srcip 198.51.100.25 dstip 203.0.113.80 srcport 51200 proto 6 packets 154000 octets 215600000 wait 1ms
    rtr -> col ipfix domainid 4001 srcip 198.51.100.25 dstip 203.0.113.80 srcport 51200 proto 6 packets 154000 octets 215600000 wait 1ms
    rtr -> col sflow agentip 10.250.10.1 subagentid 1 seq 105 uptime 86400000 samples 1
}

compile { elephant_flow_exports(core_exporter, telemetry_col) }
```

The IPv6 side uses the same keywords. `sflow` picks `address_type` 1 or 2 from the host addresses:

```frameassembly
host leaf_v6      { ip 2001:db8:fa::1 }
host collector_v6 { ip 2001:db8:fa::100 }

flow ipv6_telemetry(sw6, col6) {
    sw6 -> col6 syslog facility 23 severity 2 hostname "leaf-sw-v6" app "envmon" msgid "FAN-2-FAIL" msg "Tray 2 Fan 1 RPM below critical threshold" wait 1ms
    sw6 -> col6 sflow agentip 2001:db8:fa::1 subagentid 2 seq 500 uptime 172800000 samples 1
}

compile { ipv6_telemetry(leaf_v6, collector_v6) }
```

A quick all-in-one smoke test for a NOC dashboard: a blocked DNS lookup, the syslog line a router would write about it, and an IPFIX record, in one capture:

```frameassembly
host core_rtr { ip 10.250.0.1   mac 00:1c:73:fa:00:01 }
host sec_ops  { ip 10.250.0.100 mac 00:50:56:fa:00:64 }

flow noc_quick_check(rtr, col) {
    rtr -> col dns query txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "a" wait 1ms
    rtr <- col dns response txid 0x4401 qname "c2-beacon.bad-domain.test" qtype "a" rcode 5 wait 2ms
    rtr -> col syslog facility 16 severity 2 hostname "core-rtr-01" app "bgpd" msgid "BGP_DOWN" msg "Neighbor 198.51.100.1 Hold Timer Expired" wait 2ms
    rtr -> col ipfix domainid 4001 srcip 198.51.100.25 dstip 203.0.113.80 srcport 52400 dstport 443 proto 6 packets 15400 octets 21560000
}

compile { noc_quick_check(core_rtr, sec_ops) }
```

### Cheat-Sheet: `syslog`, `netflow`, `ipfix`, `sflow`

| Protocol | Modifiers | Default Port and Wire Behavior |
| :--- | :--- | :--- |
| **`syslog`** | `facility <0..23>`, `severity <0..7>`, `pri <0..191>`, `hostname "<str>"`, `app "<str>"`, `procid "<str>"`, `msgid "<str>"`, `msg "<str>"`, `transport tcp` | `UDP 514`, or `TCP 514` with `transport tcp`. RFC 5424 record with `PRI = (facility * 8) + severity`. |
| **`netflow`** | `srcip <ip>`, `dstip <ip>`, `srcport <u16>`, `dstport <u16>`, `proto <u8>`, `packets <u32>`, `octets <u32>` | `UDP 2055`. Cisco NetFlow v5 header plus flow record. `proto`: `1` ICMP, `6` TCP, `17` UDP. |
| **`ipfix`** | `domainid <u32>`, `srcip <ip>`, `dstip <ip>`, `srcport <u16>`, `dstport <u16>`, `proto <u8>`, `packets <u32>`, `octets <u32>` | `UDP 4739`. RFC 7011 IPFIX v10 header, Data Set `256`, 64-bit packet and octet counters. |
| **`sflow`** | `agentip <ip>`, `subagentid <u32>`, `seq <u32>`, `uptime <u32>`, `samples <u32>` | `UDP 6343`. sFlow v5 header with a 32-byte Format `1` flow sample, IPv4 or IPv6 agent address. |

Syslog severity and facility codes, since nobody remembers them:

| `severity` | Level | Meaning | Common `facility` | Subsystem |
| :---: | :--- | :--- | :---: | :--- |
| `0` / `1` | `emerg` / `alert` | System unusable / immediate action | `0` / `1` / `3` | `kern` / `user` (default) / `daemon` |
| `2` / `3` | `crit` / `err` | Hardware fault / operational error | `4` / `10` | `auth` / `authpriv` (security and logins) |
| `4` / `5` | `warning` / `notice` | Threshold crossed / config or ACL event | `16`..`19` | `local0`..`local3` (router and switch NOS) |
| `6` / `7` | `info` / `debug` | Routine message (`6` default) / trace | `20`..`23` | `local4`..`local7` (firewalls, VPN, audit) |

## Inspecting, Reversing and Replaying

```console
# Pull DNS queries and rcodes, syslog messages, and IPFIX byte counters out in tshark
$ tshark -r infra_check.pcap -T fields -e frame.number -e dns.qry.name -e dns.flags.rcode -e syslog.msg -e cflow.octets64

# Turn an existing DNS, DHCP, RADIUS, syslog, or NetFlow/IPFIX capture into .frasm code
$ frameassembly reverse infra_check.pcap edited_infra.frasm

# Run Suricata rules against sinkholes, rogue DHCP, or AXFR zone transfers
$ suricata -r axfr_attempt.pcap -k none

# Replay syslog and flow exports into a live SIEM or collector interface
$ sudo tcpreplay -i eth0 elephant_flow_exports.pcap
```
