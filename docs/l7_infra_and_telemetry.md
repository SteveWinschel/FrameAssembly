# Layer 7 Infrastructure, Time, AAA, Flow Telemetry & CLI Reference

This guide covers **16 core network infrastructure, precision time, AAA authentication, logging/flow export, and remote administration protocols** across IPv4 and IPv6.

---

## 1. Naming & Address Assignment (`DNS`, `MDNS`, `DHCP`)

| Protocol | Default Port | Modifiers & Wire Behavior |
| :--- | :--- | :--- |
| **`DNS`** | UDP / TCP `53` | `QUERY` / `RESPONSE` *(0-arg flags)*, `TXID <u16>`, `QNAME "<domain>"`, `QTYPE "<A\|AAAA\|PTR\|MX\|TXT\|SRV\|CNAME\|SOA\|AXFR>"`, `RDATA "<val>"`, `RCODE <u8>` (`0`=NOERROR, `3`=NXDOMAIN, `5`=REFUSED), `ANS_TTL <u32>`, `TRANSPORT TCP` |
| **`MDNS`** | UDP `5353` | Same modifiers as `DNS`; automatically targets multicast `224.0.0.251` (`01:00:5e:00:00:fb`) or `ff02::fb` (`33:33:00:00:00:fb`) with default `TXID 0` |
| **`DHCP`** | UDP `68`/`67` (v4), `546`/`547` (v6) | v4 flags: `DISCOVER`, `OFFER`, `REQUEST`, `ACK`, `RELEASE`. v6 flags: `SOLICIT`, `ADVERTISE`, `REQUEST`, `REPLY`. Fields: `XID <u32>` / `TXID <u32>`, `CHADDR <mac>`, `CIADDR <ip>`, `YIADDR <ip>`, `SIADDR <ip>`, `HOSTNAME "<str>"`, `SUBNET_MASK <ip>`, `ROUTER <ip>`, `DNS_SERVER <ip>`, `LEASE_TIME <u32>` |

> **Syntax Rule:** In `DNS` and `MDNS`, `QUERY` and `RESPONSE` take no inline string—always pass the domain name with `QNAME "<domain>"`.

```frameassembly
host client_v4 { ip 192.168.20.100 mac 00:50:56:20:00:64 }
host infra_v4  { ip 192.168.20.1   mac 00:50:56:20:00:01 }
host client_v6 { ip 2001:db8:20::100 mac 00:50:56:62:00:64 }
host infra_v6  { ip 2001:db8:20::1   mac 00:50:56:62:00:01 }

flow dhcp_dns_mdns_onboarding(c4, s4, c6, s6) {
    // DHCPv4 DORA lease + DNS A lookup + DNS TCP AXFR + mDNS printer discovery
    c4 -> s4 dhcp discover chaddr 00:50:56:20:00:64 hostname "eng-ws-01" wait 2ms
    c4 <- s4 dhcp offer yiaddr 192.168.20.100 siaddr 192.168.20.1 chaddr 00:50:56:20:00:64 subnet_mask 255.255.255.0 router 192.168.20.1 dns_server 192.168.20.1 lease_time 86400 wait 2ms
    c4 -> s4 dhcp request ciaddr 192.168.20.100 yiaddr 192.168.20.100 chaddr 00:50:56:20:00:64 wait 2ms
    c4 <- s4 dhcp ack yiaddr 192.168.20.100 chaddr 00:50:56:20:00:64 subnet_mask 255.255.255.0 router 192.168.20.1 dns_server 192.168.20.1 lease_time 86400 wait 2ms
    c4 -> s4 dns query txid 1010 qname "git.corp.example.com" qtype "A" wait 1ms
    c4 <- s4 dns response txid 1010 qname "git.corp.example.com" qtype "A" rdata "192.168.20.55" rcode 0 ans_ttl 300 wait 1ms
    c4 -> s4 transport tcp dns query txid 1011 qname "corp.example.com" qtype "AXFR" wait 2ms
    c4 -> s4 mdns query qname "_ipp._tcp.local" qtype "PTR" wait 2ms

    // DHCPv6 SARR lease + DNS AAAA lookup
    c6 -> s6 dhcp solicit chaddr 00:50:56:62:00:64 hostname "eng-ws-01-v6" wait 2ms
    c6 <- s6 dhcp advertise yiaddr 2001:db8:20::100 dns_server 2001:db8:20::1 lease_time 86400 wait 2ms
    c6 -> s6 dhcp request hostname "eng-ws-01-v6" wait 2ms
    c6 <- s6 dhcp reply yiaddr 2001:db8:20::100 dns_server 2001:db8:20::1 lease_time 86400 wait 2ms
    c6 -> s6 dns query txid 2020 qname "git.corp.example.com" qtype "AAAA" wait 1ms
    c6 <- s6 dns response txid 2020 qname "git.corp.example.com" qtype "AAAA" rdata "2001:db8:20::55" rcode 0 ans_ttl 300
}

compile {
    dhcp_dns_mdns_onboarding(client_v4, infra_v4, client_v6, infra_v6)
}
```

---

## 2. Precision Time Synchronization (`NTP` & `PTP`)

* **`NTP` (UDP 123):** `LI <0..3>`, `VN <1..4>` (`4` default), `MODE <1..7>` (`3`=Client, `4`=Server, `5`=Broadcast), `STRATUM <0..16>` (`1`=Primary GPS/Atomic, `16`=Unsynchronized), `POLL <u8>`, `PRECISION <i8>`, `REFID "<4char>"`, `TX_TIMESTAMP <u64>`.
* **`PTP` (IEEE 1588v2):** Automatically routes time-critical Event frames (`SYNC`, `DELAY_REQ`) to **UDP port `319`** and General frames (`FOLLOW_UP`, `DELAY_RESP`, `ANNOUNCE`) to **UDP port `320`**. Modifiers: `DOMAIN <u8>`, `SEQ_ID <u16>`, `CLOCK_ID "<eui64>"`, `VERSION <u8>`.

```frameassembly
host grandmaster { ip 10.158.0.1 }
host follower    { ip 10.158.0.50 }

flow clock_synchronization(gm, sub) {
    sub -> gm dscp 46 ntp li 0 vn 4 mode 3 stratum 2 poll 6 refid "INIT" tx_timestamp 0xe9b0000100000000 wait 1ms
    sub <- gm dscp 46 ntp li 0 vn 4 mode 4 stratum 1 poll 6 refid "GPS" tx_timestamp 0xe9b0000100001000 wait 2ms

    gm -> sub dscp 46 ptp announce domain 0 seq_id 500 clock_id "00:1c:73:ff:fe:00:01:01" wait 500us
    gm -> sub dscp 46 ptp sync domain 0 seq_id 501 clock_id "00:1c:73:ff:fe:00:01:01" wait 100us
    gm -> sub dscp 46 ptp follow_up domain 0 seq_id 501 clock_id "00:1c:73:ff:fe:00:01:01" wait 200us
    sub -> gm dscp 46 ptp delay_req domain 0 seq_id 501 clock_id "00:1c:73:ff:fe:00:01:50" wait 200us
    gm -> sub dscp 46 ptp delay_resp domain 0 seq_id 501 clock_id "00:1c:73:ff:fe:00:01:01"
}

compile {
    clock_synchronization(grandmaster, follower)
}
```

---

## 3. AAA Access Security (`RADIUS` & `TACACS`)

* **`RADIUS`:** Automatically routes Authentication packets (`ACCESS_REQUEST`, `ACCESS_ACCEPT`, `ACCESS_REJECT`, `ACCESS_CHALLENGE`) to **UDP port `1812`** and Accounting packets (`ACCOUNTING_REQUEST`, `ACCOUNTING_RESPONSE`) to **UDP port `1813`**. Supports `ID <u8>`, `USER "<str>"`, `NAS_IP <ip>`, `FRAMED_IP <ip>` (automatically emitting IPv4 Attributes `4`/`8` or IPv6 Attributes `95`/`168`), and `SERVICE_TYPE <u32>`.
* **`TACACS` (TCP 49):** `AUTHEN`, `AUTHOR`, `ACCT` (or `TYPE <AUTHEN|AUTHOR|ACCT>`), `SEQ <u8>`, `FLAGS <u8>`, `SESSION_ID <u32>`, `USER "<str>"`, `PAYLOAD "<str>"`.

```frameassembly
host nas_switch { ip 10.60.1.10 }
host aaa_server { ip 10.60.1.200 }

flow radius_and_tacacs_audit(nas, aaa) {
    nas -> aaa radius access_request id 10 user "alice@corp.local" nas_ip 10.60.1.10 service_type 2 wait 2ms
    nas <- aaa radius access_accept id 10 user "alice@corp.local" framed_ip 10.60.20.55 wait 2ms
    nas -> aaa radius accounting_request id 11 user "alice@corp.local" nas_ip 10.60.1.10 framed_ip 10.60.20.55 wait 2ms
    nas <- aaa radius accounting_response id 11 wait 5ms

    nas -> aaa tacacs author session_id 900102 user "netadmin" payload "cmd=configure;cmd-arg=terminal" wait 2ms
    nas <- aaa tacacs author session_id 900102 user "netadmin" payload "AUTHOR_STATUS_PASS_ADD"
}

compile {
    radius_and_tacacs_audit(nas_switch, aaa_server)
}
```

---

## 4. Logging & Flow Telemetry (`SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`)

| Protocol | Default Port | Modifiers |
| :--- | :--- | :--- |
| **`SYSLOG`** | UDP / TCP `514` | `FACILITY <0..23>`, `SEVERITY <0..7>` (`0`=Emerg .. `7`=Debug), `PRI <0..191>` (`FACILITY * 8 + SEVERITY` if omitted), `HOSTNAME "<str>"`, `APP "<str>"`, `PROCID "<str>"`, `MSG "<text>"`, `TRANSPORT TCP` |
| **`NETFLOW`**| UDP `2055` | NetFlow v5 record: `SRCIP <ip>`, `DSTIP <ip>`, `SRCPORT <u16>`, `DSTPORT <u16>`, `PROTO <u8>`, `PACKETS <u32>`, `OCTETS <u32>` |
| **`IPFIX`** | UDP / TCP `4739` | Dual-stack v10 flow record: `DOMAIN_ID <u32>`, `SRCIP <ip>`, `DSTIP <ip>`, `SRCPORT <u16>`, `DSTPORT <u16>`, `PROTO <u8>`, `PACKETS <u32>`, `OCTETS <u32>` |
| **`SFLOW`** | UDP `6343` | sFlow v5 Flow Sample: `AGENT_IP <ip>`, `SUB_AGENT_ID <u32>`, `SEQ <u32>`, `UPTIME <u32>`, `SAMPLES <u32>` |

```frameassembly
host core_exporter { ip 10.250.10.1 }
host collector     { ip 10.250.10.100 }

flow observability_export(rtr, col) {
    rtr -> col syslog facility 16 severity 4 hostname "core-rtr-01" app "bgpd" procid "1842" msg "Neighbor 198.51.100.1 Up" wait 1ms
    rtr -> col netflow srcip 198.51.100.25 dstip 203.0.113.80 srcport 51200 dstport 443 proto 6 packets 15400 octets 21560000 wait 1ms
    rtr -> col ipfix domain_id 4001 srcip 198.51.100.25 dstip 203.0.113.80 srcport 51200 dstport 443 proto 6 packets 15400 octets 21560000 wait 1ms
    rtr -> col sflow agent_ip 10.250.10.1 sub_agent_id 1 uptime 86400000 samples 8
}

compile {
    observability_export(core_exporter, collector)
}
```

---

## 5. File Transfer, Remote CLI & Registry (`TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`)

| Protocol | Default Port | Modifiers & Syntax Notes |
| :--- | :--- | :--- |
| **`TFTP`** | UDP `69` | `RRQ`, `WRQ`, `DATA`, `ACK`, `FILENAME "<str>"`, `MODE "<octet\|netascii>"`, `BLOCK <u16>`, `ERRCODE <u16>`, `ERRMSG "<str>"` |
| **`FTP`** | TCP `21` | `CMD "<USER\|PASS\|EPSV\|RETR\|STOR\|QUIT>"`, `ARG "<str>"`, `CODE <u16>` (`220`, `230`, `226`), `REPLY "<str>"` |
| **`SSH`** | TCP `22` | `BANNER "<str>"` (e.g. `"SSH-2.0-OpenSSH_9.8p1"`), `KEXINIT`, `NEWKEYS`, `MSG_CODE <u8>` |
| **`TELNET`** | TCP `23` | `WILL <u8>`, `WONT <u8>`, `DO <u8>`, `DONT <u8>`, `OPTION <u8>` *(pass option code integer directly, e.g. `DO 1 WILL 3`)*, `PAYLOAD "<str>"` |
| **`WHOIS`** | TCP `43` | `QUERY` / `RESPONSE` *(0-arg flags)*, `DOMAIN "<domain_or_asn>"`, `REGISTRAR "<str>"` |

```frameassembly
host bastion { ip 10.70.1.50 }
host server  { ip 10.70.1.10 }

flow remote_cli_and_transfers(adm, srv) {
    adm -> srv ssh banner "SSH-2.0-OpenSSH_9.8p1" wait 1ms
    adm <- srv ssh banner "SSH-2.0-Cisco-2.0" wait 1ms
    adm -> srv ssh kexinit payload "curve25519-sha256" wait 1ms
    adm <- srv ssh newkeys wait 2ms

    adm <- srv telnet do 24 will 1 option 3 payload "Username: " wait 1ms
    adm -> srv telnet will 24 do 3 payload "admin\r\n" wait 2ms

    adm -> srv tftp rrq filename "nos-image.bin" mode "octet" wait 1ms
    adm <- srv tftp data block 1 payload "FIRMWARE_BLOCK_0001" wait 1ms
    adm -> srv tftp ack block 1 wait 2ms

    adm <- srv ftp code 220 reply "vsFTPd Ready" wait 1ms
    adm -> srv ftp cmd "USER" arg "backup_ops" wait 1ms
    adm <- srv ftp code 230 reply "Login successful" wait 2ms

    adm -> srv whois query domain "AS65001" registrar "whois.arin.net" wait 1ms
    adm <- srv whois response domain "AS65001" registrar "whois.arin.net"
}

compile {
    remote_cli_and_transfers(bastion, server)
}
```