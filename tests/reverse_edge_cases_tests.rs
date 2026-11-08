//! Edge-case, container-variant, linktype-normalization, padding/FCS-stripping, encrypted-fallback,
//! and malformed-input fuzz-safety test suite for FrameAssembly's PCAP/PCAPNG-to-`.fasm` decompiler.
//!
//! This integration suite exercises every boundary condition of [`frameassembly::reverse`]:
//! 1. **Classic `.pcap` & `.pcapng` Container Variants**: Little-endian and big-endian microsecond
//!    and nanosecond legacy `.pcap` headers plus `.pcapng` `IfTsResol` (decimal and binary) and
//!    `IfTsOffset` options.
//! 2. **LinkType Normalization**: `ETHERNET` (`1`), `RAW` (`101`), `IPV4` (`228`), `IPV6` (`229`),
//!    `LINUX_SLL` (`113`), `LINUX_SLL2` (`276`), `NULL` (`0`), and `LOOP` (`108`).
//! 3. **Ethernet 60/64-Byte Padding & 4-Byte FCS Stripping**: Exact length truncation across IPv4,
//!    IPv6, ARP, 802.1Q VLAN, and EAPOL frames.
//! 4. **Encrypted Traffic Fallback Without Decryption**: Lossless `udp`/`tcp` + `hexpayload`
//!    step-down for SNMPv3 `authPriv` (`ScopedPduData::EncryptedPdu`), encrypted TLS, SSH, and QUIC.
//! 5. **Malformed & Truncated Input Fuzz Safety**: Truncated L2–L7 headers and corrupted payloads
//!    across all major service ports (`53`, `67`, `80`, `123`, `161`, `162`, `389`, `443`, `445`,
//!    `502`, `514`, `1812`, `3306`, `5060`, `5432`, `6379`, `20000`, `47808`, `4840`).

use std::borrow::Cow;
use std::time::Duration;

use frameassembly::backend::compile_program;
use frameassembly::parser::{parse_program, validate_semantics};
use frameassembly::reverse::reverse_pcap_bytes;
use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::Block;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::blocks::simple_packet::SimplePacketBlock;

/// Compiles a `.fasm` snippet and returns its synthesized `(frame_bytes, timestamp_ns)` list.
fn compile_fasm_frames(fasm_src: &str) -> Vec<(Vec<u8>, u64)> {
    let prog = parse_program(fasm_src).expect("parse valid .fasm snippet");
    validate_semantics(&prog, fasm_src).expect("validate .fasm snippet");
    compile_program(&prog).expect("compile .fasm snippet")
}

/// Builds a raw classic `.pcap` buffer with configurable endianness (`is_be`), timestamp precision
/// (`is_nanos`), `linktype` code, and `(ts_sec, ts_subsec, packet_bytes)` records.
fn build_legacy_pcap(
    is_be: bool,
    is_nanos: bool,
    linktype: u32,
    packets: &[(u32, u32, Vec<u8>)],
) -> Vec<u8> {
    let mut buf = Vec::new();
    let u16_bytes = |v: u16| -> [u8; 2] {
        if is_be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let u32_bytes = |v: u32| -> [u8; 4] {
        if is_be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };

    let magic: u32 = if is_nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
    buf.extend_from_slice(&u32_bytes(magic));
    buf.extend_from_slice(&u16_bytes(2)); // version_major
    buf.extend_from_slice(&u16_bytes(4)); // version_minor
    buf.extend_from_slice(&u32_bytes(0)); // thiszone
    buf.extend_from_slice(&u32_bytes(0)); // sigfigs
    buf.extend_from_slice(&u32_bytes(65535)); // snaplen
    buf.extend_from_slice(&u32_bytes(linktype)); // network / linktype

    for (sec, subsec, data) in packets {
        let len = data.len() as u32;
        buf.extend_from_slice(&u32_bytes(*sec));
        buf.extend_from_slice(&u32_bytes(*subsec));
        buf.extend_from_slice(&u32_bytes(len));
        buf.extend_from_slice(&u32_bytes(len));
        buf.extend_from_slice(data);
    }
    buf
}

/// Serializes `(frame_bytes, raw_ticks)` pairs into a PCAPNG buffer with custom `idb_options`.
fn build_pcapng_with_options(
    linktype: DataLink,
    idb_options: Vec<InterfaceDescriptionOption<'static>>,
    packets: &[(Vec<u8>, u64)],
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = PcapNgWriter::new(&mut buf).expect("create PcapNgWriter");
    let idb = InterfaceDescriptionBlock {
        linktype,
        snaplen: 65535,
        options: idb_options,
    };
    writer
        .write_block(&Block::InterfaceDescription(idb))
        .expect("write IDB");
    for (data, raw_ticks) in packets {
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(*raw_ticks),
            original_len: data.len() as u32,
            data: Cow::Borrowed(data),
            options: Vec::new(),
        };
        writer
            .write_block(&Block::EnhancedPacket(epb))
            .expect("write EPB");
    }
    buf
}

/// Verifies that all four classic `.pcap` magic headers (LE/BE microsecond and LE/BE nanosecond)
/// and `.pcapng` captures with custom `IfTsResol` (decimal $10^{-6}$, $10^{-3}$, $10^{-9}$, binary
/// $2^{-10}$), `IfTsOffset`, and `SimplePacketBlock` blocks decode frames and timestamps accurately.
#[test]
fn test_classic_pcap_all_4_magic_variants_and_pcapng_tsresol() {
    let frames = compile_fasm_frames(
        r#"
        HOST a { IP 10.0.0.1 MAC 00:11:22:33:44:01 }
        HOST b { IP 10.0.0.2 MAC 00:11:22:33:44:02 }
        FLOW f(x, y) {
            x -> y ICMP ECHO_REQUEST ID 1 SEQ 1
            x <- y ICMP ECHO_REPLY ID 1 SEQ 1
        }
        COMPILE { f(a, b) }
        "#,
    );
    let f0 = frames[0].0.clone();
    let f1 = frames[1].0.clone();

    // 1. Little-endian microsecond classic .pcap (0xa1b2c3d4 -> [d4, c3, b2, a1]): 5000us -> 8000us = 3ms delta
    let pcap_le_us = build_legacy_pcap(
        false,
        false,
        1,
        &[(100, 5_000, f0.clone()), (100, 8_000, f1.clone())],
    );
    assert_eq!(&pcap_le_us[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    let out_le_us = reverse_pcap_bytes(&pcap_le_us).expect("reverse LE microsecond .pcap");
    assert!(
        out_le_us.fasm.contains("icmp echo_reply") && out_le_us.fasm.contains("wait 3ms"),
        "expected 3ms delta in LE microsecond .pcap:\n{}",
        out_le_us.fasm
    );

    // 2. Big-endian microsecond classic .pcap (0xd4c3b2a1 -> [a1, b2, c3, d4]): 1000us -> 1250us = 250us delta
    let pcap_be_us = build_legacy_pcap(
        true,
        false,
        1,
        &[(100, 1_000, f0.clone()), (100, 1_250, f1.clone())],
    );
    assert_eq!(&pcap_be_us[0..4], &[0xa1, 0xb2, 0xc3, 0xd4]);
    let out_be_us = reverse_pcap_bytes(&pcap_be_us).expect("reverse BE microsecond .pcap");
    assert!(
        out_be_us.fasm.contains("icmp echo_reply") && out_be_us.fasm.contains("wait 250us"),
        "expected 250us delta in BE microsecond .pcap:\n{}",
        out_be_us.fasm
    );

    // 3. Little-endian nanosecond classic .pcap (0xa1b23c4d -> [4d, 3c, b2, a1]): 1000ns -> 1750ns = 750ns delta
    let pcap_le_ns = build_legacy_pcap(
        false,
        true,
        1,
        &[(100, 1_000, f0.clone()), (100, 1_750, f1.clone())],
    );
    assert_eq!(&pcap_le_ns[0..4], &[0x4d, 0x3c, 0xb2, 0xa1]);
    let out_le_ns = reverse_pcap_bytes(&pcap_le_ns).expect("reverse LE nanosecond .pcap");
    assert!(
        out_le_ns.fasm.contains("icmp echo_reply") && out_le_ns.fasm.contains("wait 750ns"),
        "expected 750ns delta in LE nanosecond .pcap:\n{}",
        out_le_ns.fasm
    );

    // 4. Big-endian nanosecond classic .pcap (0x4d3cb2a1 -> [a1, b2, 3c, 4d]): 2000ns -> 2500ns = 500ns delta
    let pcap_be_ns = build_legacy_pcap(
        true,
        true,
        1,
        &[(100, 2_000, f0.clone()), (100, 2_500, f1.clone())],
    );
    assert_eq!(&pcap_be_ns[0..4], &[0xa1, 0xb2, 0x3c, 0x4d]);
    let out_be_ns = reverse_pcap_bytes(&pcap_be_ns).expect("reverse BE nanosecond .pcap");
    assert!(
        out_be_ns.fasm.contains("icmp echo_reply") && out_be_ns.fasm.contains("wait 500ns"),
        "expected 500ns delta in BE nanosecond .pcap:\n{}",
        out_be_ns.fasm
    );

    // 5. PCAPNG with IfTsResol(3) (milliseconds) and IfTsOffset(100): 10 ticks -> 15 ticks = 5ms delta
    let ng_ms = build_pcapng_with_options(
        DataLink::ETHERNET,
        vec![
            InterfaceDescriptionOption::IfTsResol(3),
            InterfaceDescriptionOption::IfTsOffset(100),
        ],
        &[(f0.clone(), 10), (f1.clone(), 15)],
    );
    let out_ng_ms = reverse_pcap_bytes(&ng_ms).expect("reverse PCAPNG with IfTsResol(3)");
    assert!(
        out_ng_ms.fasm.contains("wait 5ms"),
        "expected 5ms wait from IfTsResol(3):\n{}",
        out_ng_ms.fasm
    );

    // 6. PCAPNG with binary IfTsResol(0x80 | 10) (2^-10 s): 1024 ticks -> 3072 ticks = 2s delta
    let ng_bin = build_pcapng_with_options(
        DataLink::ETHERNET,
        vec![InterfaceDescriptionOption::IfTsResol(0x80 | 10)],
        &[(f0.clone(), 1024), (f1.clone(), 3072)],
    );
    let out_ng_bin =
        reverse_pcap_bytes(&ng_bin).expect("reverse PCAPNG with binary IfTsResol(0x80 | 10)");
    assert!(
        out_ng_bin.fasm.contains("wait 2s"),
        "expected 2s wait from binary IfTsResol(0x80 | 10):\n{}",
        out_ng_bin.fasm
    );

    // 7. PCAPNG with SimplePacketBlock (inherits previous timestamp -> wait 0ms)
    let mut ng_spb_buf = Vec::new();
    {
        let mut writer = PcapNgWriter::new(&mut ng_spb_buf).expect("create PcapNgWriter");
        let idb = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 65535,
            options: vec![InterfaceDescriptionOption::IfTsResol(9)],
        };
        writer
            .write_block(&Block::InterfaceDescription(idb))
            .expect("write IDB");
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(1_000_000),
            original_len: f0.len() as u32,
            data: Cow::Borrowed(&f0),
            options: Vec::new(),
        };
        writer
            .write_block(&Block::EnhancedPacket(epb))
            .expect("write EPB");
        let spb = SimplePacketBlock {
            original_len: f1.len() as u32,
            data: Cow::Borrowed(&f1),
        };
        writer
            .write_block(&Block::SimplePacket(spb))
            .expect("write SPB");
    }
    let out_spb = reverse_pcap_bytes(&ng_spb_buf).expect("reverse PCAPNG with SimplePacketBlock");
    assert_eq!(out_spb.packet_count, 2);
    assert!(
        out_spb.fasm.contains("wait 0ms"),
        "SimplePacketBlock must inherit previous timestamp (wait 0ms):\n{}",
        out_spb.fasm
    );

    // 8. Reject too-short (< 4 bytes) and unrecognized magic inputs cleanly
    assert!(reverse_pcap_bytes(&[0x01, 0x02]).is_err());
    assert!(reverse_pcap_bytes(b"NOT_A_PCAP_FILE").is_err());
}

/// Verifies LinkType normalization across all 8 supported link-layer types:
/// `LINKTYPE_ETHERNET` (`1`), `LINKTYPE_RAW` (`101`), `LINKTYPE_IPV4` (`228`), `LINKTYPE_IPV6`
/// (`229`), `LINKTYPE_LINUX_SLL` (`113`), `LINKTYPE_LINUX_SLL2` (`276`), `LINKTYPE_NULL` (`0`),
/// and `LINKTYPE_LOOP` (`108`).
#[test]
fn test_linktype_normalization_all_8_encapsulations() {
    let v4_eth = compile_fasm_frames(
        r#"
        HOST a { IP 10.1.1.1 MAC 00:11:22:33:44:01 }
        HOST b { IP 10.1.1.2 MAC 00:11:22:33:44:02 }
        FLOW f(x, y) { x -> y DNS QUERY TXID 0x2222 QNAME "norm.example" QTYPE "A" }
        COMPILE { f(a, b) }
        "#,
    )[0]
    .0
    .clone();
    let v4_l3 = v4_eth[14..].to_vec();

    let v6_eth = compile_fasm_frames(
        r#"
        HOST a { IP 2001:db8::1 MAC 00:11:22:33:44:01 }
        HOST b { IP 2001:db8::2 MAC 00:11:22:33:44:02 }
        FLOW f(x, y) { x -> y ICMP ECHO_REQUEST ID 99 SEQ 3 }
        COMPILE { f(a, b) }
        "#,
    )[0]
    .0
    .clone();
    let v6_l3 = v6_eth[14..].to_vec();

    // 1. LINKTYPE_ETHERNET (1)
    let pcap_eth = build_legacy_pcap(false, false, 1, &[(1, 0, v4_eth)]);
    let out_eth = reverse_pcap_bytes(&pcap_eth).expect("normalize LINKTYPE_ETHERNET");
    assert!(out_eth.fasm.contains("dns query") && out_eth.fasm.contains("mac 00:11:22:33:44:01"));
    assert!(compile_program(&parse_program(&out_eth.fasm).expect("parse")).is_ok());

    // 2. LINKTYPE_RAW (101) — L3-only IPv4 and IPv6 packets
    let pcap_raw = build_legacy_pcap(false, false, 101, &[(1, 0, v4_l3.clone())]);
    let out_raw = reverse_pcap_bytes(&pcap_raw).expect("normalize LINKTYPE_RAW");
    assert!(
        out_raw.fasm.contains("dns query") && !out_raw.fasm.contains("mac "),
        "L3-only LINKTYPE_RAW must omit host MAC declarations:\n{}",
        out_raw.fasm
    );
    assert!(compile_program(&parse_program(&out_raw.fasm).expect("parse")).is_ok());

    // 3. LINKTYPE_IPV4 (228)
    let pcap_ipv4 = build_legacy_pcap(false, false, 228, &[(1, 0, v4_l3.clone())]);
    let out_ipv4 = reverse_pcap_bytes(&pcap_ipv4).expect("normalize LINKTYPE_IPV4");
    assert!(out_ipv4.fasm.contains("dns query") && !out_ipv4.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_ipv4.fasm).expect("parse")).is_ok());

    // 4. LINKTYPE_IPV6 (229)
    let pcap_ipv6 = build_legacy_pcap(false, false, 229, &[(1, 0, v6_l3.clone())]);
    let out_ipv6 = reverse_pcap_bytes(&pcap_ipv6).expect("normalize LINKTYPE_IPV6");
    assert!(out_ipv6.fasm.contains("icmp echo_request") && !out_ipv6.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_ipv6.fasm).expect("parse")).is_ok());

    // 5. LINKTYPE_LINUX_SLL (113, 16-byte Linux cooked v1 header)
    let mut sll1 = Vec::with_capacity(16 + v4_l3.len());
    sll1.extend_from_slice(&0u16.to_be_bytes()); // packet_type = 0 (Unicast to us)
    sll1.extend_from_slice(&1u16.to_be_bytes()); // arphrd_type = 1 (ARPHRD_ETHER)
    sll1.extend_from_slice(&6u16.to_be_bytes()); // halen = 6
    sll1.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00]); // 6B MAC + 2B pad
    sll1.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol = IPv4
    sll1.extend_from_slice(&v4_l3);
    let pcap_sll1 = build_legacy_pcap(false, false, 113, &[(1, 0, sll1)]);
    let out_sll1 = reverse_pcap_bytes(&pcap_sll1).expect("normalize LINKTYPE_LINUX_SLL");
    assert!(out_sll1.fasm.contains("dns query") && out_sll1.fasm.contains("00:11:22:33:44:55"));
    assert!(compile_program(&parse_program(&out_sll1.fasm).expect("parse")).is_ok());

    // 6. LINKTYPE_LINUX_SLL2 (276, 20-byte Linux cooked v2 header)
    let mut sll2 = vec![0u8; 20];
    sll2[0..2].copy_from_slice(&0x86DDu16.to_be_bytes()); // protocol = IPv6
    sll2[10] = 6; // halen = 6
    sll2[12..18].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    sll2.extend_from_slice(&v6_l3);
    let pcap_sll2 = build_legacy_pcap(false, false, 276, &[(1, 0, sll2)]);
    let out_sll2 = reverse_pcap_bytes(&pcap_sll2).expect("normalize LINKTYPE_LINUX_SLL2");
    assert!(
        out_sll2.fasm.contains("icmp echo_request") && out_sll2.fasm.contains("aa:bb:cc:dd:ee:ff")
    );
    assert!(compile_program(&parse_program(&out_sll2.fasm).expect("parse")).is_ok());

    // 7. LINKTYPE_NULL (0, 4-byte LE BSD loopback AF_INET = 2)
    let mut bsd_null = Vec::with_capacity(4 + v4_l3.len());
    bsd_null.extend_from_slice(&2u32.to_le_bytes());
    bsd_null.extend_from_slice(&v4_l3);
    let pcap_null = build_legacy_pcap(false, false, 0, &[(1, 0, bsd_null)]);
    let out_null = reverse_pcap_bytes(&pcap_null).expect("normalize LINKTYPE_NULL");
    assert!(out_null.fasm.contains("dns query") && !out_null.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_null.fasm).expect("parse")).is_ok());

    // 8. LINKTYPE_LOOP (108, 4-byte BE OpenBSD loopback AF_INET6 = 24)
    let mut obsd_loop = Vec::with_capacity(4 + v6_l3.len());
    obsd_loop.extend_from_slice(&24u32.to_be_bytes());
    obsd_loop.extend_from_slice(&v6_l3);
    let pcap_loop = build_legacy_pcap(false, false, 108, &[(1, 0, obsd_loop)]);
    let out_loop = reverse_pcap_bytes(&pcap_loop).expect("normalize LINKTYPE_LOOP");
    assert!(out_loop.fasm.contains("icmp echo_request") && !out_loop.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_loop.fasm).expect("parse")).is_ok());
}

/// Verifies that 60-byte Ethernet minimum zero-padding and 64-byte padding + 4-byte FCS trailers
/// are stripped from IPv4, IPv6, ARP, 802.1Q VLAN, and EAPOL frames without leaving bogus
/// `hexpayload` bytes.
#[test]
fn test_ethernet_padding_and_fcs_trailer_stripping() {
    let frames = compile_fasm_frames(
        r#"
        HOST a { IP 192.168.10.1 MAC 00:11:22:33:44:01 }
        HOST b { IP 192.168.10.2 MAC 00:11:22:33:44:02 }
        FLOW f(x, y) {
            x -> y TCP SYN SEQ 1000 SRCPORT 50000 DSTPORT 80
            x -> y ARP REQUEST
            x -> y VLAN 100 ICMP ECHO_REQUEST ID 10 SEQ 1
        }
        COMPILE { f(a, b) }
        "#,
    );
    let ipv4_tcp_syn = frames[0].0.clone(); // 54 bytes
    let arp_req = frames[1].0.clone(); // 42 bytes
    let vlan_icmp = frames[2].0.clone(); // 46 bytes

    // Pad IPv4 TCP SYN (54B) to 60B with zeros + 4B non-zero FCS (64B total)
    let mut ipv4_padded_fcs = ipv4_tcp_syn.clone();
    ipv4_padded_fcs.resize(60, 0x00);
    ipv4_padded_fcs.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(ipv4_padded_fcs.len(), 64);

    // Pad ARP Request (42B) to 60B with zeros, and another copy to 64B with 4B FCS
    let mut arp_padded_60 = arp_req.clone();
    arp_padded_60.resize(60, 0x00);
    let mut arp_padded_64 = arp_padded_60.clone();
    arp_padded_64.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

    // Append 4-byte FCS trailer onto 802.1Q VLAN + IPv4 ICMP frame
    let mut vlan_padded_64 = vlan_icmp.clone();
    vlan_padded_64.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);

    // IPv6 UDP frame padded with 4-byte FCS trailer
    let v6_udp = compile_fasm_frames(
        r#"
        HOST a { IP 2001:db8::1 MAC 00:11:22:33:44:01 }
        HOST b { IP 2001:db8::2 MAC 00:11:22:33:44:02 }
        FLOW f(x, y) { x -> y NTP VN 4 MODE 3 }
        COMPILE { f(a, b) }
        "#,
    )[0]
    .0
    .clone();
    let mut v6_with_fcs = v6_udp.clone();
    v6_with_fcs.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

    // EAPOL frame (18 bytes) padded to 60B and 64B with FCS
    let eapol_raw = compile_fasm_frames(
        r#"
        HOST a { MAC 00:11:22:33:44:01 }
        HOST b { MAC 00:11:22:33:44:02 }
        FLOW f(x, y) { x -> y EAPOL TYPE START }
        COMPILE { f(a, b) }
        "#,
    )[0]
    .0
    .clone();
    let mut eapol_padded_64 = eapol_raw.clone();
    eapol_padded_64.resize(60, 0x00);
    eapol_padded_64.extend_from_slice(&[0xfe, 0xed, 0xfa, 0xce]);

    for (label, padded, orig_unpadded, expected_kw) in [
        ("ipv4_tcp_fcs", ipv4_padded_fcs, ipv4_tcp_syn, "tcp syn"),
        ("arp_pad_60", arp_padded_60, arp_req.clone(), "arp request"),
        ("arp_fcs_64", arp_padded_64, arp_req, "arp request"),
        (
            "vlan_icmp_fcs",
            vlan_padded_64,
            vlan_icmp,
            "icmp echo_request",
        ),
        ("ipv6_ntp_fcs", v6_with_fcs, v6_udp, "ntp"),
        ("eapol_fcs_64", eapol_padded_64, eapol_raw, "eapol"),
    ] {
        let pcap = build_legacy_pcap(false, false, 1, &[(1, 0, padded)]);
        let rev = reverse_pcap_bytes(&pcap)
            .unwrap_or_else(|e| panic!("[{label}] failed to reverse padded frame: {e}"));
        assert!(
            rev.fasm.contains(expected_kw),
            "[{label}] expected '{expected_kw}' in:\n{}",
            rev.fasm
        );
        assert!(
            !rev.fasm.contains("hexpayload"),
            "[{label}] padding/FCS must be stripped without leaking into hexpayload:\n{}",
            rev.fasm
        );
        let reframes = compile_fasm_frames(&rev.fasm);
        assert_eq!(
            reframes[0].0, orig_unpadded,
            "[{label}] recompiled frame must match unpadded original frame"
        );
    }
}

/// Verifies Rule 4 (Never Attempt Decryption): SNMPv3 `authPriv` (`ScopedPduData::EncryptedPdu`
/// where `msgFlags & 0x02 != 0`), SNMPv3 `authNoPriv` with unknown HMAC key, encrypted TLS
/// records, encrypted SSH post-key-exchange frames, and encrypted UDP payloads never attempt
/// decryption, step down cleanly to `udp`/`tcp` with `hexpayload` (or preserve opaque ciphertext),
/// and recompile to 100% byte-for-byte identical Ethernet frames (`orig_frames == reframes`).
#[test]
fn test_encrypted_traffic_lossless_fallback_without_decryption() {
    // 1. SNMPv3 authPriv (AES-128-CFB + SHA-256 and DES-CBC + MD5) + SNMPv3 authNoPriv
    let snmp3_encrypted_src = r#"
        HOST agent { IP 10.151.0.1   MAC 00:11:22:33:44:01 }
        HOST nms   { IP 10.151.0.250 MAC 00:11:22:33:44:02 }
        FLOW f(a, n) {
            a -> n SNMP3 TRAP USER "secops" ENGINEID "80001f8880510001" ENGINEBOOTS 5 ENGINETIME 1200 AUTH SHA256 "authpass123" PRIV AES "privpass123" OID 1.3.6.1.6.3.1.1.5.3 WAIT 5ms
            a -> n SNMP3 GET USER "legacy" ENGINEID "80001f8880510002" ENGINEBOOTS 1 ENGINETIME 99 AUTH MD5 "md5secret123" PRIV DES "dessecret123" OID 1.3.6.1.2.1.1.1.0 WAIT 5ms
            a -> n SNMP3 TRAP USER "authonly" ENGINEID "80001f8880510003" AUTH SHA512 "sha512secret" OID 1.3.6.1.2.1.1.3.0 WAIT 5ms
        }
        COMPILE { f(agent, nms) }
    "#;
    let orig_snmp = compile_fasm_frames(snmp3_encrypted_src);
    let pcap_snmp = build_pcapng_with_options(
        DataLink::ETHERNET,
        vec![InterfaceDescriptionOption::IfTsResol(9)],
        &orig_snmp,
    );
    let rev_snmp = reverse_pcap_bytes(&pcap_snmp).expect("reverse encrypted SNMPv3");
    assert!(!rev_snmp.fasm.contains("//"));
    assert!(
        rev_snmp.fasm.contains("udp") && rev_snmp.fasm.contains("hexpayload"),
        "encrypted SNMPv3 must step down to udp + hexpayload:\n{}",
        rev_snmp.fasm
    );
    let re_snmp = compile_fasm_frames(&rev_snmp.fasm);
    assert_eq!(orig_snmp.len(), re_snmp.len());
    for (i, ((ob, _), (rb, _))) in orig_snmp.iter().zip(re_snmp.iter()).enumerate() {
        assert_eq!(
            ob, rb,
            "encrypted SNMPv3 frame #{i} must recompile byte-for-byte identically"
        );
    }

    // 2. Encrypted TLS 1.3 Application Data, opaque multi-record TLS ciphertext on TCP/443,
    //    encrypted SSH binary ciphertext on TCP/22, and encrypted QUIC / WireGuard UDP ciphertext
    let encrypted_mix_src = r#"
        HOST client { IP 10.200.0.10 MAC 00:11:22:33:44:10 }
        HOST server { IP 10.200.0.20 MAC 00:11:22:33:44:20 }
        FLOW f(c, s) {
            c -> s TLS APP_DATA HEXPAYLOAD "9f8e7d6c5b4a39281706f5e4d3c2b1a0" WAIT 2ms
            c <- s TCP PSH ACK SRCPORT 443 DSTPORT 12345 HEXPAYLOAD "1703030004aabbccdd170303000411223344" WAIT 2ms
            c -> s TCP PSH ACK SRCPORT 12345 DSTPORT 22 HEXPAYLOAD "e491a75c82094b11d033fe87412299ab" WAIT 2ms
            c -> s UDP SRCPORT 51820 DSTPORT 51820 HEXPAYLOAD "04000000778899aabbccddeeff00112233445566778899" WAIT 2ms
        }
        COMPILE { f(client, server) }
    "#;
    let orig_mix = compile_fasm_frames(encrypted_mix_src);
    let pcap_mix = build_pcapng_with_options(
        DataLink::ETHERNET,
        vec![InterfaceDescriptionOption::IfTsResol(9)],
        &orig_mix,
    );
    let rev_mix = reverse_pcap_bytes(&pcap_mix).expect("reverse encrypted TLS/SSH/UDP mix");
    assert!(!rev_mix.fasm.contains("//"));
    let re_mix = compile_fasm_frames(&rev_mix.fasm);
    assert_eq!(orig_mix.len(), re_mix.len());
    for (i, ((ob, _), (rb, _))) in orig_mix.iter().zip(re_mix.iter()).enumerate() {
        assert_eq!(
            ob, rb,
            "encrypted mix frame #{i} must round-trip byte-for-byte identically\nFASM:\n{}",
            rev_mix.fasm
        );
    }
}

/// Synthesizes an IPv4 UDP Ethernet II frame with arbitrary payload bytes for fuzz testing.
fn craft_ipv4_udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let ip_len = 20 + udp_len;
    let mut f = Vec::with_capacity(14 + ip_len as usize);
    // Ethernet II header (dst, src, 0x0800)
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x02]);
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header (20 bytes)
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&ip_len.to_be_bytes());
    f.extend_from_slice(&0x1234u16.to_be_bytes());
    f.extend_from_slice(&0x0000u16.to_be_bytes());
    f.push(64);
    f.push(17); // UDP
    f.extend_from_slice(&[0x00, 0x00]); // checksum (ignored by dissector)
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[10, 0, 0, 2]);
    // UDP header (8 bytes)
    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&udp_len.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(payload);
    f
}

/// Synthesizes an IPv4 TCP Ethernet II frame with arbitrary payload bytes for fuzz testing.
fn craft_ipv4_tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let tcp_len = (20 + payload.len()) as u16;
    let ip_len = 20 + tcp_len;
    let mut f = Vec::with_capacity(14 + ip_len as usize);
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x02]);
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&ip_len.to_be_bytes());
    f.extend_from_slice(&0x1234u16.to_be_bytes());
    f.extend_from_slice(&0x0000u16.to_be_bytes());
    f.push(64);
    f.push(6); // TCP
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[10, 0, 0, 2]);
    // TCP header (20 bytes, PSH+ACK)
    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&1000u32.to_be_bytes());
    f.extend_from_slice(&1000u32.to_be_bytes());
    f.push(0x50); // data offset = 5 (20 bytes)
    f.push(0x18); // PSH | ACK
    f.extend_from_slice(&64240u16.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    f.extend_from_slice(payload);
    f
}

/// Verifies fuzz safety (zero panics and 100% compilable `.fasm` output) when feeding truncated
/// L2/L3/L4 headers (VLAN, QinQ, MPLS, IPv4, IPv6, TCP, UDP, SCTP) and corrupted L7 payloads
/// across well-known service ports (`53`, `67`, `80`, `123`, `161`, `162`, `389`, `443`, `445`,
/// `502`, `514`, `1812`, `3306`, `5060`, `5432`, `6379`, `20000`, `47808`, `4840`).
#[test]
fn test_malformed_and_truncated_headers_and_corrupted_l7_ports_fuzz_safety() {
    // 1. Sub-14-byte Ethernet frame is rejected cleanly with `Err` (never panics)
    let sub_14_pcap = build_legacy_pcap(false, false, 1, &[(1, 0, vec![0u8; 10])]);
    assert!(reverse_pcap_bytes(&sub_14_pcap).is_err());

    // 2. Truncated L2/L3/L4 frames (>= 14 bytes so they survive Ethernet container check)
    let mut fuzz_frames: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let dst_src = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01,
    ];

    // Truncated 802.1Q VLAN (EtherType 0x8100 with only 1 byte after EtherType)
    let mut trunc_vlan = dst_src.to_vec();
    trunc_vlan.extend_from_slice(&[0x81, 0x00, 0x00]);
    fuzz_frames.push((1, 0, trunc_vlan));

    // Truncated 802.1ad QinQ (outer 0x88A8 + incomplete inner tag)
    let mut trunc_qinq = dst_src.to_vec();
    trunc_qinq.extend_from_slice(&[0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x01]);
    fuzz_frames.push((1, 1000, trunc_qinq));

    // Truncated MPLS stack without BOS bit set
    let mut trunc_mpls = dst_src.to_vec();
    trunc_mpls.extend_from_slice(&[0x88, 0x47, 0x00, 0x01, 0x00, 0x40]);
    fuzz_frames.push((1, 2000, trunc_mpls));

    // Truncated IPv4 header (< 20 bytes after 0x0800) and bogus IHL = 2
    let mut trunc_ipv4 = dst_src.to_vec();
    trunc_ipv4.extend_from_slice(&[0x08, 0x00, 0x42, 0x00, 0x00, 0x14, 0x12, 0x34]);
    fuzz_frames.push((1, 3000, trunc_ipv4));

    // Truncated IPv6 header (< 40 bytes after 0x86DD)
    let mut trunc_ipv6 = dst_src.to_vec();
    trunc_ipv6.extend_from_slice(&[0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 17, 64]);
    fuzz_frames.push((1, 4000, trunc_ipv6));

    // Valid IPv4 header with truncated TCP (< 20B), truncated UDP (< 8B), and truncated SCTP (< 12B)
    for (proto, bad_l4) in [
        (6u8, vec![0x00, 0x50, 0x1f, 0x90, 0x00]),
        (17u8, vec![0x00, 0x35, 0x00]),
        (132u8, vec![0x0b, 0x59, 0x0b, 0x59, 0x01, 0x02]),
    ] {
        let mut f = dst_src.to_vec();
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        let ip_len = (20 + bad_l4.len()) as u16;
        f.extend_from_slice(&[0x45, 0x00]);
        f.extend_from_slice(&ip_len.to_be_bytes());
        f.extend_from_slice(&[0x12, 0x34, 0x00, 0x00, 64, proto, 0x00, 0x00]);
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        f.extend_from_slice(&bad_l4);
        fuzz_frames.push((2, u32::from(proto) * 1000, f));
    }

    // 3. Corrupted payloads across all 19 well-known ports over both UDP and TCP
    let ports: &[u16] = &[
        53, 67, 80, 123, 161, 162, 389, 443, 445, 502, 514, 1812, 3306, 5060, 5432, 6379, 20000,
        47808, 4840,
    ];
    let corrupted_payloads: &[&[u8]] = &[
        &[0xff],
        // Self-pointer DNS compression loop (`0xc0 0x0c` at offset 12) + truncated header
        &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
        ],
        // Truncated ASN.1 BER indefinite/oversized length (`0x30, 0x84, 0xff, 0xff, 0xff, 0x7f`)
        &[0x30, 0x84, 0xff, 0xff, 0xff, 0x7f, 0x02, 0x01, 0x03],
        // Malformed HTTP/SIP/RTSP/Redis/Modbus/DNP3/OPCUA/SMB/TLS headers with non-UTF8 bytes
        b"GET / HTTP/1.1\r\nHost: \xff\xfe\x00\r\n\r\n",
        b"\x16\x03\x03\x00\xff\x01\x00\x00\xfb\x03\x03",
        b"\x05\x64\x05\xc0\x01\x00\x00\x04\xff\xff",
        b"HEL\x46\xff\xff\x00\x00",
    ];

    let mut ts_counter = 10_000u32;
    for &port in ports {
        for sample in corrupted_payloads {
            ts_counter += 100;
            fuzz_frames.push((3, ts_counter, craft_ipv4_udp_frame(49152, port, sample)));
            ts_counter += 100;
            fuzz_frames.push((3, ts_counter, craft_ipv4_tcp_frame(49152, port, sample)));
        }
    }

    let fuzz_pcap = build_legacy_pcap(false, false, 1, &fuzz_frames);
    let rev = reverse_pcap_bytes(&fuzz_pcap)
        .expect("reverse_pcap_bytes must never panic or fail on surviving malformed L2-L7 frames");
    assert_eq!(rev.packet_count, fuzz_frames.len());
    assert!(
        !rev.fasm.contains("//"),
        "fuzz output must contain zero comments:\n{}",
        rev.fasm
    );

    let parsed = parse_program(&rev.fasm).unwrap_or_else(|e| {
        panic!(
            "decompiled fuzz .fasm must parse cleanly: {e:?}\n--- FASM ---\n{}",
            rev.fasm
        )
    });
    validate_semantics(&parsed, &rev.fasm)
        .expect("decompiled fuzz .fasm must pass semantic validation");
    let recompiled = compile_program(&parsed).expect("decompiled fuzz .fasm must compile cleanly");
    assert_eq!(recompiled.len(), fuzz_frames.len());
}
