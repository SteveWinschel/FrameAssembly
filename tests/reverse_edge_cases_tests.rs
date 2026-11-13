//! Edge-case, container-variant, linktype-normalization, padding/FCS-stripping, encrypted-fallback,
//! and malformed-input fuzz-safety test suite for FrameAssembly v3.0.0's PCAP/PCAPNG-to-`.frasm`
//! decompiler.
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

/// Compiles a `.frasm` snippet and returns its synthesized `(frame_bytes, timestamp_ns)` list.
fn compile_fasm_frames(fasm_src: &str) -> Vec<(Vec<u8>, u64)> {
    let prog = parse_program(fasm_src).expect("parse valid .frasm snippet");
    validate_semantics(&prog, fasm_src).expect("validate .frasm snippet");
    compile_program(&prog).expect("compile .frasm snippet")
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
        if is_be { v.to_be_bytes() } else { v.to_le_bytes() }
    };
    let u32_bytes = |v: u32| -> [u8; 4] {
        if is_be { v.to_be_bytes() } else { v.to_le_bytes() }
    };

    let magic: u32 = if is_nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
    buf.extend_from_slice(&u32_bytes(magic));
    buf.extend_from_slice(&u16_bytes(2));
    buf.extend_from_slice(&u16_bytes(4));
    buf.extend_from_slice(&u32_bytes(0));
    buf.extend_from_slice(&u32_bytes(0));
    buf.extend_from_slice(&u32_bytes(65535));
    buf.extend_from_slice(&u32_bytes(linktype));

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
/// and `.pcapng` captures with custom `IfTsResol`, `IfTsOffset`, and `SimplePacketBlock` blocks
/// decode frames and timestamps accurately.
#[test]
fn test_classic_pcap_all_4_magic_variants_and_pcapng_tsresol() {
    let frames = compile_fasm_frames(
        r#"
        host a { ip 10.0.0.1 mac 00:11:22:33:44:01 }
        host b { ip 10.0.0.2 mac 00:11:22:33:44:02 }
        flow f(x, y) {
            x -> y icmp echorequest id 1 seq 1
            x <- y icmp echoreply id 1 seq 1
        }
        compile { f(a, b) }
        "#,
    );
    let f0 = frames[0].0.clone();
    let f1 = frames[1].0.clone();

    let pcap_le_us = build_legacy_pcap(
        false,
        false,
        1,
        &[(100, 5_000, f0.clone()), (100, 8_000, f1.clone())],
    );
    assert_eq!(&pcap_le_us[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    let out_le_us = reverse_pcap_bytes(&pcap_le_us).expect("reverse LE microsecond .pcap");
    assert!(
        out_le_us.fasm.contains("host host1")
            && out_le_us.fasm.contains("icmp echoreply")
            && out_le_us.fasm.contains("wait 3ms"),
        "expected host1, icmp echoreply, and 3ms delta:\n{}",
        out_le_us.fasm
    );

    let pcap_be_us = build_legacy_pcap(
        true,
        false,
        1,
        &[(100, 1_000, f0.clone()), (100, 1_250, f1.clone())],
    );
    assert_eq!(&pcap_be_us[0..4], &[0xa1, 0xb2, 0xc3, 0xd4]);
    let out_be_us = reverse_pcap_bytes(&pcap_be_us).expect("reverse BE microsecond .pcap");
    assert!(out_be_us.fasm.contains("icmp echoreply") && out_be_us.fasm.contains("wait 250us"));

    let pcap_le_ns = build_legacy_pcap(
        false,
        true,
        1,
        &[(100, 1_000, f0.clone()), (100, 1_750, f1.clone())],
    );
    assert_eq!(&pcap_le_ns[0..4], &[0x4d, 0x3c, 0xb2, 0xa1]);
    let out_le_ns = reverse_pcap_bytes(&pcap_le_ns).expect("reverse LE nanosecond .pcap");
    assert!(out_le_ns.fasm.contains("icmp echoreply") && out_le_ns.fasm.contains("wait 750ns"));

    let pcap_be_ns = build_legacy_pcap(
        true,
        true,
        1,
        &[(100, 2_000, f0.clone()), (100, 2_500, f1.clone())],
    );
    assert_eq!(&pcap_be_ns[0..4], &[0xa1, 0xb2, 0x3c, 0x4d]);
    let out_be_ns = reverse_pcap_bytes(&pcap_be_ns).expect("reverse BE nanosecond .pcap");
    assert!(out_be_ns.fasm.contains("icmp echoreply") && out_be_ns.fasm.contains("wait 500ns"));

    let ng_ms = build_pcapng_with_options(
        DataLink::ETHERNET,
        vec![
            InterfaceDescriptionOption::IfTsResol(3),
            InterfaceDescriptionOption::IfTsOffset(100),
        ],
        &[(f0.clone(), 10), (f1.clone(), 15)],
    );
    let out_ng_ms = reverse_pcap_bytes(&ng_ms).expect("reverse PCAPNG with IfTsResol(3)");
    assert!(out_ng_ms.fasm.contains("wait 5ms"));

    let ng_bin = build_pcapng_with_options(
        DataLink::ETHERNET,
        vec![InterfaceDescriptionOption::IfTsResol(0x80 | 10)],
        &[(f0.clone(), 1024), (f1.clone(), 3072)],
    );
    let out_ng_bin =
        reverse_pcap_bytes(&ng_bin).expect("reverse PCAPNG with binary IfTsResol(0x80 | 10)");
    assert!(out_ng_bin.fasm.contains("wait 2s"));

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
    assert!(out_spb.fasm.contains("wait 0ms"));

    assert!(reverse_pcap_bytes(&[0x01, 0x02]).is_err());
    assert!(reverse_pcap_bytes(b"NOT_A_PCAP_FILE").is_err());
}

/// Verifies LinkType normalization across all 8 supported link-layer types.
#[test]
fn test_linktype_normalization_all_8_encapsulations() {
    let v4_eth = compile_fasm_frames(
        r#"
        host a { ip 10.1.1.1 mac 00:11:22:33:44:01 }
        host b { ip 10.1.1.2 mac 00:11:22:33:44:02 }
        flow f(x, y) { x -> y dns query txid 0x2222 qname "norm.example" qtype "a" }
        compile { f(a, b) }
        "#,
    )[0]
    .0
    .clone();
    let v4_l3 = v4_eth[14..].to_vec();

    let v6_eth = compile_fasm_frames(
        r#"
        host a { ip 2001:db8::1 mac 00:11:22:33:44:01 }
        host b { ip 2001:db8::2 mac 00:11:22:33:44:02 }
        flow f(x, y) { x -> y icmp echorequest id 99 seq 3 }
        compile { f(a, b) }
        "#,
    )[0]
    .0
    .clone();
    let v6_l3 = v6_eth[14..].to_vec();

    let pcap_eth = build_legacy_pcap(false, false, 1, &[(1, 0, v4_eth)]);
    let out_eth = reverse_pcap_bytes(&pcap_eth).expect("normalize LINKTYPE_ETHERNET");
    assert!(out_eth.fasm.contains("dns query") && out_eth.fasm.contains("mac 00:11:22:33:44:01"));
    assert!(compile_program(&parse_program(&out_eth.fasm).expect("parse")).is_ok());

    let pcap_raw = build_legacy_pcap(false, false, 101, &[(1, 0, v4_l3.clone())]);
    let out_raw = reverse_pcap_bytes(&pcap_raw).expect("normalize LINKTYPE_RAW");
    assert!(out_raw.fasm.contains("dns query") && !out_raw.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_raw.fasm).expect("parse")).is_ok());

    let pcap_ipv4 = build_legacy_pcap(false, false, 228, &[(1, 0, v4_l3.clone())]);
    let out_ipv4 = reverse_pcap_bytes(&pcap_ipv4).expect("normalize LINKTYPE_IPV4");
    assert!(out_ipv4.fasm.contains("dns query") && !out_ipv4.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_ipv4.fasm).expect("parse")).is_ok());

    let pcap_ipv6 = build_legacy_pcap(false, false, 229, &[(1, 0, v6_l3.clone())]);
    let out_ipv6 = reverse_pcap_bytes(&pcap_ipv6).expect("normalize LINKTYPE_IPV6");
    assert!(out_ipv6.fasm.contains("icmp echorequest") && !out_ipv6.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_ipv6.fasm).expect("parse")).is_ok());

    let mut sll1 = Vec::with_capacity(16 + v4_l3.len());
    sll1.extend_from_slice(&0u16.to_be_bytes());
    sll1.extend_from_slice(&1u16.to_be_bytes());
    sll1.extend_from_slice(&6u16.to_be_bytes());
    sll1.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00]);
    sll1.extend_from_slice(&0x0800u16.to_be_bytes());
    sll1.extend_from_slice(&v4_l3);
    let pcap_sll1 = build_legacy_pcap(false, false, 113, &[(1, 0, sll1)]);
    let out_sll1 = reverse_pcap_bytes(&pcap_sll1).expect("normalize LINKTYPE_LINUX_SLL");
    assert!(out_sll1.fasm.contains("dns query") && out_sll1.fasm.contains("00:11:22:33:44:55"));
    assert!(compile_program(&parse_program(&out_sll1.fasm).expect("parse")).is_ok());

    let mut sll2 = vec![0u8; 20];
    sll2[0..2].copy_from_slice(&0x86DDu16.to_be_bytes());
    sll2[10] = 6;
    sll2[12..18].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    sll2.extend_from_slice(&v6_l3);
    let pcap_sll2 = build_legacy_pcap(false, false, 276, &[(1, 0, sll2)]);
    let out_sll2 = reverse_pcap_bytes(&pcap_sll2).expect("normalize LINKTYPE_LINUX_SLL2");
    assert!(out_sll2.fasm.contains("icmp echorequest") && out_sll2.fasm.contains("aa:bb:cc:dd:ee:ff"));
    assert!(compile_program(&parse_program(&out_sll2.fasm).expect("parse")).is_ok());

    let mut bsd_null = Vec::with_capacity(4 + v4_l3.len());
    bsd_null.extend_from_slice(&2u32.to_le_bytes());
    bsd_null.extend_from_slice(&v4_l3);
    let pcap_null = build_legacy_pcap(false, false, 0, &[(1, 0, bsd_null)]);
    let out_null = reverse_pcap_bytes(&pcap_null).expect("normalize LINKTYPE_NULL");
    assert!(out_null.fasm.contains("dns query") && !out_null.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_null.fasm).expect("parse")).is_ok());

    let mut obsd_loop = Vec::with_capacity(4 + v6_l3.len());
    obsd_loop.extend_from_slice(&24u32.to_be_bytes());
    obsd_loop.extend_from_slice(&v6_l3);
    let pcap_loop = build_legacy_pcap(false, false, 108, &[(1, 0, obsd_loop)]);
    let out_loop = reverse_pcap_bytes(&pcap_loop).expect("normalize LINKTYPE_LOOP");
    assert!(out_loop.fasm.contains("icmp echorequest") && !out_loop.fasm.contains("mac "));
    assert!(compile_program(&parse_program(&out_loop.fasm).expect("parse")).is_ok());
}

/// Verifies that 60-byte Ethernet minimum zero-padding and 64-byte padding + 4-byte FCS trailers
/// are stripped without leaving bogus `hexpayload` bytes.
#[test]
fn test_ethernet_padding_and_fcs_trailer_stripping() {
    let frames = compile_fasm_frames(
        r#"
        host a { ip 192.168.10.1 mac 00:11:22:33:44:01 }
        host b { ip 192.168.10.2 mac 00:11:22:33:44:02 }
        flow f(x, y) {
            x -> y tcp syn seq 1000 srcport 50000 dstport 80
            x -> y arp request
            x -> y vlan 100 icmp echorequest id 10 seq 1
        }
        compile { f(a, b) }
        "#,
    );
    let ipv4_tcp_syn = frames[0].0.clone();
    let arp_req = frames[1].0.clone();
    let vlan_icmp = frames[2].0.clone();

    let mut ipv4_padded_fcs = ipv4_tcp_syn.clone();
    ipv4_padded_fcs.resize(60, 0x00);
    ipv4_padded_fcs.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    let mut arp_padded_60 = arp_req.clone();
    arp_padded_60.resize(60, 0x00);
    let mut arp_padded_64 = arp_padded_60.clone();
    arp_padded_64.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

    let mut vlan_padded_64 = vlan_icmp.clone();
    vlan_padded_64.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);

    let v6_udp = compile_fasm_frames(
        r#"
        host a { ip 2001:db8::1 mac 00:11:22:33:44:01 }
        host b { ip 2001:db8::2 mac 00:11:22:33:44:02 }
        flow f(x, y) { x -> y ntp vn 4 mode 3 }
        compile { f(a, b) }
        "#,
    )[0]
    .0
    .clone();
    let mut v6_with_fcs = v6_udp.clone();
    v6_with_fcs.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

    let eapol_raw = compile_fasm_frames(
        r#"
        host a { mac 00:11:22:33:44:01 }
        host b { mac 00:11:22:33:44:02 }
        flow f(x, y) { x -> y eapol type start }
        compile { f(a, b) }
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
        ("vlan_icmp_fcs", vlan_padded_64, vlan_icmp, "icmp echorequest"),
        ("ipv6_ntp_fcs", v6_with_fcs, v6_udp, "ntp"),
        ("eapol_fcs_64", eapol_padded_64, eapol_raw, "eapol"),
    ] {
        let pcap = build_legacy_pcap(false, false, 1, &[(1, 0, padded)]);
        let rev = reverse_pcap_bytes(&pcap)
            .unwrap_or_else(|e| panic!("[{label}] failed to reverse padded frame: {e}"));
        assert!(rev.fasm.contains(expected_kw));
        assert!(!rev.fasm.contains("hexpayload"));
        let reframes = compile_fasm_frames(&rev.fasm);
        assert_eq!(reframes[0].0, orig_unpadded);
    }
}

/// Verifies lossless `udp`/`tcp` + `hexpayload` fallback without decryption on encrypted SNMPv3,
/// TLS Application Data, SSH ciphertext, and WireGuard/QUIC UDP ciphertext.
#[test]
fn test_encrypted_traffic_lossless_fallback_without_decryption() {
    let snmp3_encrypted_src = r#"
        host agent { ip 10.151.0.1   mac 00:11:22:33:44:01 }
        host nms   { ip 10.151.0.250 mac 00:11:22:33:44:02 }
        flow f(a, n) {
            a -> n snmp3 trap user "secops" engineid "80001f8880510001" engineboots 5 enginetime 1200 auth sha256 "authpass123" priv aes "privpass123" oid 1.3.6.1.6.3.1.1.5.3 wait 5ms
            a -> n snmp3 get user "legacy" engineid "80001f8880510002" engineboots 1 enginetime 99 auth md5 "md5secret123" priv des "dessecret123" oid 1.3.6.1.2.1.1.1.0 wait 5ms
            a -> n snmp3 trap user "authonly" engineid "80001f8880510003" auth sha512 "sha512secret" oid 1.3.6.1.2.1.1.3.0 wait 5ms
        }
        compile { f(agent, nms) }
    "#;
    let orig_snmp = compile_fasm_frames(snmp3_encrypted_src);
    let pcap_snmp = build_pcapng_with_options(
        DataLink::ETHERNET,
        vec![InterfaceDescriptionOption::IfTsResol(9)],
        &orig_snmp,
    );
    let rev_snmp = reverse_pcap_bytes(&pcap_snmp).expect("reverse encrypted SNMPv3");
    assert!(!rev_snmp.fasm.contains("//"));
    assert!(rev_snmp.fasm.contains("udp") && rev_snmp.fasm.contains("hexpayload"));
    let re_snmp = compile_fasm_frames(&rev_snmp.fasm);
    assert_eq!(orig_snmp.len(), re_snmp.len());
    for ((ob, _), (rb, _)) in orig_snmp.iter().zip(re_snmp.iter()) {
        assert_eq!(ob, rb);
    }

    let encrypted_mix_src = r#"
        host client { ip 10.200.0.10 mac 00:11:22:33:44:10 }
        host server { ip 10.200.0.20 mac 00:11:22:33:44:20 }
        flow f(c, s) {
            c -> s tls appdata hexpayload "9f8e7d6c5b4a39281706f5e4d3c2b1a0" wait 2ms
            c <- s tcp psh ack srcport 443 dstport 12345 hexpayload "1703030004aabbccdd170303000411223344" wait 2ms
            c -> s tcp psh ack srcport 12345 dstport 22 hexpayload "e491a75c82094b11d033fe87412299ab" wait 2ms
            c -> s udp srcport 51820 dstport 51820 hexpayload "04000000778899aabbccddeeff00112233445566778899" wait 2ms
        }
        compile { f(client, server) }
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
    for ((ob, _), (rb, _)) in orig_mix.iter().zip(re_mix.iter()) {
        assert_eq!(ob, rb);
    }
}

/// Synthesizes an IPv4 UDP Ethernet II frame with arbitrary payload bytes for fuzz testing.
fn craft_ipv4_udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let ip_len = 20 + udp_len;
    let mut f = Vec::with_capacity(14 + ip_len as usize);
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x02]);
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&ip_len.to_be_bytes());
    f.extend_from_slice(&0x1234u16.to_be_bytes());
    f.extend_from_slice(&0x0000u16.to_be_bytes());
    f.push(64);
    f.push(17);
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[10, 0, 0, 2]);
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
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&ip_len.to_be_bytes());
    f.extend_from_slice(&0x1234u16.to_be_bytes());
    f.extend_from_slice(&0x0000u16.to_be_bytes());
    f.push(64);
    f.push(6);
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[10, 0, 0, 2]);
    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&1000u32.to_be_bytes());
    f.extend_from_slice(&1000u32.to_be_bytes());
    f.push(0x50);
    f.push(0x18);
    f.extend_from_slice(&64240u16.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    f.extend_from_slice(payload);
    f
}

/// Verifies fuzz safety (zero panics and 100% compilable `.frasm` output) on truncated L2/L3/L4
/// headers and corrupted L7 payloads across well-known service ports.
#[test]
fn test_malformed_and_truncated_headers_and_corrupted_l7_ports_fuzz_safety() {
    let sub_14_pcap = build_legacy_pcap(false, false, 1, &[(1, 0, vec![0u8; 10])]);
    assert!(reverse_pcap_bytes(&sub_14_pcap).is_err());

    let mut fuzz_frames: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let dst_src = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01,
    ];

    let mut trunc_vlan = dst_src.to_vec();
    trunc_vlan.extend_from_slice(&[0x81, 0x00, 0x00]);
    fuzz_frames.push((1, 0, trunc_vlan));

    let mut trunc_qinq = dst_src.to_vec();
    trunc_qinq.extend_from_slice(&[0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x01]);
    fuzz_frames.push((1, 1000, trunc_qinq));

    let mut trunc_mpls = dst_src.to_vec();
    trunc_mpls.extend_from_slice(&[0x88, 0x47, 0x00, 0x01, 0x00, 0x40]);
    fuzz_frames.push((1, 2000, trunc_mpls));

    let mut trunc_ipv4 = dst_src.to_vec();
    trunc_ipv4.extend_from_slice(&[0x08, 0x00, 0x42, 0x00, 0x00, 0x14, 0x12, 0x34]);
    fuzz_frames.push((1, 3000, trunc_ipv4));

    let mut trunc_ipv6 = dst_src.to_vec();
    trunc_ipv6.extend_from_slice(&[0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 17, 64]);
    fuzz_frames.push((1, 4000, trunc_ipv6));

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

    let ports: &[u16] = &[
        53, 67, 80, 123, 161, 162, 389, 443, 445, 502, 514, 1812, 3306, 5060, 5432, 6379, 20000,
        47808, 4840,
    ];
    let corrupted_payloads: &[&[u8]] = &[
        &[0xff],
        &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
        ],
        &[0x30, 0x84, 0xff, 0xff, 0xff, 0x7f, 0x02, 0x01, 0x03],
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
    assert!(!rev.fasm.contains("//"));

    let parsed = parse_program(&rev.fasm).expect("decompiled fuzz .frasm must parse cleanly");
    validate_semantics(&parsed, &rev.fasm)
        .expect("decompiled fuzz .frasm must pass semantic validation");
    let recompiled = compile_program(&parsed).expect("decompiled fuzz .frasm must compile cleanly");
    assert_eq!(recompiled.len(), fuzz_frames.len());
}
