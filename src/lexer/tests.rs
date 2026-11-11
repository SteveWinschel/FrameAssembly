//! Unit tests for the FrameAssembly `logos` lexical analyzer (`src/lexer/mod.rs`).
//!
//! Verifies regex priority disambiguation between 4-octet IPv4 addresses (`Token::IpAddress`),
//! dotted ASN.1 Object Identifiers (`Token::OidStr`), signed/unsigned integer and hexadecimal
//! numeric literals (`Token::Number`), IEEE 802.3 MAC addresses (`Token::MacAddress`), IPv6
//! colons, strict-lowercase time suffixes (`ns`, `us`, `ms`, `s`, `m`), flexible user-defined
//! identifiers (`fw-dmz-01`, `core_sw`), and all strict-lowercase `[a-z0-9]+` protocol keywords.

use super::*;

/// Verifies that 4-octet IPv4 addresses are tokenized as `Token::IpAddress` rather than `Token::OidStr`.
#[test]
fn test_ip_address_not_shadowed_by_oid() {
    let input = "192.168.1.1 10.0.0.1";
    let tokens = lex(input).unwrap();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].0, Token::IpAddress("192.168.1.1"));
    assert_eq!(tokens[1].0, Token::IpAddress("10.0.0.1"));
}

/// Verifies tokenization of leading-dot and multi-arc OIDs alongside positive and negative numbers.
#[test]
fn test_oid_leading_dot_and_numbers() {
    let input = ".1.3.6.1.4.1 1.3.6.1.2.1.1.1.0 100 -42";
    let tokens = lex(input).unwrap();
    assert_eq!(tokens.len(), 4);
    assert_eq!(tokens[0].0, Token::OidStr(".1.3.6.1.4.1"));
    assert_eq!(tokens[1].0, Token::OidStr("1.3.6.1.2.1.1.1.0"));
    assert_eq!(tokens[2].0, Token::Number("100"));
    assert_eq!(tokens[3].0, Token::Number("-42"));
}

/// Verifies tokenization of IPv6 addresses and colon-delimited MAC addresses.
#[test]
fn test_ipv6_and_mac_addresses() {
    let input = "fe80::1 ::1 2001:db8::1 00:11:22:33:44:55";
    let tokens = lex(input).unwrap();
    assert_eq!(tokens.len(), 4);
    assert_eq!(tokens[0].0, Token::IpAddress("fe80::1"));
    assert_eq!(tokens[1].0, Token::IpAddress("::1"));
    assert_eq!(tokens[2].0, Token::IpAddress("2001:db8::1"));
    assert_eq!(tokens[3].0, Token::MacAddress("00:11:22:33:44:55"));
}

/// Verifies tokenization of `hexpayload` and strict-lowercase duration time unit suffixes.
#[test]
fn test_hexpayload_and_time_units() {
    let input = "hexpayload 5ns 10us 20ms 1s 2m";
    let tokens = lex(input).unwrap();
    assert_eq!(tokens.len(), 11);
    assert_eq!(tokens[0].0, Token::HexPayload);
    assert_eq!(tokens[1].0, Token::Number("5"));
    assert_eq!(tokens[2].0, Token::Ns);
    assert_eq!(tokens[3].0, Token::Number("10"));
    assert_eq!(tokens[4].0, Token::Us);
    assert_eq!(tokens[5].0, Token::Number("20"));
    assert_eq!(tokens[6].0, Token::Ms);
    assert_eq!(tokens[7].0, Token::Number("1"));
    assert_eq!(tokens[8].0, Token::Sec);
    assert_eq!(tokens[9].0, Token::Number("2"));
    assert_eq!(tokens[10].0, Token::Min);
}

/// Verifies tokenization of escaped string literals.
#[test]
fn test_string_escapes_tokenization() {
    let input = r#""hello\r\n\x41\u0042\"world\\""#;
    let tokens = lex(input).unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, Token::StringLit(input));
}

/// Verifies v2.0.0 strict-lowercase `[a-z0-9]+` keywords, promoted sub-keywords, unified tokens,
/// removal of `loop`, and rejection of uppercase/snake_case/kebab-case forms into `Token::Ident`.
#[test]
fn test_strict_lowercase_keywords_and_flexible_identifiers() {
    let valid_kw = "host flow compile wait tcp syn ack sackperm agentip hellotime whois pkttype read write nop error shutdownack echorequest innervlan clienthello hosthdr transporthdr";
    let kw_tokens: Vec<Token<'_>> = lex(valid_kw).unwrap().into_iter().map(|(t, _)| t).collect();
    assert_eq!(
        kw_tokens,
        vec![
            Token::Host,
            Token::Flow,
            Token::Compile,
            Token::Wait,
            Token::Tcp,
            Token::Syn,
            Token::Ack,
            Token::SackPerm,
            Token::AgentIp,
            Token::HelloTime,
            Token::Whois,
            Token::PktType,
            Token::Read,
            Token::Write,
            Token::Nop,
            Token::ErrorKw,
            Token::ShutdownAck,
            Token::EchoRequest,
            Token::InnerVlan,
            Token::ClientHello,
            Token::HostHdr,
            Token::TransportHdr,
        ]
    );

    let non_kw = "HOST loop LOOP echo_request client-hello SACK_PERM WHO_IS fw-dmz-01->core_sw_02";
    let non_kw_tokens: Vec<Token<'_>> = lex(non_kw).unwrap().into_iter().map(|(t, _)| t).collect();
    assert_eq!(
        non_kw_tokens,
        vec![
            Token::Ident("HOST"),
            Token::Ident("loop"),
            Token::Ident("LOOP"),
            Token::Ident("echo_request"),
            Token::Ident("client-hello"),
            Token::Ident("SACK_PERM"),
            Token::Ident("WHO_IS"),
            Token::Ident("fw-dmz-01"),
            Token::RightArrow,
            Token::Ident("core_sw_02"),
        ]
    );

    assert_eq!(
        suggest_v2_lowercase_keyword("HOST").as_deref(),
        Some("host")
    );
    assert_eq!(
        suggest_v2_lowercase_keyword("echo_request").as_deref(),
        Some("echorequest")
    );
    assert_eq!(
        suggest_v2_lowercase_keyword("client-hello").as_deref(),
        Some("clienthello")
    );
    assert_eq!(suggest_v2_lowercase_keyword("host"), None);
    assert_eq!(suggest_v2_lowercase_keyword("fw-dmz-01"), None);
}

/// Verifies native tokenization of colon-separated, hyphen-separated, and Cisco dotted-quad MAC addresses.
#[test]
fn test_multi_format_mac_tokenization() {
    let input = "00:1a:2b:3c:4d:5e 00-1A-2B-3C-4D-5E 001a.2b3c.4d5e";
    let tokens = lex(input).unwrap();
    assert_eq!(tokens.len(), 3);
    assert_eq!(tokens[0].0, Token::MacAddress("00:1a:2b:3c:4d:5e"));
    assert_eq!(tokens[1].0, Token::MacAddress("00-1A-2B-3C-4D-5E"));
    assert_eq!(tokens[2].0, Token::MacAddress("001a.2b3c.4d5e"));
}

/// Verifies that common non-programmer lexical mistakes produce plain-English hints without compiler jargon.
#[test]
fn test_plain_english_lexer_error_hints() {
    use miette::Diagnostic;

    let cases = [
        ("# router config", "comments in .fasm start with '//'"),
        ("/* block */", "block comments are not supported"),
        ("host a { ip '10.0.0.1' }", "single quotes are not used"),
        (
            "host a { ip 10.0.0.1/24 }",
            "subnet masks (CIDR notation) are not used",
        ),
        ("host a = { ip 10.0.0.1 }", "assignment symbol '=' is not used"),
        ("host a { ip: 10.0.0.1 }", "assignment symbol ':' is not used"),
        ("a -> b tcp [syn]", "square brackets '[' and ']' are not used"),
        ("host a { ip 10.0.0.1; }", "semicolons are not needed"),
        (
            "+5ms a -> b tcp syn",
            "relative delay prefixes like '+5ms' are not used",
        ),
    ];

    for (src, expected_hint) in cases {
        let err = lex(src).unwrap_err();
        let combined = format!(
            "{} {}",
            err,
            err.help().map(|h| h.to_string()).unwrap_or_default()
        );
        assert!(
            combined.contains(expected_hint),
            "For input `{src}`, expected diagnostic containing `{expected_hint}`, got `{combined}`"
        );
        assert!(!combined.contains("AST"));
    }
}

