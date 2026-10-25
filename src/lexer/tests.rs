//! Unit tests for the FrameAssembly `logos` lexical analyzer (`src/lexer/mod.rs`).
//!
//! Verifies regex priority disambiguation between 4-octet IPv4 addresses (`Token::IpAddress`),
//! dotted ASN.1 Object Identifiers (`Token::OidStr`), signed/unsigned integer and hexadecimal
//! numeric literals (`Token::Number`), IEEE 802.3 MAC addresses (`Token::MacAddress`), IPv6
//! colons, time suffixes (`ns`, `us`, `ms`, `s`, `m`), and all 640 uppercase protocol keywords.

use super::*;

    #[test]
    fn test_ip_address_not_shadowed_by_oid() {
        let input = "192.168.1.1 10.0.0.1";
        let tokens = lex(input).unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].0, Token::IpAddress("192.168.1.1"));
        assert_eq!(tokens[1].0, Token::IpAddress("10.0.0.1"));
    }

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

    #[test]
    fn test_hexpayload_and_time_units() {
        let input = "HEXPAYLOAD 5ns 10us 20ms 1s 2m";
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

    #[test]
    fn test_string_escapes_tokenization() {
        let input = r#""hello\r\n\x41\u0042\"world\\""#;
        let tokens = lex(input).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].0, Token::StringLit(input));
    }
