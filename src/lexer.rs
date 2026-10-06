use logos::Logos;

/// Represents all lexical tokens recognized by the FrameAssembly DSL.
/// 
/// The lexer ignores whitespace and single-line comments.
/// 
/// # Examples
/// ```
/// use frameassembly::lexer::Token;
/// 
/// let token = Token::Host;
/// assert_eq!(token, Token::Host);
/// ```
#[derive(Logos, Debug, PartialEq, Clone)]
#[logos(skip r"[ \t\n\f]+")]
#[logos(skip r"//.*")]
pub enum Token<'a> {
    #[token("HOST")]
    Host,
    #[token("FLOW")]
    Flow,
    #[token("IP")]
    Ip,
    #[token("MAC")]
    Mac,
    #[token("COMPILE")]
    Compile,
    #[token("LOOP")]
    Loop,
    #[token("TCP")]
    Tcp,
    #[token("UDP")]
    Udp,
    #[token("SYN")]
    Syn,
    #[token("ACK")]
    Ack,
    #[token("SRCPORT")]
    SrcPort,
    #[token("DSTPORT")]
    DstPort,
    #[token("PORT")]
    Port,
    #[token("SEQ")]
    Seq,
    #[token("ACKNUM")]
    AckNum,
    #[token("WIN")]
    Win,
    #[token("PAYLOAD")]
    Payload,
    #[token("WAIT")]
    Wait,
    #[token("SNMP1")]
    Snmp1,
    #[token("SNMP2")]
    Snmp2,
    #[token("SNMP3")]
    Snmp3,
    #[token("TRAP")]
    Trap,
    #[token("COMMUNITY")]
    Community,
    #[token("USER")]
    User,
    #[token("OID")]
    Oid,
    #[token("SYSUPTIME")]
    SysUpTime,

    #[token("->")]
    RightArrow,
    #[token("<-")]
    LeftArrow,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token(",")]
    Comma,
    #[token("=")]
    Equals,

    // Time suffixes
    #[token("ms", priority = 2)]
    Ms,
    #[token("s", priority = 2)]
    Sec,
    #[token("m", priority = 2)]
    Min,

    #[regex("[a-zA-Z_][a-zA-Z0-9_]*", priority = 1)]
    Ident(&'a str),

    #[regex(r#""([^"\\]|\\["\\bnfrt]|u[a-fA-F0-9]{4})*""#)]
    StringLit(&'a str),

    // Match IPv4 and IPv6-like strings loosely, parser will validate
    #[regex(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", priority = 4)]
    IpAddress(&'a str),

    // Match MAC addresses loosely
    #[regex(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")]
    MacAddress(&'a str),

    // Match OIDs loosely
    #[regex(r"[0-9]+(\.[0-9]+)+", priority = 5)]
    OidStr(&'a str),

    #[regex("[0-9]+")]
    Number(&'a str),
}

/// Lexes an input string into a sequence of tokens and their source spans.
///
/// # Examples
/// ```
/// use frameassembly::lexer::lex;
///
/// let input = "HOST example { IP 10.0.0.1 }";
/// let tokens = lex(input).unwrap();
/// assert_eq!(tokens.len(), 6);
/// ```
///
/// # Errors
/// Returns a `CompilerError::LexError` if an unrecognized sequence of characters is encountered.
pub fn lex<'a>(
    input: &'a str,
) -> Result<alloc::vec::Vec<(Token<'a>, std::ops::Range<usize>)>, crate::error::CompilerError> {
    let mut lexer = Token::lexer(input);
    let mut tokens = alloc::vec::Vec::new();
    while let Some(res) = lexer.next() {
        match res {
            Ok(token) => tokens.push((token, lexer.span())),
            Err(_) => {
                return Err(crate::error::CompilerError::LexError {
                    src: input.to_string(),
                    span: (lexer.span().start, lexer.span().end - lexer.span().start),
                });
            }
        }
    }
    Ok(tokens)
}
