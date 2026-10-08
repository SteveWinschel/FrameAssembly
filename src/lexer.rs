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
    /// `HOST` keyword
    #[token("HOST")]
    Host,
    /// `FLOW` keyword
    #[token("FLOW")]
    Flow,
    /// `IP` keyword
    #[token("IP")]
    Ip,
    /// `MAC` keyword
    #[token("MAC")]
    Mac,
    /// `COMPILE` keyword
    #[token("COMPILE")]
    Compile,
    /// `LOOP` keyword
    #[token("LOOP")]
    Loop,
    /// `TCP` keyword
    #[token("TCP")]
    Tcp,
    /// `UDP` keyword
    #[token("UDP")]
    Udp,
    /// `SYN` flag
    #[token("SYN")]
    Syn,
    /// `ACK` flag
    #[token("ACK")]
    Ack,
    /// `FIN` flag
    #[token("FIN")]
    Fin,
    /// `RST` flag
    #[token("RST")]
    Rst,
    /// `PSH` flag
    #[token("PSH")]
    Psh,
    /// `URG` flag
    #[token("URG")]
    Urg,
    /// `ECE` flag
    #[token("ECE")]
    Ece,
    /// `CWR` flag
    #[token("CWR")]
    Cwr,
    /// `SRCPORT` keyword
    #[token("SRCPORT")]
    SrcPort,
    /// `DSTPORT` keyword
    #[token("DSTPORT")]
    DstPort,
    /// `PORT` keyword
    #[token("PORT")]
    Port,
    /// `SEQ` keyword
    #[token("SEQ")]
    Seq,
    /// `ACKNUM` keyword
    #[token("ACKNUM")]
    AckNum,
    /// `WIN` keyword
    #[token("WIN")]
    Win,
    /// `PAYLOAD` keyword
    #[token("PAYLOAD")]
    Payload,
    /// `WAIT` keyword
    #[token("WAIT")]
    Wait,
    /// `SNMP1` keyword
    #[token("SNMP1")]
    Snmp1,
    /// `SNMP2` keyword
    #[token("SNMP2")]
    Snmp2,
    /// `SNMP3` keyword
    #[token("SNMP3")]
    Snmp3,
    /// `TRAP` keyword
    #[token("TRAP")]
    Trap,
    /// `GET` keyword
    #[token("GET")]
    Get,
    /// `SET` keyword
    #[token("SET")]
    Set,
    /// `RESPONSE` keyword
    #[token("RESPONSE")]
    Response,
    /// `INFORM` keyword
    #[token("INFORM")]
    Inform,
    /// `GETNEXT` keyword
    #[token("GETNEXT")]
    GetNext,
    /// `GETBULK` keyword
    #[token("GETBULK")]
    GetBulk,
    /// `COMMUNITY` keyword
    #[token("COMMUNITY")]
    Community,
    /// `USER` keyword
    #[token("USER")]
    User,
    /// `OID` keyword
    #[token("OID")]
    Oid,
    /// `SYSUPTIME` keyword
    #[token("SYSUPTIME")]
    SysUpTime,

    /// `VARBIND` keyword
    #[token("VARBIND")]
    VarBind,
    /// `NULLVAL` keyword
    #[token("NULLVAL")]
    NullVal,
    /// `STRING` keyword
    #[token("STRING")]
    StringVal,
    /// `INT` keyword
    #[token("INT")]
    IntVal,
    /// `TIMETICKS` keyword
    #[token("TIMETICKS")]
    TimeTicksVal,
    /// `IPVAL` keyword
    #[token("IPVAL")]
    IpVal,

    /// `ENTERPRISE` keyword
    #[token("ENTERPRISE")]
    Enterprise,
    /// `AGENTIP` keyword
    #[token("AGENTIP")]
    AgentIp,
    /// `GENTRAP` keyword
    #[token("GENTRAP")]
    GenTrap,
    /// `SPECTRAP` keyword
    #[token("SPECTRAP")]
    SpecTrap,

    /// `ENGINEID` keyword
    #[token("ENGINEID")]
    EngineId,
    /// `ENGINEBOOTS` keyword
    #[token("ENGINEBOOTS")]
    EngineBoots,
    /// `ENGINETIME` keyword
    #[token("ENGINETIME")]
    EngineTime,
    /// `CONTEXTNAME` keyword
    #[token("CONTEXTNAME")]
    ContextName,
    /// `AUTH` keyword
    #[token("AUTH")]
    Auth,
    /// `PRIV` keyword
    #[token("PRIV")]
    Priv,
    /// `MD5` keyword
    #[token("MD5")]
    Md5,
    /// `SHA` keyword
    #[token("SHA")]
    Sha,
    /// `SHA256` keyword
    #[token("SHA256")]
    Sha256,
    /// `SHA384` keyword
    #[token("SHA384")]
    Sha384,
    /// `SHA512` keyword
    #[token("SHA512")]
    Sha512,
    /// `DES` keyword
    #[token("DES")]
    Des,
    /// `AES` keyword
    #[token("AES")]
    Aes,

    /// `NONREPEATERS` keyword
    #[token("NONREPEATERS")]
    NonRepeaters,
    /// `MAXREPETITIONS` keyword
    #[token("MAXREPETITIONS")]
    MaxRepetitions,
    /// `REQID` keyword
    #[token("REQID")]
    ReqId,

    /// `->` operator
    #[token("->")]
    RightArrow,
    /// `<-` operator
    #[token("<-")]
    LeftArrow,
    /// `{` token
    #[token("{")]
    LBrace,
    /// `}` token
    #[token("}")]
    RBrace,
    /// `(` token
    #[token("(")]
    LParen,
    /// `)` token
    #[token(")")]
    RParen,
    /// `,` token
    #[token(",")]
    Comma,

    // Time suffixes
    /// `ms` suffix
    #[token("ms", priority = 2)]
    Ms,
    /// `s` suffix
    #[token("s", priority = 2)]
    Sec,
    /// `m` suffix
    #[token("m", priority = 2)]
    Min,

    /// Identifier
    #[regex("[a-zA-Z_][a-zA-Z0-9_]*", priority = 1)]
    Ident(&'a str),

    /// String literal
    #[regex(r#""([^"\\]|\\["\\bnfrt]|u[a-fA-F0-9]{4})*""#)]
    StringLit(&'a str),

    // Match IPv4 and IPv6-like strings loosely, parser will validate
    /// IPv4/IPv6 address
    #[regex(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", priority = 4)]
    IpAddress(&'a str),

    // Match MAC addresses loosely
    /// MAC address
    #[regex(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")]
    MacAddress(&'a str),

    // Match OIDs loosely
    /// SNMP OID
    #[regex(r"[0-9]+(\.[0-9]+)+", priority = 5)]
    OidStr(&'a str),

    /// Numeric literal
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
