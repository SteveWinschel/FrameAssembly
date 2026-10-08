use alloc::vec::Vec;
use core::net::IpAddr;

/// A host definition with an IP and optional MAC address.
///
/// Syntax mapping:
/// ```frameassembly
/// HOST name { IP 1.2.3.4 MAC 00:11:22:33:44:55 }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDef<'a> {
    /// The name of the host.
    pub name: &'a str,
    /// The IP address of the host.
    pub ip: IpAddr,
    /// The optional MAC address of the host.
    pub mac: Option<[u8; 6]>,
}

/// The direction of the packet in a template statement.
///
/// # Examples
/// ```
/// use frameassembly::ast::Direction;
/// let dir = Direction::LeftToRight;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    /// -> operator
    LeftToRight, // ->
    /// <- operator
    RightToLeft, // <-
}

/// Represents a TCP flag.
///
/// # Examples
/// ```
/// use frameassembly::ast::TcpFlag;
/// let flag = TcpFlag::Syn;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpFlag {
    /// SYN flag
    Syn,
    /// ACK flag
    Ack,
    /// FIN flag
    Fin,
    /// RST flag
    Rst,
    /// PSH flag
    Psh,
    /// URG flag
    Urg,
    /// ECE flag
    Ece,
    /// CWR flag
    Cwr,
}

/// Represents the supported network protocols.
///
/// # Examples
/// ```
/// use frameassembly::ast::Protocol;
/// let proto = Protocol::Tcp;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// Simple Network Management Protocol v1
    Snmp1,
    /// Simple Network Management Protocol v2c
    Snmp2,
    /// Simple Network Management Protocol v3
    Snmp3,
}

/// Represents the type of SNMP PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPduType {
    /// Trap PDU
    Trap,
    /// GetRequest PDU
    Get,
    /// SetRequest PDU
    Set,
    /// Response PDU
    Response,
    /// InformRequest PDU
    Inform,
    /// GetNextRequest PDU
    GetNext,
    /// GetBulkRequest PDU
    GetBulk,
}

/// Represents the SNMP Auth type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpAuthType {
    /// HMAC-MD5-96
    Md5,
    /// HMAC-SHA-96
    Sha,
    /// HMAC-SHA-256
    Sha256,
    /// HMAC-SHA-384
    Sha384,
    /// HMAC-SHA-512
    Sha512,
}

/// Represents the SNMP Priv type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPrivType {
    /// DES privacy
    Des,
    /// AES privacy
    Aes,
}

/// Represents the value of a VarBind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarBindType<'a> {
    /// Null value
    Null,
    /// OctetString value
    String(&'a str),
    /// Integer value
    Int(u32),
    /// TimeTicks value
    TimeTicks(u32),
    /// IpAddress value
    Ip(IpAddr),
}

/// Represents a single VarBind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBindAst<'a> {
    /// The Object Identifier
    pub oid: &'a str,
    /// The value associated with the OID
    pub val: VarBindType<'a>,
}

/// A single frame statement inside a flow.
///
/// Syntax mapping:
/// ```frameassembly
/// client -> server TCP SYN ACK PAYLOAD "World" WAIT 10ms
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameStatement<'a> {
    /// The caller (source).
    pub caller: &'a str,
    /// The direction of the packet.
    pub dir: Direction,
    /// The callee (destination).
    pub callee: &'a str,
    /// The protocol used.
    pub protocol: Protocol,
    /// Optional source port.
    pub src_port: Option<u16>,
    /// Optional destination port.
    pub dst_port: Option<u16>,

    // TCP specific
    /// TCP flags.
    pub flags: Vec<TcpFlag>,
    /// Optional TCP sequence number.
    pub seq: Option<u32>,
    /// Optional TCP acknowledgment number.
    pub ack_num: Option<u32>,
    /// Optional TCP window size.
    pub win: Option<u16>,
    /// Optional payload data.
    pub payload: Option<&'a str>,

    // SNMP specific
    /// Optional SNMP community string.
    pub community: Option<&'a str>,
    /// Optional SNMP user.
    pub user: Option<&'a str>,
    /// Optional SNMP OID.
    pub oid: Option<&'a str>,
    /// Optional SNMP system uptime.
    pub sys_up_time: Option<u32>,
    /// PDU Type.
    pub pdu_type: Option<SnmpPduType>,
    /// Optional enterprise OID for v1 traps.
    pub enterprise: Option<&'a str>,
    /// Optional agent IP for v1 traps.
    pub agent_ip: Option<IpAddr>,
    /// Optional generic trap for v1 traps.
    pub gen_trap: Option<u32>,
    /// Optional specific trap for v1 traps.
    pub spec_trap: Option<u32>,
    /// Optional engine ID for v3.
    pub engine_id: Option<&'a str>,
    /// Optional engine boots for v3.
    pub engine_boots: Option<u32>,
    /// Optional engine time for v3.
    pub engine_time: Option<u32>,
    /// Optional context name for v3.
    pub context_name: Option<&'a str>,
    /// Optional auth params for v3.
    pub auth: Option<(SnmpAuthType, &'a str)>,
    /// Optional priv params for v3.
    pub priv_param: Option<(SnmpPrivType, &'a str)>,
    /// List of variable bindings.
    pub varbinds: Vec<VarBindAst<'a>>,
    /// Optional Non-Repeaters for GETBULK.
    pub non_repeaters: Option<u32>,
    /// Optional Max-Repetitions for GETBULK.
    pub max_repetitions: Option<u32>,
    /// Optional Request ID.
    pub req_id: Option<u32>,

    /// Optional wait time before sending the packet (in nanoseconds).
    pub wait: Option<u64>,
}

/// A flow definition in the form `FLOW name(arg1, arg2) { statements }`
///
/// Syntax mapping:
/// ```frameassembly
/// FLOW name(arg1, arg2) { 
///     arg1 -> arg2 TCP SYN
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDef<'a> {
    /// The name of the flow.
    pub name: &'a str,
    /// The parameters of the flow.
    pub params: Vec<&'a str>,
    /// The statements inside the flow.
    pub statements: Vec<FrameStatement<'a>>,
}

/// An argument passed to a flow invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argument<'a> {
    /// A simple variable reference, e.g., `my_client`
    Variable(&'a str),
}

/// A flow invocation, e.g., `tcp_handshake(my_client, google_dns)`
///
/// # Examples
/// ```
/// use frameassembly::ast::{TemplateInvocation, Argument};
/// let inv = TemplateInvocation { name: "handshake", args: vec![] };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateInvocation<'a> {
    /// The name of the flow being invoked.
    pub name: &'a str,
    /// The arguments passed to the flow.
    pub args: Vec<Argument<'a>>,
}

/// A statement in the run/compile block, can be a loop or a single invocation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatement<'a> {
    /// A single template invocation directly in the block
    Invocation(TemplateInvocation<'a>),
    /// A loop block containing a count and inner invocations
    Loop(u32, Vec<TemplateInvocation<'a>>),
}

/// The root of the AST containing all assignments, flows, and the compile block.
///
/// # Examples
/// ```
/// use frameassembly::ast::Program;
/// let prog = Program { hosts: vec![], flows: vec![], compile_block: vec![] };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program<'a> {
    /// The list of host definitions.
    pub hosts: Vec<HostDef<'a>>,
    /// The list of flow definitions.
    pub flows: Vec<FlowDef<'a>>,
    /// The list of statements in the compile block.
    pub compile_block: Vec<RunStatement<'a>>,
}
