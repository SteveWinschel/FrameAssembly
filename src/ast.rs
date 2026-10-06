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
    pub name: &'a str,
    pub ip: IpAddr,
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
    LeftToRight, // ->
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
    Syn,
    Ack,
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
    Tcp,
    Udp,
    Snmp1,
    Snmp2,
    Snmp3,
}

/// A single frame statement inside a flow.
///
/// Syntax mapping:
/// ```frameassembly
/// client -> server TCP SYN ACK PAYLOAD "World" WAIT 10ms
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameStatement<'a> {
    pub caller: &'a str,
    pub dir: Direction,
    pub callee: &'a str,
    pub protocol: Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,

    // TCP specific
    pub flags: Vec<TcpFlag>,
    pub seq: Option<u32>,
    pub ack_num: Option<u32>,
    pub win: Option<u16>,
    pub payload: Option<&'a str>,

    // SNMP specific
    pub community: Option<&'a str>,
    pub user: Option<&'a str>,
    pub oid: Option<&'a str>,
    pub sys_up_time: Option<u32>,

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
    pub name: &'a str,
    pub params: Vec<&'a str>,
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
    pub name: &'a str,
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
    pub hosts: Vec<HostDef<'a>>,
    pub flows: Vec<FlowDef<'a>>,
    pub compile_block: Vec<RunStatement<'a>>,
}
