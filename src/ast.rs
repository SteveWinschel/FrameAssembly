use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

// A simple, flat AST for the FrameAssembly DSL.
// We avoid spans and lossless syntax trees (LSTs) to keep it minimal.

/// A host definition with an IP and optional MAC address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDef {
    pub name: String,
    pub ip: IpAddr,
    pub mac: Option<[u8; 6]>,
}

/// The direction of the packet in a template statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    LeftToRight, // ->
    RightToLeft, // <-
}

/// TODO: Add the other flags
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpFlag {
    Syn,
    Ack,
}

/// TODO: add more protocols
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A single frame statement inside a flow, e.g., `src -> dst tcp srcport 12345 dstport 80 syn ack seq=1 len=64240 payload="test"`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameStatement {
    pub caller: String,
    pub dir: Direction,
    pub callee: String,
    pub protocol: Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub flags: Vec<TcpFlag>,
    pub seq: Option<u32>,
    pub win: Option<u16>,
    pub payload: Option<String>,
    pub wait: Option<u64>,
}

/// A flow definition in the form `FLOW name(arg1, arg2) { statements }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDef {
    pub name: String,
    pub params: Vec<String>,
    pub statements: Vec<FrameStatement>,
}

/// An argument passed to a flow invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argument {
    /// A simple variable reference, e.g., `my_client`
    Variable(String),
}

/// A flow invocation, e.g., `tcp_handshake(my_client, google_dns)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateInvocation {
    pub name: String,
    pub args: Vec<Argument>,
}

/// A statement in the run/compile block, can be a loop or a single invocation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatement {
    /// A single template invocation directly in the block
    Invocation(TemplateInvocation),
    /// A loop block containing an optional count (None = infinite) and inner invocations
    Loop(Option<u32>, Vec<TemplateInvocation>),
}

/// The root of the AST containing all assignments, flows, and the compile block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub hosts: Vec<HostDef>,
    pub flows: Vec<FlowDef>,
    pub compile_block: Vec<RunStatement>,
}
