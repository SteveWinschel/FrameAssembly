use core::net::IpAddr;
use alloc::string::String;
use alloc::vec::Vec;

/// A simple, flat AST for the FrameAssembly DSL.
/// We avoid spans and lossless syntax trees (LSTs) to keep it minimal and zero-dependency.

/// An assigned value can be just an IP, or an IP with a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignValue {
    Ip(IpAddr),
    Endpoint(IpAddr, u16),
}

/// A global assignment in the form `let name = value`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalAssignment {
    pub name: String,
    pub value: AssignValue,
}

/// The direction of the packet in a macro statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    Src, // ->
    Dst, // <-
}

/// Supported TCP flags for this minimal scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpFlag {
    Syn,
    Ack,
}

/// A single frame statement inside a macro, e.g., `src -> dst tcp syn ack seq=1 len=64240 payload="test"`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameStatement {
    pub caller: String,
    pub dir: Direction,
    pub callee: String,
    pub flags: Vec<TcpFlag>,
    pub seq: Option<u32>,
    pub win: Option<u16>,
    pub payload: Option<String>,
    pub wait: Option<u64>,
}

/// A macro definition in the form `let macro name(arg1, arg2) { statements }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroDef {
    pub name: String,
    pub params: Vec<String>,
    pub statements: Vec<FrameStatement>,
}

/// An argument passed to a macro invocation in the `compile` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argument {
    /// A simple variable reference, e.g., `my_client`
    Variable(String),
    /// A variable reference with a port override, e.g., `google_dns:80`
    VarWithPort(String, u16),
}

/// A macro invocation inside the `compile` block, e.g., `tcp_handshake(my_client, google_dns:80)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroInvocation {
    pub name: String,
    pub args: Vec<Argument>,
}

/// The root of the AST containing all assignments, macros, and the compile block invocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub assignments: Vec<GlobalAssignment>,
    pub macros: Vec<MacroDef>,
    pub compile_block: Vec<MacroInvocation>,
}
