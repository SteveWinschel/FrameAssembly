//! GRPC protocol AST definitions.

/// gRPC remote procedure call framing specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrpcSpec<'a> {
    /// Service name string.
    pub service: Option<&'a str>,
    /// Method name string.
    pub method: Option<&'a str>,
    /// Status code.
    pub grpc_status: Option<u32>,
}
