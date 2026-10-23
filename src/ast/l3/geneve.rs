//! Generic Network Virtualization Encapsulation (GENEVE) AST definitions.

use core::marker::PhantomData;

/// Generic Network Virtualization Encapsulation (RFC 8926) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeneveSpec<'a> {
    /// 24-bit Virtual Network Identifier.
    pub vni: Option<u32>,
    /// Option class.
    pub opt_class: Option<u16>,
    /// Option type.
    pub opt_type: Option<u8>,
    /// Protocol type.
    pub protocol_type: Option<u16>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
