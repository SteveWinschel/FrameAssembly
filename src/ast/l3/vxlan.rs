//! Virtual eXtensible Local Area Network (VXLAN) AST definitions.

use core::marker::PhantomData;

/// Virtual eXtensible Local Area Network (RFC 7348) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VxlanSpec<'a> {
    /// 24-bit VXLAN Network Identifier.
    pub vni: Option<u32>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
