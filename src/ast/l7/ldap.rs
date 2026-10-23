//! LDAP protocol AST definitions.

/// RFC 4511 Lightweight Directory Access Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LdapSpec<'a> {
    /// BindRequest flag.
    pub is_bind_req: bool,
    /// BindResponse flag.
    pub is_bind_res: bool,
    /// SearchRequest flag.
    pub is_search_req: bool,
    /// SearchResultEntry flag.
    pub is_search_entry: bool,
    /// SearchResultDone flag.
    pub is_search_done: bool,
    /// UnbindRequest flag.
    pub is_unbind_req: bool,
    /// Message ID.
    pub msgid: Option<i32>,
    /// Base DN string.
    pub base_dn: Option<&'a str>,
    /// Search filter string.
    pub filter: Option<&'a str>,
    /// Result code.
    pub result_code: Option<u32>,
}
