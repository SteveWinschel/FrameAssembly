//! KERBEROS protocol AST definitions.

/// RFC 4120 Kerberos Network Authentication Service specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KerberosSpec<'a> {
    /// AS-REQ ticket request flag.
    pub is_as_req: bool,
    /// AS-REP ticket reply flag.
    pub is_as_rep: bool,
    /// TGS-REQ ticket granting request flag.
    pub is_tgs_req: bool,
    /// TGS-REP ticket granting reply flag.
    pub is_tgs_rep: bool,
    /// KRB-ERROR message flag.
    pub is_krb_error: bool,
    /// Realm name string.
    pub realm: Option<&'a str>,
    /// Client principal name.
    pub cname: Option<&'a str>,
    /// Server principal name.
    pub sname: Option<&'a str>,
    /// Encryption type.
    pub etype: Option<i32>,
}
