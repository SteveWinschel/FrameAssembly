use alloc::string::String;
use miette::Diagnostic;

/// Represents all possible errors that can occur during the compilation process.
///
/// This enum uses `miette` for rich terminal diagnostics.
#[derive(Diagnostic, Debug)]
pub enum CompilerError {
    /// Occurs when the lexer encounters an invalid sequence of characters that cannot be tokenized.
    #[diagnostic(
        code(frameassembly::lex_error),
        help("Check the token for typos or invalid characters.")
    )]
    LexError {
        #[source_code]
        src: String,
        #[label("Invalid token")]
        span: (usize, usize),
    },

    /// Occurs when the parser encounters a syntax error or unexpected token.
    #[diagnostic(
        code(frameassembly::parse_error),
        help("Ensure the syntax matches the expected grammar.")
    )]
    ParseError {
        message: String,
        #[source_code]
        src: String,
        #[label("Here")]
        span: (usize, usize),
    },

    /// Occurs when the AST is syntactically valid but semantically invalid (e.g. undefined variable).
    #[diagnostic(code(frameassembly::semantic_error))]
    SemanticError {
        message: String,
        #[source_code]
        src: String,
        #[label("Error occurred here")]
        span: (usize, usize),
    },

    /// Occurs during the backend PCAP generation (e.g. invalid IP address formatting, missing file access).
    #[diagnostic(code(frameassembly::backend_error))]
    BackendError(String),
}

impl core::fmt::Display for CompilerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LexError { .. } => write!(f, "Failed to parse token"),
            Self::ParseError { message, .. } => write!(f, "Failed to parse input: {}", message),
            Self::SemanticError { message, .. } => write!(f, "Semantic error: {}", message),
            Self::BackendError(msg) => write!(f, "Backend generation error: {}", msg),
        }
    }
}

impl std::error::Error for CompilerError {}
