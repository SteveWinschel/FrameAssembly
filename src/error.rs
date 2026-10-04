use alloc::string::String;
use miette::Diagnostic;

#[derive(Diagnostic, Debug)]
pub enum CompilerError {
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

    #[diagnostic(code(frameassembly::semantic_error))]
    SemanticError {
        message: String,
        #[source_code]
        src: String,
        #[label("Error occurred here")]
        span: (usize, usize),
    },

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
