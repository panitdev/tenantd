use std::fmt::Display;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors map one-to-one onto gRPC status codes at the API edge.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// A policy rule refused the request. `rule` names the config key or
    /// limit that refused, so the control plane can show a useful message.
    #[error("denied by {rule}: {message}")]
    PermissionDenied { rule: String, message: String },
    #[error("failed precondition: {0}")]
    FailedPrecondition(String),
    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    pub fn denied(rule: impl Into<String>, message: impl Into<String>) -> Self {
        Error::PermissionDenied {
            rule: rule.into(),
            message: message.into(),
        }
    }

    pub fn internal(context: impl Display, err: impl Display) -> Self {
        Error::Internal(format!("{context}: {err}"))
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::InvalidArgument(msg.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Internal(e.to_string())
    }
}

/// Attach context to backend errors without losing their kind.
pub trait Context<T> {
    fn context(self, ctx: impl Display) -> Result<T>;
}

impl<T, E: Display> Context<T> for std::result::Result<T, E> {
    fn context(self, ctx: impl Display) -> Result<T> {
        self.map_err(|e| Error::internal(ctx, e))
    }
}
