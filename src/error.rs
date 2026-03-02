use std::fmt;

/// Errors returned by the `direct_to_mx` crate.
#[derive(Debug)]
pub enum DirectToMxError {
    /// Builder misconfiguration (missing required field, empty value).
    Config(String),
    /// DNS resolution failure.
    Dns(String),
    /// SMTP delivery failure.
    Smtp(String),
    /// DKIM key generation or parsing error.
    Dkim(String),
    /// Message construction error.
    Message(String),
}

impl fmt::Display for DirectToMxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "config error: {msg}"),
            Self::Dns(msg) => write!(f, "DNS error: {msg}"),
            Self::Smtp(msg) => write!(f, "SMTP error: {msg}"),
            Self::Dkim(msg) => write!(f, "DKIM error: {msg}"),
            Self::Message(msg) => write!(f, "message error: {msg}"),
        }
    }
}

impl std::error::Error for DirectToMxError {}

impl From<lettre::error::Error> for DirectToMxError {
    fn from(e: lettre::error::Error) -> Self {
        Self::Message(e.to_string())
    }
}

impl From<lettre::address::AddressError> for DirectToMxError {
    fn from(e: lettre::address::AddressError) -> Self {
        Self::Message(format!("invalid address: {e}"))
    }
}
