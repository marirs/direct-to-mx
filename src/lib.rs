//! # direct_to_mx
//!
//! Direct-to-MX email delivery with DKIM signing, IPv4 forcing, MX fallback,
//! DKIM key generation, and DNS verification.
//!
//! This crate provides a builder-based API for sending emails directly to
//! recipient MX servers without relying on an intermediate relay or third-party
//! API. It handles MX resolution, IPv4-only connections (to avoid IPv6 PTR
//! rejections), opportunistic TLS, DKIM signing with relaxed/relaxed
//! canonicalization, and automatic fallback across multiple MX hosts.
//!
//! # Example
//!
//! ```rust,no_run
//! use direct_to_mx::{DirectToMx, Body, DkimOptions};
//!
//! # async fn example() -> Result<(), direct_to_mx::DirectToMxError> {
//! let mailer = DirectToMx::builder()
//!     .from("no-reply@mail.example.com")
//!     .ehlo_hostname("mail.example.com")
//!     .dkim(DkimOptions {
//!         selector: "sel1".into(),
//!         domain: "mail.example.com".into(),
//!         private_key_pem: std::fs::read_to_string("/path/to/dkim.pem").unwrap(),
//!     })
//!     .build()?;
//!
//! mailer.send("user@gmail.com", "Hello", Body::text("Hi there")).await?;
//! # Ok(())
//! # }
//! ```

pub mod dkim;
pub mod dns;
pub mod error;
mod send;

pub use dkim::{generate_dkim_keypair, DkimKeyPair};
pub use dns::{
    verify_dns, DnsCheck, DnsCheckResult, DnsCheckStatus, DnsVerifyOptions, DnsVerifyReport,
};
pub use error::DirectToMxError;
pub use send::{
    Attachment, Body, BulkResult, DkimOptions, DirectToMx, DirectToMxBuilder, OutboundMessage,
    DEFAULT_CONCURRENCY,
};
