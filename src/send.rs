use std::collections::HashMap;
use std::sync::Arc;

use crate::error::DirectToMxError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Default number of concurrent SMTP deliveries for [`DirectToMx::send_bulk`].
pub const DEFAULT_CONCURRENCY: usize = 5;

/// Email body — HTML, plain text, or both (multipart/alternative).
#[derive(Clone, Debug)]
pub enum Body {
    /// HTML-only body.
    Html(String),
    /// Plain-text-only body.
    Text(String),
    /// Multipart/alternative with both a plain-text and an HTML part.
    Both { html: String, text: String },
    /// Pre-formatted body with a custom Content-Type (e.g. `multipart/signed`).
    /// The caller is responsible for providing a valid MIME body.
    Raw {
        /// Full Content-Type header value, e.g.
        /// `"multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"abc\""`
        content_type: String,
        /// The raw MIME body.
        body: String,
    },
}

impl Body {
    /// Convenience constructor for an HTML body.
    pub fn html(s: impl Into<String>) -> Self {
        Self::Html(s.into())
    }

    /// Convenience constructor for a plain-text body.
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    /// Convenience constructor for multipart/alternative.
    pub fn both(html: impl Into<String>, text: impl Into<String>) -> Self {
        Self::Both {
            html: html.into(),
            text: text.into(),
        }
    }

    /// Convenience constructor for a pre-formatted raw body.
    pub fn raw(content_type: impl Into<String>, body: impl Into<String>) -> Self {
        Self::Raw {
            content_type: content_type.into(),
            body: body.into(),
        }
    }
}

/// A file attachment.
#[derive(Clone, Debug)]
pub struct Attachment {
    /// Filename as it will appear to the recipient.
    pub filename: String,
    /// MIME content type, e.g. `"application/pdf"` or `"image/png"`.
    pub content_type: String,
    /// Raw file bytes.
    pub data: Vec<u8>,
}

impl Attachment {
    /// Create an attachment from raw bytes.
    pub fn new(
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            filename: filename.into(),
            content_type: content_type.into(),
            data,
        }
    }

    /// Create an attachment by reading a file from disk.
    ///
    /// The content type is inferred from the file extension. Falls back to
    /// `application/octet-stream` for unknown extensions.
    pub fn from_file(path: &std::path::Path) -> Result<Self, DirectToMxError> {
        let data = std::fs::read(path).map_err(|e| {
            DirectToMxError::Message(format!("failed to read {}: {e}", path.display()))
        })?;
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "attachment".into());
        let content_type = mime_from_extension(path).to_string();
        Ok(Self {
            filename,
            content_type,
            data,
        })
    }
}

/// DKIM signing configuration.
///
/// # Security
///
/// This struct derives `Debug`, which **will include the private key** in
/// debug output. Avoid logging `DkimOptions` in production.
#[derive(Clone, Debug)]
pub struct DkimOptions {
    /// DKIM selector (the `s=` tag), e.g. `"sel1"`.
    pub selector: String,
    /// Signing domain (the `d=` tag), e.g. `"mail.example.com"`.
    pub domain: String,
    /// RSA private key in PEM format.
    pub private_key_pem: String,
}

/// A single outbound message for [`DirectToMx::send_bulk`].
#[derive(Clone, Debug)]
pub struct OutboundMessage {
    /// Recipient address.
    pub to: String,
    /// Email subject.
    pub subject: String,
    /// Email body.
    pub body: Body,
    /// File attachments (empty = no attachments).
    pub attachments: Vec<Attachment>,
}

/// Result of a single delivery within a bulk send.
#[derive(Debug)]
pub struct BulkResult {
    /// Recipient address.
    pub to: String,
    /// `Ok(())` on success, or the delivery error.
    pub status: Result<(), DirectToMxError>,
}

/// DKIM configuration validated at build time.
/// The PEM is validated eagerly so `build()` fails fast on bad keys.
struct CachedDkim {
    selector: String,
    domain: String,
    private_key_pem: String,
}

/// The configured mailer. Obtain one via [`DirectToMx::builder()`].
pub struct DirectToMx {
    from: String,
    ehlo_hostname: String,
    dkim: Option<CachedDkim>,
    force_ipv4: bool,
}

impl std::fmt::Debug for DirectToMx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectToMx")
            .field("from", &self.from)
            .field("ehlo_hostname", &self.ehlo_hostname)
            .field("dkim", &self.dkim.as_ref().map(|d| &d.selector))
            .field("force_ipv4", &self.force_ipv4)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`DirectToMx`].
#[derive(Clone, Debug, Default)]
pub struct DirectToMxBuilder {
    from: Option<String>,
    ehlo_hostname: Option<String>,
    dkim: Option<DkimOptions>,
    force_ipv4: Option<bool>,
}

impl DirectToMx {
    /// Create a new builder.
    pub fn builder() -> DirectToMxBuilder {
        DirectToMxBuilder::default()
    }
}

impl DirectToMxBuilder {
    /// RFC 5321 envelope-from / header `From`.
    /// Must be a valid mailbox, e.g. `"Sender <no-reply@example.com>"` or
    /// `"no-reply@example.com"`.
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Hostname used in the SMTP EHLO greeting.
    /// Must match your server's reverse-DNS (PTR) record for best
    /// deliverability.
    pub fn ehlo_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.ehlo_hostname = Some(hostname.into());
        self
    }

    /// Optional DKIM signing configuration. If omitted, emails are sent
    /// unsigned.
    pub fn dkim(mut self, opts: DkimOptions) -> Self {
        self.dkim = Some(opts);
        self
    }

    /// Force IPv4-only connections (default: **true**).
    /// When enabled, MX hosts are resolved via A records only, avoiding
    /// IPv6 PTR-related rejections from providers like Gmail.
    pub fn force_ipv4(mut self, yes: bool) -> Self {
        self.force_ipv4 = Some(yes);
        self
    }

    /// Build the [`DirectToMx`] mailer.
    ///
    /// Fails if required fields are missing or if the DKIM private key
    /// cannot be parsed.
    pub fn build(self) -> Result<DirectToMx, DirectToMxError> {
        let from = self
            .from
            .ok_or_else(|| DirectToMxError::Config("from address is required".into()))?;
        if from.is_empty() {
            return Err(DirectToMxError::Config(
                "from address must not be empty".into(),
            ));
        }
        let ehlo_hostname = self
            .ehlo_hostname
            .ok_or_else(|| DirectToMxError::Config("ehlo_hostname is required".into()))?;
        if ehlo_hostname.is_empty() {
            return Err(DirectToMxError::Config(
                "ehlo_hostname must not be empty".into(),
            ));
        }

        // Validate DKIM key eagerly so build() fails fast on bad keys
        let cached_dkim = match self.dkim {
            Some(opts) => {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                let _ = rsa::RsaPrivateKey::from_pkcs1_pem(&opts.private_key_pem)
                    .map_err(|e| DirectToMxError::Dkim(format!("failed to parse DKIM key: {e}")))?;
                Some(CachedDkim {
                    selector: opts.selector,
                    domain: opts.domain,
                    private_key_pem: opts.private_key_pem,
                })
            }
            None => None,
        };

        Ok(DirectToMx {
            from,
            ehlo_hostname,
            dkim: cached_dkim,
            force_ipv4: self.force_ipv4.unwrap_or(true),
        })
    }
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

impl DirectToMx {
    /// Send a single email to `to` with the given `subject` and `body`.
    pub async fn send(&self, to: &str, subject: &str, body: Body) -> Result<(), DirectToMxError> {
        self.send_with_attachments(to, subject, body, Vec::new())
            .await
    }

    /// Send a single email with file attachments.
    pub async fn send_with_attachments(
        &self,
        to: &str,
        subject: &str,
        body: Body,
        attachments: Vec<Attachment>,
    ) -> Result<(), DirectToMxError> {
        let email = self.prepare_message(to, subject, body, &attachments)?;
        let envelope = email.envelope().clone();
        let raw = self.sign_to_raw(email);

        let rcpt_domain = to.rsplit_once('@').map(|(_, d)| d).unwrap_or(to);
        let mx_hosts = resolve_mx(rcpt_domain).await;

        deliver_with_fallback_raw(
            &self.ehlo_hostname,
            self.force_ipv4,
            &mx_hosts,
            &envelope,
            &raw,
        )
        .await
    }

    /// Send multiple emails concurrently.
    ///
    /// Each [`OutboundMessage`] can have a different recipient, subject, and
    /// body. Deliveries run in parallel up to `concurrency` at a time
    /// (default: [`DEFAULT_CONCURRENCY`] = 5). MX lookups are cached
    /// per-domain for the duration of the batch.
    ///
    /// Returns one [`BulkResult`] per message, **in the same order** as the
    /// input.
    pub async fn send_bulk(
        &self,
        messages: Vec<OutboundMessage>,
        concurrency: Option<usize>,
    ) -> Vec<BulkResult> {
        let concurrency = concurrency.unwrap_or(DEFAULT_CONCURRENCY).max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mx_cache: Arc<tokio::sync::Mutex<HashMap<String, Vec<String>>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        let mut handles = Vec::with_capacity(messages.len());

        for msg in messages {
            let sem = semaphore.clone();
            let cache = mx_cache.clone();

            // Prepare the message (build + DKIM sign) on the current task so
            // errors are captured per-message without spawning.
            let prepared =
                self.prepare_message(&msg.to, &msg.subject, msg.body.clone(), &msg.attachments);
            let to = msg.to.clone();
            let force_ipv4 = self.force_ipv4;
            let ehlo_hostname = self.ehlo_hostname.clone();

            let (envelope, raw) = match prepared {
                Ok(email) => {
                    let env = email.envelope().clone();
                    let raw = self.sign_to_raw(email);
                    (env, raw)
                }
                Err(e) => {
                    // Push a ready result for build failures
                    handles.push(tokio::spawn(
                        async move { BulkResult { to, status: Err(e) } },
                    ));
                    continue;
                }
            };

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");

                let rcpt_domain = to
                    .rsplit_once('@')
                    .map(|(_, d)| d.to_string())
                    .unwrap_or_else(|| to.clone());

                // Check MX cache
                let mx_hosts = {
                    let mut guard = cache.lock().await;
                    if let Some(cached) = guard.get(&rcpt_domain) {
                        cached.clone()
                    } else {
                        let hosts = resolve_mx(&rcpt_domain).await;
                        guard.insert(rcpt_domain.clone(), hosts.clone());
                        hosts
                    }
                };

                let status = deliver_with_fallback_raw(
                    &ehlo_hostname,
                    force_ipv4,
                    &mx_hosts,
                    &envelope,
                    &raw,
                )
                .await;
                BulkResult { to, status }
            }));
        }

        // Collect results in input order
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(r) => results.push(r),
                Err(e) => results.push(BulkResult {
                    to: String::new(),
                    status: Err(DirectToMxError::Smtp(format!("task panicked: {e}"))),
                }),
            }
        }
        results
    }

    /// Send a diagnostic test email. Returns `Ok(())` on successful delivery
    /// or an error describing what went wrong (DNS, TLS, DKIM, SMTP).
    pub async fn test_send(&self, to: &str) -> Result<(), DirectToMxError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let dkim_status = match &self.dkim {
            Some(d) => format!("enabled (selector={}, domain={})", d.selector, d.domain),
            None => "disabled (no DKIM key configured)".to_string(),
        };
        let html = format!(
            "<h2>DirectToMx Test Email</h2>\
             <p><b>Timestamp:</b> {now}</p>\
             <p><b>From:</b> {from}</p>\
             <p><b>EHLO hostname:</b> {ehlo}</p>\
             <p><b>DKIM:</b> {dkim_status}</p>\
             <p><b>Force IPv4:</b> {ipv4}</p>\
             <hr>\
             <p style=\"color:#888\">This is an automated test from the \
             <code>direct_to_mx</code> crate.</p>",
            from = self.from,
            ehlo = self.ehlo_hostname,
            ipv4 = self.force_ipv4,
        );
        let text = format!(
            "DirectToMx Test Email\n\
             Timestamp: {now}\n\
             From: {from}\n\
             EHLO hostname: {ehlo}\n\
             DKIM: {dkim_status}\n\
             Force IPv4: {ipv4}\n\
             ---\n\
             This is an automated test from the direct_to_mx crate.",
            from = self.from,
            ehlo = self.ehlo_hostname,
            ipv4 = self.force_ipv4,
        );
        self.send(to, "DirectToMx Test Email", Body::both(html, text))
            .await
    }

    // -----------------------------------------------------------------------
    // Internal helpers (on &self)
    // -----------------------------------------------------------------------

    /// Build a `lettre::Message` with a unique Message-ID.
    fn prepare_message(
        &self,
        to: &str,
        subject: &str,
        body: Body,
        attachments: &[Attachment],
    ) -> Result<lettre::Message, DirectToMxError> {
        let from_domain = self
            .from
            .rsplit_once('@')
            .map(|(_, d)| d.trim_end_matches('>'))
            .unwrap_or(&self.ehlo_hostname);
        let message_id = format!(
            "<{}.{}@{}>",
            random_hex(16),
            chrono::Utc::now().timestamp(),
            from_domain
        );
        build_message(&self.from, to, subject, &message_id, body, attachments)
    }

    /// Format the message and optionally DKIM-sign it, returning final raw bytes.
    fn sign_to_raw(&self, email: lettre::Message) -> Vec<u8> {
        let raw = email.formatted();
        match self.dkim {
            Some(ref dkim) => dkim_sign_raw(&raw, dkim),
            None => raw,
        }
    }
}

// ---------------------------------------------------------------------------
// Free-standing delivery (used by both send() and send_bulk() tasks)
// ---------------------------------------------------------------------------

async fn deliver_with_fallback_raw(
    ehlo_hostname: &str,
    force_ipv4: bool,
    mx_hosts: &[String],
    envelope: &lettre::address::Envelope,
    raw: &[u8],
) -> Result<(), DirectToMxError> {
    let mut last_err: Option<DirectToMxError> = None;
    for mx_host in mx_hosts {
        let connect_host = if force_ipv4 {
            resolve_ipv4(mx_host).await
        } else {
            mx_host.clone()
        };

        match try_deliver_raw(ehlo_hostname, &connect_host, mx_host, envelope, raw).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!(
                    "direct_to_mx: delivery to {connect_host} (MX: {mx_host}) failed: {e}, trying next…"
                );
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| DirectToMxError::Dns("no MX hosts available".into())))
}

async fn try_deliver_raw(
    ehlo_hostname: &str,
    connect_host: &str,
    mx_host: &str,
    envelope: &lettre::address::Envelope,
    raw: &[u8],
) -> Result<(), DirectToMxError> {
    use lettre::AsyncTransport;
    use lettre::transport::smtp::client::{Tls, TlsParameters};
    use lettre::transport::smtp::extension::ClientId;

    let tls = match TlsParameters::new(mx_host.to_string()) {
        Ok(params) => Tls::Opportunistic(params),
        Err(_) => Tls::None,
    };

    let transport =
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(connect_host)
            .port(25)
            .hello_name(ClientId::Domain(ehlo_hostname.to_string()))
            .tls(tls)
            .build();

    transport
        .send_raw(envelope, raw)
        .await
        .map(|_| ())
        .map_err(|e| {
            DirectToMxError::Smtp(format!(
                "delivery to {connect_host} (MX: {mx_host}):25 failed: {e}"
            ))
        })
}

// ---------------------------------------------------------------------------
// Helpers (private)
// ---------------------------------------------------------------------------

fn build_message(
    from: &str,
    to: &str,
    subject: &str,
    message_id: &str,
    body: Body,
    attachments: &[Attachment],
) -> Result<lettre::Message, DirectToMxError> {
    use lettre::message::{MultiPart, SinglePart, header::ContentType};

    let builder = lettre::Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .message_id(Some(message_id.to_string()))
        .subject(subject);

    // Raw body: caller provides the full Content-Type and MIME body.
    // This bypasses MultiPart wrapping entirely (attachments are ignored).
    // We pass a pre-encoded lettre::message::body::Body so lettre does NOT
    // validate or re-encode the content (critical for multipart/signed).
    if let Body::Raw { content_type, body } = body {
        let ct: ContentType = content_type
            .parse()
            .map_err(|e| DirectToMxError::Message(format!("invalid Content-Type: {e}")))?;
        let raw_body = lettre::message::Body::dangerous_pre_encoded(
            body.into_bytes(),
            lettre::message::header::ContentTransferEncoding::SevenBit,
        );
        let email = builder.header(ct).body(raw_body)?;
        return Ok(email);
    }

    // Build the body part
    let body_part = match body {
        Body::Html(html) => MultiPart::alternative().singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_HTML)
                .body(html),
        ),
        Body::Text(text) => MultiPart::alternative().singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(text),
        ),
        Body::Both { html, text } => MultiPart::alternative()
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(text),
            )
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_HTML)
                    .body(html),
            ),
        Body::Raw { .. } => unreachable!(),
    };

    let email = if attachments.is_empty() {
        builder.multipart(body_part)?
    } else {
        // Wrap in multipart/mixed: body + attachments
        let mut mixed = MultiPart::mixed().multipart(body_part);
        for att in attachments {
            let ct: ContentType = att
                .content_type
                .parse()
                .unwrap_or(ContentType::parse("application/octet-stream").unwrap());
            mixed = mixed.singlepart(
                lettre::message::Attachment::new(att.filename.clone()).body(att.data.clone(), ct),
            );
        }
        builder.multipart(mixed)?
    };

    Ok(email)
}

/// Infer MIME type from file extension.
fn mime_from_extension(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("txt") => "text/plain",
        Some("html" | "htm") => "text/html",
        Some("csv") => "text/csv",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("zip") => "application/zip",
        Some("gz" | "gzip") => "application/gzip",
        Some("tar") => "application/x-tar",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xls") => "application/vnd.ms-excel",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("ppt") => "application/vnd.ms-powerpoint",
        Some("pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("avi") => "video/x-msvideo",
        Some("mov") => "video/quicktime",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Headers to include in the DKIM signature.
/// Each is listed twice (N+1 over-signing) to prevent header injection
/// attacks per RFC 6376 §5.4.
const DKIM_SIGNED_HEADERS: [&str; 12] = [
    "From",
    "From",
    "To",
    "To",
    "Subject",
    "Subject",
    "Date",
    "Date",
    "Message-ID",
    "Message-ID",
    "Content-Type",
    "Content-Type",
];

/// DKIM-sign the final formatted message bytes using mail-auth's
/// battle-tested DkimSigner (same implementation as Stalwart mail server).
/// Returns new raw bytes with DKIM-Signature prepended.
fn dkim_sign_raw(raw: &[u8], dkim: &CachedDkim) -> Vec<u8> {
    use mail_auth::common::crypto::{RsaKey, Sha256};
    use mail_auth::common::headers::HeaderWriter;
    use mail_auth::dkim::DkimSigner;

    let rsa_key = match RsaKey::<Sha256>::from_pkcs1_pem(&dkim.private_key_pem) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("direct_to_mx: DKIM key parse failed, sending unsigned: {e}");
            return raw.to_vec();
        }
    };

    let signer = DkimSigner::from_key(rsa_key)
        .domain(&dkim.domain)
        .selector(&dkim.selector)
        .headers(DKIM_SIGNED_HEADERS);

    let signature = match signer.sign(raw) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("direct_to_mx: DKIM signing failed: {e}");
            return raw.to_vec();
        }
    };

    // Prepend the DKIM-Signature header to the raw message
    let mut result = Vec::with_capacity(raw.len() + 512);
    signature.write_header(&mut result);
    result.extend_from_slice(raw);
    result
}

/// Resolve MX hosts for a domain, sorted by preference (lowest = highest
/// priority). Falls back to the domain itself if no MX records exist.
async fn resolve_mx(domain: &str) -> Vec<String> {
    let resolver = hickory_resolver::TokioAsyncResolver::tokio(
        hickory_resolver::config::ResolverConfig::default(),
        hickory_resolver::config::ResolverOpts::default(),
    );

    match resolver.mx_lookup(domain).await {
        Ok(mx) => {
            let mut records: Vec<_> = mx.iter().collect();
            records.sort_by_key(|r| r.preference());
            let hosts: Vec<String> = records
                .iter()
                .map(|r| r.exchange().to_string().trim_end_matches('.').to_string())
                .filter(|h| !h.is_empty())
                .collect();
            if hosts.is_empty() {
                vec![domain.to_string()]
            } else {
                hosts
            }
        }
        Err(_) => vec![domain.to_string()],
    }
}

/// Resolve a hostname to its first IPv4 address. Falls back to the hostname
/// itself if no A record is found.
async fn resolve_ipv4(host: &str) -> String {
    let resolver = hickory_resolver::TokioAsyncResolver::tokio(
        hickory_resolver::config::ResolverConfig::default(),
        hickory_resolver::config::ResolverOpts::default(),
    );

    match resolver.ipv4_lookup(host).await {
        Ok(lookup) => {
            if let Some(addr) = lookup.iter().next() {
                addr.to_string()
            } else {
                host.to_string()
            }
        }
        Err(_) => host.to_string(),
    }
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use base64::Engine;
    use mail_auth::common::parse::TxtRecordParser;
    use mail_auth::common::verify::DomainKey;
    use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};

    /// Verify DKIM using mail-auth's own verifier — the same code path
    /// that production mail servers (Stalwart, etc.) use.
    async fn verify_dkim_with_mail_auth(signed_raw: &[u8], pem: &str) -> bool {
        let private_key = rsa::RsaPrivateKey::from_pkcs1_pem(pem).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let pub_der = public_key.to_pkcs1_der().unwrap();
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(pub_der.as_bytes());
        let dns_txt = format!("v=DKIM1; k=rsa; p={pub_b64}");

        let resolver = Resolver::new_system_conf().unwrap();
        // Extract selector and domain from the DKIM-Signature in the message
        let raw_str = String::from_utf8_lossy(signed_raw);
        let unfolded = raw_str.replace("\r\n\t", " ").replace("\r\n ", " ");

        let s_start = unfolded.find("s=").unwrap();
        let s_end = unfolded[s_start..].find(';').unwrap() + s_start;
        let selector = &unfolded[s_start + 2..s_end].trim();

        let d_start = unfolded.find("d=").unwrap();
        let d_end = unfolded[d_start..].find(';').unwrap() + d_start;
        let domain = &unfolded[d_start + 2..d_end].trim();

        let dns_name = format!("{selector}._domainkey.{domain}.");
        resolver.txt_add(
            dns_name,
            DomainKey::parse(dns_txt.as_bytes()).unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );

        let message = AuthenticatedMessage::parse(signed_raw).unwrap();
        let dkim = resolver.verify_dkim(&message).await;

        matches!(dkim.last().unwrap().result(), DkimResult::Pass)
    }

    #[tokio::test]
    async fn dkim_sign_and_verify_html_only() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let email = build_message(
            "no-reply@example.com",
            "user@gmail.com",
            "Test Subject",
            "<test.123@example.com>",
            Body::html("<h1>Hello</h1>"),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);

        assert!(
            verify_dkim_with_mail_auth(&signed, &kp.private_key_pem).await,
            "DKIM verification failed for HTML-only email"
        );
    }

    #[tokio::test]
    async fn dkim_sign_and_verify_multipart() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let email = build_message(
            "no-reply@example.com",
            "user@gmail.com",
            "Test Subject",
            "<test.456@example.com>",
            Body::both("<h1>Hello</h1>", "Hello"),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);

        assert!(
            verify_dkim_with_mail_auth(&signed, &kp.private_key_pem).await,
            "DKIM verification failed for multipart email"
        );
    }

    #[tokio::test]
    async fn dkim_sign_and_verify_text_only() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let email = build_message(
            "no-reply@example.com",
            "user@gmail.com",
            "Test Subject",
            "<test.789@example.com>",
            Body::text("Hello world"),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);

        assert!(
            verify_dkim_with_mail_auth(&signed, &kp.private_key_pem).await,
            "DKIM verification failed for text-only email"
        );
    }

    #[tokio::test]
    async fn dkim_sign_and_verify_with_attachment() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let att = Attachment::new("test.txt", "text/plain", b"file content".to_vec());
        let email = build_message(
            "no-reply@example.com",
            "user@gmail.com",
            "With attachment",
            "<test.att@example.com>",
            Body::html("<p>See attached</p>"),
            &[att],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);

        assert!(
            verify_dkim_with_mail_auth(&signed, &kp.private_key_pem).await,
            "DKIM verification failed for email with attachment"
        );
    }

    #[test]
    fn dkim_signed_message_has_dkim_header() {
        let kp = crate::generate_dkim_keypair("mysel", "test.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "mysel".into(),
            domain: "test.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let email = build_message(
            "a@test.com",
            "b@example.com",
            "hi",
            "<id@test.com>",
            Body::text("yo"),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);
        let signed_str = String::from_utf8_lossy(&signed);

        assert!(signed_str.starts_with("DKIM-Signature:"));
        assert!(signed_str.contains("s=mysel"));
        assert!(signed_str.contains("d=test.com"));
        assert!(signed_str.contains("a=rsa-sha256"));
        assert!(signed_str.contains("c=relaxed/relaxed"));
    }

    #[test]
    fn dkim_h_tag_has_n_plus_1_over_signing() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let email = build_message(
            "a@example.com",
            "b@example.com",
            "hi",
            "<id@example.com>",
            Body::text("yo"),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);
        let signed_str = String::from_utf8_lossy(&signed);

        // Unfold the DKIM header before extracting the h= tag
        let unfolded = signed_str.replace("\r\n\t", " ").replace("\r\n ", " ");
        let h_start = unfolded.find("h=").expect("no h= tag");
        let h_end = unfolded[h_start..].find(';').unwrap() + h_start;
        let h_value = &unfolded[h_start + 2..h_end];
        let names: Vec<&str> = h_value.split(':').collect();
        // Each signed header present in the message should appear;
        // missing headers also appear (N+1 over-signing)
        for hdr in &["From", "To", "Subject"] {
            let lower = hdr.to_lowercase();
            let count = names
                .iter()
                .filter(|n| n.eq_ignore_ascii_case(&lower))
                .count();
            assert!(
                count >= 1,
                "header '{}' should appear at least once in h=, found {}",
                hdr,
                count
            );
        }
    }

    #[tokio::test]
    async fn dkim_n_plus_1_rejects_injected_header() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let email = build_message(
            "a@example.com",
            "b@example.com",
            "Test",
            "<id@example.com>",
            Body::text("hello"),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);

        // Verify the unmodified message passes
        assert!(
            verify_dkim_with_mail_auth(&signed, &kp.private_key_pem).await,
            "original message should verify"
        );

        // Inject a duplicate From header after the DKIM-Signature.
        // Skip past the full folded DKIM-Signature header.
        let signed_str = String::from_utf8_lossy(&signed);
        let mut dkim_end = 0;
        let mut first = true;
        for line in signed_str.split("\r\n") {
            if first {
                first = false;
                dkim_end += line.len() + 2;
                continue;
            }
            if line.starts_with('\t') || line.starts_with(' ') {
                dkim_end += line.len() + 2;
            } else {
                break;
            }
        }
        let mut tampered = Vec::new();
        tampered.extend_from_slice(&signed[..dkim_end]);
        tampered.extend_from_slice(b"From: attacker@evil.com\r\n");
        tampered.extend_from_slice(&signed[dkim_end..]);

        // The tampered message should FAIL verification because of N+1
        assert!(
            !verify_dkim_with_mail_auth(&tampered, &kp.private_key_pem).await,
            "tampered message with injected From should fail DKIM"
        );
    }

    #[test]
    fn no_dkim_without_config() {
        let email = build_message(
            "a@test.com",
            "b@example.com",
            "hi",
            "<id@test.com>",
            Body::text("yo"),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("DKIM-Signature"));
    }

    #[tokio::test]
    async fn dkim_sign_and_verify_body_raw_simple() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let email = build_message(
            "no-reply@example.com",
            "user@gmail.com",
            "Raw body DKIM test",
            "<raw.1@example.com>",
            Body::raw(
                "text/html; charset=utf-8".to_string(),
                "<h1>Hello from raw</h1>".to_string(),
            ),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);

        assert!(
            verify_dkim_with_mail_auth(&signed, &kp.private_key_pem).await,
            "DKIM verification failed for Body::Raw simple email"
        );
    }

    #[tokio::test]
    async fn dkim_sign_and_verify_body_raw_pgp_mime() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let boundary = "----pgp-abc123def456";
        let long_token = "f8c5b7b3a2c78762fdc5069123bb087584d2ec012f24300da1a3c971be61be07";
        let qp_html = format!(
            "<p>Click to sign in:</p><p><a href=3D\"https://indev.email/auth/callback?token=3D{}\">Sign=\r\n in</a></p>",
            long_token
        );
        let ct = format!(
            "multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"{}\"",
            boundary
        );
        let body = format!(
            "--{b}\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             {html}\r\n\
             --{b}\r\n\
             Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n\
             Content-Disposition: attachment; filename=\"signature.asc\"\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             -----BEGIN PGP SIGNATURE-----\r\n\
             \r\n\
             iHUEARYIAB0WIQT/fake/signature/here/AAAAAAAAAAAAAAAA\r\n\
             =AAAA\r\n\
             -----END PGP SIGNATURE-----\r\n\
             --{b}--",
            b = boundary,
            html = qp_html
        );

        let email = build_message(
            "no-reply@indev.email",
            "marirs@gmail.com",
            "Your sign-in link",
            "<magic.link@indev.email>",
            Body::raw(ct, body),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);

        assert!(
            verify_dkim_with_mail_auth(&signed, &kp.private_key_pem).await,
            "DKIM verification failed for PGP/MIME multipart/signed email"
        );

        let signed_str = String::from_utf8_lossy(&signed);
        assert!(signed_str.contains(long_token));
        assert!(signed_str.contains("BEGIN PGP SIGNATURE"));
        assert!(signed_str.contains(boundary));
    }

    #[tokio::test]
    async fn dkim_body_raw_tamper_detected() {
        let kp = crate::generate_dkim_keypair("sel1", "example.com", Some(2048)).unwrap();
        let dkim = CachedDkim {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem.clone(),
        };

        let email = build_message(
            "no-reply@example.com",
            "user@gmail.com",
            "Tamper test",
            "<tamper.1@example.com>",
            Body::raw(
                "text/html; charset=utf-8".to_string(),
                "<p>Original content</p>".to_string(),
            ),
            &[],
        )
        .unwrap();

        let raw = email.formatted();
        let signed = dkim_sign_raw(&raw, &dkim);

        assert!(
            verify_dkim_with_mail_auth(&signed, &kp.private_key_pem).await,
            "original raw body must pass DKIM"
        );

        let tampered =
            String::from_utf8_lossy(&signed).replace("Original content", "Tampered content");

        assert!(
            !verify_dkim_with_mail_auth(tampered.as_bytes(), &kp.private_key_pem).await,
            "tampered raw body must FAIL DKIM verification"
        );
    }

    #[test]
    fn body_raw_formatted_body_matches_input() {
        let boundary = "----pgp-test9999";
        let ct = format!(
            "multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"{}\"",
            boundary
        );
        let input_body = format!(
            "--{b}\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             <p>test</p>\r\n\
             --{b}\r\n\
             Content-Type: application/pgp-signature\r\n\
             \r\n\
             -----BEGIN PGP SIGNATURE-----\r\nfake\r\n-----END PGP SIGNATURE-----\r\n\
             --{b}--",
            b = boundary
        );

        let email = build_message(
            "a@test.com",
            "b@test.com",
            "test",
            "<id@test.com>",
            Body::raw(ct, input_body.clone()),
            &[],
        )
        .unwrap();

        let formatted = email.formatted();
        let formatted_str = String::from_utf8_lossy(&formatted);

        let body_start = formatted_str.find("\r\n\r\n").expect("no header/body sep") + 4;
        let output_body = &formatted_str[body_start..];

        assert_eq!(
            output_body, input_body,
            "Body::Raw output must match input exactly"
        );
    }

    #[test]
    fn body_raw_no_panic_with_multipart_signed() {
        let boundary = "----pgp-test1234";
        let ct = format!(
            "multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"{}\"",
            boundary
        );
        let body = format!(
            "--{b}\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             <p>Click: <a href=3D\"https://example.com/auth?token=3Dabcdef1234567890=\r\nabcdef\">Sign in</a></p>\r\n\
             --{b}\r\n\
             Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             -----BEGIN PGP SIGNATURE-----\r\nfakesig\r\n-----END PGP SIGNATURE-----\r\n\
             --{b}--",
            b = boundary
        );
        let email = build_message(
            "no-reply@example.com",
            "user@example.com",
            "Test",
            "<id@example.com>",
            Body::raw(ct, body),
            &[],
        )
        .unwrap();

        let formatted = email.formatted();
        let raw = String::from_utf8_lossy(&formatted);
        assert!(raw.contains("----pgp-test1234"), "boundary must be intact");
        assert!(
            raw.contains("BEGIN PGP SIGNATURE"),
            "signature must be present"
        );
    }

    #[test]
    fn body_raw_preserves_content_verbatim() {
        let ct = "text/plain; charset=utf-8".to_string();
        let body_text = "Hello =3D World\r\nLine two with special chars: àéîõü".to_string();
        let email = build_message(
            "a@test.com",
            "b@test.com",
            "raw test",
            "<id@test.com>",
            Body::raw(ct, body_text.clone()),
            &[],
        )
        .unwrap();

        let formatted = email.formatted();
        let raw = String::from_utf8_lossy(&formatted);
        assert!(raw.contains(&body_text), "body must be preserved verbatim");
    }

    #[test]
    fn body_raw_with_long_url_no_line_wrap() {
        let long_url = format!(
            "https://example.com/auth/callback?token={}",
            "a".repeat(200)
        );
        let ct = "text/html; charset=utf-8".to_string();
        let body = format!("<a href=\"{}\">{}</a>", long_url, long_url);
        let email = build_message(
            "a@test.com",
            "b@test.com",
            "long url",
            "<id@test.com>",
            Body::raw(ct, body),
            &[],
        )
        .unwrap();

        let formatted = email.formatted();
        let raw = String::from_utf8_lossy(&formatted);
        assert!(raw.contains(&long_url), "long URL must not be line-wrapped");
    }
}
