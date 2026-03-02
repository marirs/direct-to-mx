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
                use lettre::message::dkim::{DkimSigningAlgorithm, DkimSigningKey};
                let _ = DkimSigningKey::new(&opts.private_key_pem, DkimSigningAlgorithm::Rsa)
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
        let mut email = self.prepare_message(to, subject, body, &attachments)?;
        self.sign_message(&mut email);

        let rcpt_domain = to.rsplit_once('@').map(|(_, d)| d).unwrap_or(to);
        let mx_hosts = resolve_mx(rcpt_domain).await;

        self.deliver_with_fallback(&mx_hosts, email).await
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

            let email = match prepared {
                Ok(mut email) => {
                    self.sign_message(&mut email);
                    email
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

                let status =
                    deliver_with_fallback_static(&ehlo_hostname, force_ipv4, &mx_hosts, email)
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

    /// DKIM-sign a message using the cached signer.
    fn sign_message(&self, email: &mut lettre::Message) {
        if let Some(ref dkim) = self.dkim {
            sign_dkim_cached(email, dkim);
        }
    }

    /// Try all MX hosts in priority order for a single email.
    async fn deliver_with_fallback(
        &self,
        mx_hosts: &[String],
        email: lettre::Message,
    ) -> Result<(), DirectToMxError> {
        deliver_with_fallback_static(&self.ehlo_hostname, self.force_ipv4, mx_hosts, email).await
    }
}

// ---------------------------------------------------------------------------
// Free-standing delivery (used by both send() and send_bulk() tasks)
// ---------------------------------------------------------------------------

async fn deliver_with_fallback_static(
    ehlo_hostname: &str,
    force_ipv4: bool,
    mx_hosts: &[String],
    email: lettre::Message,
) -> Result<(), DirectToMxError> {
    let mut last_err: Option<DirectToMxError> = None;
    for mx_host in mx_hosts {
        let connect_host = if force_ipv4 {
            resolve_ipv4(mx_host).await
        } else {
            mx_host.clone()
        };

        match try_deliver(ehlo_hostname, &connect_host, mx_host, email.clone()).await {
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

async fn try_deliver(
    ehlo_hostname: &str,
    connect_host: &str,
    mx_host: &str,
    email: lettre::Message,
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

    transport.send(email).await.map(|_| ()).map_err(|e| {
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

/// DKIM sign using the pre-parsed (cached) signing key.
/// Uses N+1 oversigning on `From` to prevent header injection attacks
/// (RFC 6376 §5.4).
fn sign_dkim_cached(email: &mut lettre::Message, dkim: &CachedDkim) {
    use lettre::message::dkim::{
        DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningAlgorithm,
        DkimSigningKey,
    };
    use lettre::message::header::HeaderName;

    // Key was validated at build() time so this should not fail.
    let signing_key = match DkimSigningKey::new(&dkim.private_key_pem, DkimSigningAlgorithm::Rsa) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("direct_to_mx: DKIM key parse failed, sending unsigned: {e}");
            return;
        }
    };

    let config = DkimConfig::new(
        dkim.selector.clone(),
        dkim.domain.clone(),
        signing_key,
        vec![
            // N+1 oversigning: sign From twice to prevent injection of a
            // second From header (RFC 6376 §5.4 recommendation).
            HeaderName::new_from_ascii_str("From"),
            HeaderName::new_from_ascii_str("From"),
            HeaderName::new_from_ascii_str("To"),
            HeaderName::new_from_ascii_str("Subject"),
            HeaderName::new_from_ascii_str("Date"),
            HeaderName::new_from_ascii_str("Message-ID"),
            HeaderName::new_from_ascii_str("Content-Type"),
            HeaderName::new_from_ascii_str("Content-Transfer-Encoding"),
        ],
        DkimCanonicalization {
            header: DkimCanonicalizationType::Relaxed,
            body: DkimCanonicalizationType::Relaxed,
        },
    );

    email.sign(&config);
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
