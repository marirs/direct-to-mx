# direct_to_mx

Direct-to-MX email delivery with DKIM signing, IPv4 forcing, MX fallback, DKIM key generation, and DNS verification.

Send emails directly to recipient MX servers — no relay, no third-party API. Handles MX resolution, IPv4-only connections (avoids IPv6 PTR rejections from Gmail/Outlook), opportunistic STARTTLS, DKIM signing with `relaxed/relaxed` canonicalization, and automatic fallback across multiple MX hosts.

## Features

- **Builder pattern** — configure once, send many
- **Bulk sending** — `send_bulk()` with configurable concurrency (default: 5) and per-domain MX caching
- **DKIM signing** — RSA-SHA256 with `relaxed/relaxed` canonicalization and N+1 `From` oversigning (RFC 6376 §5.4)
- **DKIM key generation** — generate RSA keypairs with ready-to-use DNS TXT records
- **Early DKIM validation** — PEM key is parsed and validated at `build()` time, not per-send
- **IPv4 forcing** — resolve MX to A records only (default: on)
- **MX fallback** — tries all MX hosts in priority order
- **Opportunistic TLS** — STARTTLS when supported, plaintext fallback
- **Proper EHLO** — configurable hostname for PTR/rDNS compliance
- **DNS verification** — check MX, A, PTR, SPF, DKIM, DMARC records
- **Test emails** — built-in diagnostic `test_send()` method
- **HTML / Text / Both** — multipart/alternative support

## Installation

```toml
[dependencies]
direct_to_mx = "0.1"
```

## Quick Start

### Send an Email

```rust,no_run
use direct_to_mx::{DirectToMx, Body, DkimOptions};

#[tokio::main]
async fn main() -> Result<(), direct_to_mx::DirectToMxError> {
    let mailer = DirectToMx::builder()
        .from("no-reply@mail.example.com")
        .ehlo_hostname("mail.example.com")
        .dkim(DkimOptions {
            selector: "sel1".into(),
            domain: "mail.example.com".into(),
            private_key_pem: std::fs::read_to_string("/path/to/dkim-private.pem").unwrap(),
        })
        .build()?;

    // HTML email
    mailer.send("user@gmail.com", "Hello!", Body::html("<h1>Hi there</h1>")).await?;

    // Plain text email
    mailer.send("user@gmail.com", "Hello!", Body::text("Hi there")).await?;

    // Multipart (HTML + text fallback) — best for deliverability
    mailer.send(
        "user@gmail.com",
        "Hello!",
        Body::both("<h1>Hi there</h1>", "Hi there"),
    ).await?;

    Ok(())
}
```

### Bulk Send (Concurrent)

```rust,no_run
use direct_to_mx::{DirectToMx, Body, OutboundMessage};

#[tokio::main]
async fn main() -> Result<(), direct_to_mx::DirectToMxError> {
    let mailer = DirectToMx::builder()
        .from("no-reply@mail.example.com")
        .ehlo_hostname("mail.example.com")
        .build()?;

    let messages = vec![
        OutboundMessage {
            to: "alice@gmail.com".into(),
            subject: "Hi Alice".into(),
            body: Body::text("Hello Alice!"),
            attachments: vec![],
        },
        OutboundMessage {
            to: "bob@yahoo.com".into(),
            subject: "Hi Bob".into(),
            body: Body::html("<p>Hello Bob!</p>"),
            attachments: vec![],
        },
        OutboundMessage {
            to: "carol@outlook.com".into(),
            subject: "Hi Carol".into(),
            body: Body::both("<p>Hello Carol!</p>", "Hello Carol!"),
            attachments: vec![],
        },
    ];

    // Default concurrency: 5 parallel deliveries
    let results = mailer.send_bulk(messages, None).await;

    // Or set custom concurrency
    // let results = mailer.send_bulk(messages, Some(10)).await;

    for r in &results {
        match &r.status {
            Ok(()) => println!("{}: delivered", r.to),
            Err(e) => println!("{}: failed — {}", r.to, e),
        }
    }

    Ok(())
}
```

### Send a Test Email

```rust,no_run
use direct_to_mx::DirectToMx;

#[tokio::main]
async fn main() -> Result<(), direct_to_mx::DirectToMxError> {
    let mailer = DirectToMx::builder()
        .from("no-reply@mail.example.com")
        .ehlo_hostname("mail.example.com")
        .build()?;

    // Sends a diagnostic email with config details
    mailer.test_send("admin@gmail.com").await?;
    Ok(())
}
```

### Send with Attachments

```rust,no_run
use direct_to_mx::{DirectToMx, Body, Attachment};

#[tokio::main]
async fn main() -> Result<(), direct_to_mx::DirectToMxError> {
    let mailer = DirectToMx::builder()
        .from("no-reply@mail.example.com")
        .ehlo_hostname("mail.example.com")
        .build()?;

    // From raw bytes
    let pdf_bytes = std::fs::read("invoice.pdf").unwrap();
    mailer.send_with_attachments(
        "user@gmail.com",
        "Your Invoice",
        Body::text("Please find your invoice attached."),
        vec![Attachment::new("invoice.pdf", "application/pdf", pdf_bytes)],
    ).await?;

    // From a file path (content type inferred from extension)
    mailer.send_with_attachments(
        "user@gmail.com",
        "Photos",
        Body::html("<p>Here are the photos!</p>"),
        vec![
            Attachment::from_file(std::path::Path::new("photo1.jpg"))?,
            Attachment::from_file(std::path::Path::new("photo2.png"))?,
        ],
    ).await?;

    Ok(())
}
```

### Generate DKIM Keys

```rust
use direct_to_mx::generate_dkim_keypair;

fn main() -> Result<(), direct_to_mx::DirectToMxError> {
    let kp = generate_dkim_keypair("sel1", "mail.example.com", None)?;

    println!("Private key (store securely):");
    println!("{}", kp.private_key_pem);

    println!("\nAdd this DNS TXT record:");
    println!("  Name:  {}", kp.dns_record_name);
    println!("  Value: {}", kp.dns_txt_value);

    // kp.dns_record_name  → "sel1._domainkey.mail.example.com"
    // kp.dns_txt_value    → "v=DKIM1; k=rsa; p=MIIBIjAN..."
    // kp.public_key_base64 → "MIIBIjAN..." (just the key)
    // kp.selector          → "sel1"

    Ok(())
}
```

### Verify DNS Configuration

```rust,no_run
use direct_to_mx::{verify_dns, DnsVerifyOptions, DnsCheckStatus};

#[tokio::main]
async fn main() -> Result<(), direct_to_mx::DirectToMxError> {
    let report = verify_dns(&DnsVerifyOptions {
        domain: "mail.example.com".into(),
        dkim_selector: Some("sel1".into()),
        dkim_public_key_base64: Some("MIIBIjAN...".into()),
        sending_ip: Some("93.184.216.34".into()),
        ehlo_hostname: Some("mail.example.com".into()),
    }).await?;

    // Human-readable summary
    println!("{}", report.summary());
    // [PASS] Mx: 10 mx.example.com
    // [PASS] A: 93.184.216.34
    // [PASS] Ptr: 93.184.216.34 → mail.example.com
    // [PASS] Spf: v=spf1 ip4:93.184.216.34 -all
    // [PASS] Dkim: v=DKIM1; k=rsa; p=MIIBIjAN...
    // [PASS] Dmarc: v=DMARC1; p=quarantine; ...

    // Programmatic check
    if report.all_pass() {
        println!("All DNS checks passed!");
    } else {
        for r in &report.results {
            if r.status == DnsCheckStatus::Fail {
                println!("FAILED: {:?} — {}", r.check, r.detail);
            }
        }
    }

    Ok(())
}
```

## Configuration

### Builder Options

| Method | Required | Default | Description |
|--------|----------|---------|-------------|
| `.from()` | **Yes** | — | Sender address (e.g. `"no-reply@mail.example.com"`) |
| `.ehlo_hostname()` | **Yes** | — | SMTP EHLO hostname — must match your PTR record |
| `.dkim()` | No | None | DKIM signing config (selector, domain, private key PEM) |
| `.force_ipv4()` | No | `true` | Resolve MX to IPv4 only (avoids IPv6 PTR rejections) |

### Prerequisites for Good Deliverability

Before sending, make sure your server has:

1. **SPF** — Add a TXT record: `v=spf1 ip4:YOUR_IP -all`
2. **DKIM** — Generate keys with `generate_dkim_keypair()` and add the DNS TXT record
3. **DMARC** — Add a TXT record at `_dmarc.yourdomain`: `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain`
4. **PTR (rDNS)** — Your server IP's reverse DNS must point to your EHLO hostname
5. **MX record** — Point your domain's MX to your server

Use `verify_dns()` to check all of these.

## Error Handling

All public functions return `Result<T, DirectToMxError>`:

```rust
pub enum DirectToMxError {
    Config(String),   // builder misconfiguration
    Dns(String),      // DNS resolution failure
    Smtp(String),     // SMTP delivery failure
    Dkim(String),     // DKIM key error
    Message(String),  // email construction error
}
```

`DirectToMxError` implements `std::error::Error`, `Display`, and `Debug`.

## License

MIT — same as [lettre](https://github.com/lettre/lettre).
