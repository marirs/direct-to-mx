use direct_to_mx::*;
use std::path::Path;

// ---------------------------------------------------------------------------
// Builder validation
// ---------------------------------------------------------------------------

#[test]
fn builder_requires_from() {
    let err = DirectToMx::builder()
        .ehlo_hostname("mail.example.com")
        .build();
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("from"), "expected 'from' in error: {msg}");
}

#[test]
fn builder_requires_ehlo_hostname() {
    let err = DirectToMx::builder().from("test@example.com").build();
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("ehlo"), "expected 'ehlo' in error: {msg}");
}

#[test]
fn builder_rejects_empty_from() {
    let err = DirectToMx::builder()
        .from("")
        .ehlo_hostname("mail.example.com")
        .build();
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("empty"), "expected 'empty' in error: {msg}");
}

#[test]
fn builder_rejects_empty_ehlo() {
    let err = DirectToMx::builder()
        .from("test@example.com")
        .ehlo_hostname("")
        .build();
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("empty"), "expected 'empty' in error: {msg}");
}

#[test]
fn builder_ok_with_required_fields() {
    let mailer = DirectToMx::builder()
        .from("test@example.com")
        .ehlo_hostname("mail.example.com")
        .build();
    assert!(mailer.is_ok());
}

#[test]
fn builder_ok_with_all_fields() {
    let kp = generate_dkim_keypair("sel1", "example.com", Some(1024)).unwrap();
    let mailer = DirectToMx::builder()
        .from("test@example.com")
        .ehlo_hostname("mail.example.com")
        .dkim(DkimOptions {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: kp.private_key_pem,
        })
        .force_ipv4(false)
        .build();
    assert!(mailer.is_ok());
}

#[test]
fn builder_rejects_bad_dkim_key() {
    let err = DirectToMx::builder()
        .from("test@example.com")
        .ehlo_hostname("mail.example.com")
        .dkim(DkimOptions {
            selector: "sel1".into(),
            domain: "example.com".into(),
            private_key_pem: "not-a-valid-pem".into(),
        })
        .build();
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("DKIM"), "expected 'DKIM' in error: {msg}");
}

#[test]
fn builder_force_ipv4_defaults_true() {
    // Build without setting force_ipv4 — it should default to true.
    // We can't inspect the field directly, but we verify it builds OK.
    let mailer = DirectToMx::builder()
        .from("test@example.com")
        .ehlo_hostname("mail.example.com")
        .build();
    assert!(mailer.is_ok());
}

// ---------------------------------------------------------------------------
// Body constructors
// ---------------------------------------------------------------------------

#[test]
fn body_html() {
    let b = Body::html("<p>Hello</p>");
    assert!(matches!(b, Body::Html(ref s) if s == "<p>Hello</p>"));
}

#[test]
fn body_text() {
    let b = Body::text("Hello");
    assert!(matches!(b, Body::Text(ref s) if s == "Hello"));
}

#[test]
fn body_both() {
    let b = Body::both("<p>Hi</p>", "Hi");
    match b {
        Body::Both { ref html, ref text } => {
            assert_eq!(html, "<p>Hi</p>");
            assert_eq!(text, "Hi");
        }
        _ => panic!("expected Body::Both"),
    }
}

#[test]
fn body_clone() {
    let b1 = Body::html("test");
    let b2 = b1.clone();
    assert!(matches!(b2, Body::Html(ref s) if s == "test"));
}

// ---------------------------------------------------------------------------
// DKIM key generation
// ---------------------------------------------------------------------------

#[test]
fn generate_dkim_keypair_ok() {
    let kp = generate_dkim_keypair("sel1", "example.com", None).unwrap();

    assert_eq!(kp.selector, "sel1");
    assert_eq!(kp.dns_record_name, "sel1._domainkey.example.com");
    assert!(kp.dns_txt_value.starts_with("v=DKIM1; k=rsa; p="));
    assert!(kp.private_key_pem.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!kp.public_key_base64.is_empty());
    // The DNS TXT value should contain the public key
    assert!(kp.dns_txt_value.contains(&kp.public_key_base64));
}

#[test]
fn generate_dkim_keypair_custom_bits() {
    // 1024 bits for faster test (not recommended for production)
    let kp = generate_dkim_keypair("test", "example.com", Some(1024)).unwrap();
    assert!(kp.private_key_pem.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!kp.public_key_base64.is_empty());
}

#[test]
fn generate_dkim_keypair_empty_selector_fails() {
    let err = generate_dkim_keypair("", "example.com", None);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("selector"), "expected 'selector' in: {msg}");
}

#[test]
fn generate_dkim_keypair_empty_domain_fails() {
    let err = generate_dkim_keypair("sel1", "", None);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("domain"), "expected 'domain' in: {msg}");
}

#[test]
fn generate_dkim_keypair_unique_keys() {
    let kp1 = generate_dkim_keypair("s1", "example.com", Some(1024)).unwrap();
    let kp2 = generate_dkim_keypair("s1", "example.com", Some(1024)).unwrap();
    // Two calls should produce different keys
    assert_ne!(kp1.private_key_pem, kp2.private_key_pem);
    assert_ne!(kp1.public_key_base64, kp2.public_key_base64);
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[test]
fn error_display_config() {
    let e = DirectToMxError::Config("missing field".into());
    assert_eq!(e.to_string(), "config error: missing field");
}

#[test]
fn error_display_dns() {
    let e = DirectToMxError::Dns("NXDOMAIN".into());
    assert_eq!(e.to_string(), "DNS error: NXDOMAIN");
}

#[test]
fn error_display_smtp() {
    let e = DirectToMxError::Smtp("connection refused".into());
    assert_eq!(e.to_string(), "SMTP error: connection refused");
}

#[test]
fn error_display_dkim() {
    let e = DirectToMxError::Dkim("bad key".into());
    assert_eq!(e.to_string(), "DKIM error: bad key");
}

#[test]
fn error_display_message() {
    let e = DirectToMxError::Message("invalid address".into());
    assert_eq!(e.to_string(), "message error: invalid address");
}

#[test]
fn error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(DirectToMxError::Config("test".into()));
    assert!(e.to_string().contains("test"));
}

// ---------------------------------------------------------------------------
// DNS verify types
// ---------------------------------------------------------------------------

#[test]
fn dns_verify_report_all_pass_when_empty() {
    let report = DnsVerifyReport { results: vec![] };
    assert!(report.all_pass());
}

#[test]
fn dns_verify_report_all_pass_with_passes() {
    let report = DnsVerifyReport {
        results: vec![
            DnsCheckResult {
                check: DnsCheck::Mx,
                status: DnsCheckStatus::Pass,
                detail: "ok".into(),
            },
            DnsCheckResult {
                check: DnsCheck::Spf,
                status: DnsCheckStatus::Skip,
                detail: "skipped".into(),
            },
        ],
    };
    assert!(report.all_pass());
}

#[test]
fn dns_verify_report_not_all_pass_with_fail() {
    let report = DnsVerifyReport {
        results: vec![
            DnsCheckResult {
                check: DnsCheck::Mx,
                status: DnsCheckStatus::Pass,
                detail: "ok".into(),
            },
            DnsCheckResult {
                check: DnsCheck::Dkim,
                status: DnsCheckStatus::Fail,
                detail: "missing".into(),
            },
        ],
    };
    assert!(!report.all_pass());
}

#[test]
fn dns_verify_report_not_all_pass_with_warn() {
    let report = DnsVerifyReport {
        results: vec![DnsCheckResult {
            check: DnsCheck::Dmarc,
            status: DnsCheckStatus::Warn,
            detail: "p=none".into(),
        }],
    };
    assert!(!report.all_pass());
}

#[test]
fn dns_verify_report_summary_contains_checks() {
    let report = DnsVerifyReport {
        results: vec![
            DnsCheckResult {
                check: DnsCheck::Mx,
                status: DnsCheckStatus::Pass,
                detail: "10 mx.example.com".into(),
            },
            DnsCheckResult {
                check: DnsCheck::Spf,
                status: DnsCheckStatus::Fail,
                detail: "no SPF".into(),
            },
        ],
    };
    let summary = report.summary();
    assert!(summary.contains("[PASS]"));
    assert!(summary.contains("[FAIL]"));
    assert!(summary.contains("Mx"));
    assert!(summary.contains("Spf"));
}

// ---------------------------------------------------------------------------
// DnsVerifyOptions validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_dns_empty_domain_fails() {
    let err = verify_dns(&DnsVerifyOptions {
        domain: "".into(),
        ..Default::default()
    })
    .await;
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// DnsCheck / DnsCheckStatus equality
// ---------------------------------------------------------------------------

#[test]
fn dns_check_eq() {
    assert_eq!(DnsCheck::Mx, DnsCheck::Mx);
    assert_ne!(DnsCheck::Mx, DnsCheck::Spf);
}

#[test]
fn dns_check_status_eq() {
    assert_eq!(DnsCheckStatus::Pass, DnsCheckStatus::Pass);
    assert_ne!(DnsCheckStatus::Pass, DnsCheckStatus::Fail);
    assert_ne!(DnsCheckStatus::Warn, DnsCheckStatus::Skip);
}

// ---------------------------------------------------------------------------
// send_bulk types
// ---------------------------------------------------------------------------

#[test]
fn outbound_message_clone() {
    let msg = OutboundMessage {
        to: "a@example.com".into(),
        subject: "Hi".into(),
        body: Body::text("hello"),
        attachments: vec![],
    };
    let msg2 = msg.clone();
    assert_eq!(msg2.to, "a@example.com");
    assert_eq!(msg2.subject, "Hi");
    assert!(msg2.attachments.is_empty());
}

#[test]
fn outbound_message_with_attachments() {
    let msg = OutboundMessage {
        to: "a@example.com".into(),
        subject: "Hi".into(),
        body: Body::text("hello"),
        attachments: vec![Attachment::new(
            "file.pdf",
            "application/pdf",
            vec![1, 2, 3],
        )],
    };
    assert_eq!(msg.attachments.len(), 1);
    assert_eq!(msg.attachments[0].filename, "file.pdf");
}

#[test]
fn default_concurrency_is_5() {
    assert_eq!(DEFAULT_CONCURRENCY, 5);
}

#[test]
fn bulk_result_debug() {
    let r = BulkResult {
        to: "a@example.com".into(),
        status: Ok(()),
    };
    let dbg = format!("{r:?}");
    assert!(dbg.contains("a@example.com"));
}

#[test]
fn bulk_result_with_error() {
    let r = BulkResult {
        to: "b@example.com".into(),
        status: Err(DirectToMxError::Smtp("timeout".into())),
    };
    assert!(r.status.is_err());
    assert_eq!(r.to, "b@example.com");
}

// ---------------------------------------------------------------------------
// Attachment
// ---------------------------------------------------------------------------

#[test]
fn attachment_new() {
    let att = Attachment::new("report.pdf", "application/pdf", vec![0xDE, 0xAD]);
    assert_eq!(att.filename, "report.pdf");
    assert_eq!(att.content_type, "application/pdf");
    assert_eq!(att.data, vec![0xDE, 0xAD]);
}

#[test]
fn attachment_clone() {
    let att = Attachment::new("img.png", "image/png", vec![1, 2, 3]);
    let att2 = att.clone();
    assert_eq!(att2.filename, "img.png");
    assert_eq!(att2.data.len(), 3);
}

#[test]
fn attachment_from_file_nonexistent() {
    let err = Attachment::from_file(Path::new("/tmp/nonexistent_file_xyz_123.pdf"));
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("failed to read"),
        "expected 'failed to read' in: {msg}"
    );
}

#[test]
fn attachment_from_file_ok() {
    // Write a temp file, read it back via from_file
    let path = std::env::temp_dir().join("direct_to_mx_test_attachment.txt");
    std::fs::write(&path, b"hello world").unwrap();
    let att = Attachment::from_file(&path).unwrap();
    assert_eq!(att.filename, "direct_to_mx_test_attachment.txt");
    assert_eq!(att.content_type, "text/plain");
    assert_eq!(att.data, b"hello world");
    std::fs::remove_file(&path).ok();
}

#[test]
fn attachment_from_file_unknown_ext() {
    let path = std::env::temp_dir().join("direct_to_mx_test.xyz789");
    std::fs::write(&path, b"data").unwrap();
    let att = Attachment::from_file(&path).unwrap();
    assert_eq!(att.content_type, "application/octet-stream");
    std::fs::remove_file(&path).ok();
}

#[test]
fn direct_to_mx_debug() {
    let mailer = DirectToMx::builder()
        .from("test@example.com")
        .ehlo_hostname("mail.example.com")
        .build()
        .unwrap();
    let dbg = format!("{mailer:?}");
    assert!(dbg.contains("DirectToMx"));
    assert!(dbg.contains("test@example.com"));
}
