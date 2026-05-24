use crate::error::DirectToMxError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options for DNS verification. Only `domain` is required; all other fields
/// are optional and control which checks are performed.
#[derive(Clone, Debug, Default)]
pub struct DnsVerifyOptions {
    /// The sending domain (e.g. `"r.indev.email"`). **Required.**
    pub domain: String,
    /// DKIM selector (e.g. `"sel1"`). If set, the DKIM TXT record is checked.
    pub dkim_selector: Option<String>,
    /// Expected DKIM public key (base64). If set together with `dkim_selector`,
    /// the DNS record is compared against this value.
    pub dkim_public_key_base64: Option<String>,
    /// The sending server's IP address (e.g. `"89.167.97.191"`). If set, the
    /// PTR record is checked.
    pub sending_ip: Option<String>,
    /// Expected EHLO hostname for the PTR check (e.g. `"r.indev.email"`). If
    /// omitted, `domain` is used.
    pub ehlo_hostname: Option<String>,
}

/// The kind of DNS check that was performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsCheck {
    Mx,
    A,
    Ptr,
    Spf,
    Dkim,
    Dmarc,
}

/// Outcome of a single DNS check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsCheckStatus {
    /// The check passed.
    Pass,
    /// The check failed.
    Fail,
    /// The record exists but may need attention (e.g. DMARC `p=none`).
    Warn,
    /// Not enough information was provided to run this check.
    Skip,
}

/// Result of a single DNS check.
#[derive(Clone, Debug)]
pub struct DnsCheckResult {
    pub check: DnsCheck,
    pub status: DnsCheckStatus,
    pub detail: String,
}

/// Full DNS verification report.
#[derive(Clone, Debug)]
pub struct DnsVerifyReport {
    pub results: Vec<DnsCheckResult>,
}

impl DnsVerifyReport {
    /// Returns `true` if every check that was run (not skipped) passed.
    pub fn all_pass(&self) -> bool {
        self.results
            .iter()
            .all(|r| matches!(r.status, DnsCheckStatus::Pass | DnsCheckStatus::Skip))
    }

    /// Human-readable one-line-per-check summary.
    pub fn summary(&self) -> String {
        self.results
            .iter()
            .map(|r| {
                let icon = match r.status {
                    DnsCheckStatus::Pass => "PASS",
                    DnsCheckStatus::Fail => "FAIL",
                    DnsCheckStatus::Warn => "WARN",
                    DnsCheckStatus::Skip => "SKIP",
                };
                format!("[{icon}] {:?}: {}", r.check, r.detail)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Perform DNS verification for the given options.
///
/// Each check runs independently — a failure in one does not prevent the
/// others from executing.
pub async fn verify_dns(opts: &DnsVerifyOptions) -> Result<DnsVerifyReport, DirectToMxError> {
    if opts.domain.is_empty() {
        return Err(DirectToMxError::Config("domain must not be empty".into()));
    }

    // hickory-resolver 0.26 replaced the infallible `TokioAsyncResolver::tokio`
    // constructor with a fallible builder. Building from `Config::default()`
    // + a default tokio provider does no IO and cannot fail in practice.
    let resolver = hickory_resolver::TokioResolver::builder_with_config(
        hickory_resolver::config::ResolverConfig::default(),
        hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
    )
    .build()
    .expect("hickory resolver build from default config cannot fail");

    let mut results = Vec::new();

    // MX
    results.push(check_mx(&resolver, &opts.domain).await);

    // A record
    results.push(check_a(&resolver, &opts.domain).await);

    // PTR (reverse DNS)
    let ehlo = opts.ehlo_hostname.as_deref().unwrap_or(&opts.domain);
    results.push(check_ptr(&resolver, &opts.domain, ehlo).await);

    // SPF
    results.push(check_spf(&resolver, &opts.domain).await);

    // DKIM
    results.push(
        check_dkim(
            &resolver,
            &opts.domain,
            opts.dkim_selector.as_deref(),
            opts.dkim_public_key_base64.as_deref(),
        )
        .await,
    );

    // DMARC
    results.push(check_dmarc(&resolver, &opts.domain).await);

    Ok(DnsVerifyReport { results })
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

async fn check_mx(resolver: &hickory_resolver::TokioResolver, domain: &str) -> DnsCheckResult {
    use hickory_resolver::proto::rr::RData;
    match resolver.mx_lookup(domain).await {
        Ok(mx) => {
            // hickory 0.26 returns a generic `Lookup`; the typed `MX` iterator
            // is gone. Walk `.answers()` and pattern-match the RData variant.
            let records: Vec<String> = mx
                .answers()
                .iter()
                .filter_map(|rec| match &rec.data {
                    RData::MX(mx) => Some(format!(
                        "{} {}",
                        mx.preference,
                        mx.exchange.to_string().trim_end_matches('.')
                    )),
                    _ => None,
                })
                .collect();
            if records.is_empty() {
                DnsCheckResult {
                    check: DnsCheck::Mx,
                    status: DnsCheckStatus::Fail,
                    detail: "no MX records found".into(),
                }
            } else {
                DnsCheckResult {
                    check: DnsCheck::Mx,
                    status: DnsCheckStatus::Pass,
                    detail: records.join(", "),
                }
            }
        }
        Err(e) => DnsCheckResult {
            check: DnsCheck::Mx,
            status: DnsCheckStatus::Fail,
            detail: format!("error: {e}"),
        },
    }
}

async fn check_a(resolver: &hickory_resolver::TokioResolver, domain: &str) -> DnsCheckResult {
    match resolver.lookup_ip(domain).await {
        Ok(ips) => {
            let addrs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
            if addrs.is_empty() {
                DnsCheckResult {
                    check: DnsCheck::A,
                    status: DnsCheckStatus::Fail,
                    detail: "no A/AAAA records found".into(),
                }
            } else {
                DnsCheckResult {
                    check: DnsCheck::A,
                    status: DnsCheckStatus::Pass,
                    detail: addrs.join(", "),
                }
            }
        }
        Err(e) => DnsCheckResult {
            check: DnsCheck::A,
            status: DnsCheckStatus::Fail,
            detail: format!("error: {e}"),
        },
    }
}

async fn check_ptr(
    resolver: &hickory_resolver::TokioResolver,
    domain: &str,
    ehlo_hostname: &str,
) -> DnsCheckResult {
    // First resolve domain to an IPv4 address
    let ip = match resolver.lookup_ip(domain).await {
        Ok(ips) => match ips.iter().find(|ip| ip.is_ipv4()) {
            Some(ip) => ip,
            None => {
                return DnsCheckResult {
                    check: DnsCheck::Ptr,
                    status: DnsCheckStatus::Fail,
                    detail: "no IPv4 A record to check PTR for".into(),
                };
            }
        },
        Err(_) => {
            return DnsCheckResult {
                check: DnsCheck::Ptr,
                status: DnsCheckStatus::Fail,
                detail: "no A record found — cannot check PTR".into(),
            };
        }
    };

    match resolver.reverse_lookup(ip).await {
        Ok(names) => {
            use hickory_resolver::proto::rr::RData;
            // hickory 0.26: reverse_lookup returns a generic `Lookup` whose
            // answers carry `RData::PTR(Name)` records. Pattern-match.
            let ptrs: Vec<String> = names
                .answers()
                .iter()
                .filter_map(|rec| match &rec.data {
                    RData::PTR(ptr) => Some(ptr.0.to_string().trim_end_matches('.').to_string()),
                    _ => None,
                })
                .collect();
            let ok = ptrs.iter().any(|n| n.eq_ignore_ascii_case(ehlo_hostname));
            DnsCheckResult {
                check: DnsCheck::Ptr,
                status: if ok {
                    DnsCheckStatus::Pass
                } else {
                    DnsCheckStatus::Fail
                },
                detail: format!("{ip} → {}", ptrs.join(", ")),
            }
        }
        Err(e) => DnsCheckResult {
            check: DnsCheck::Ptr,
            status: DnsCheckStatus::Fail,
            detail: format!("{ip} → error: {e}"),
        },
    }
}

async fn check_spf(
    resolver: &hickory_resolver::TokioResolver,
    domain: &str,
) -> DnsCheckResult {
    match resolver.txt_lookup(domain).await {
        Ok(txts) => {
            let records: Vec<String> = txt_strings(&txts);
            let has_spf = records.iter().any(|t| t.contains("v=spf1"));
            DnsCheckResult {
                check: DnsCheck::Spf,
                status: if has_spf {
                    DnsCheckStatus::Pass
                } else {
                    DnsCheckStatus::Fail
                },
                detail: if records.is_empty() {
                    "no TXT records found".into()
                } else {
                    records.join(" | ")
                },
            }
        }
        Err(e) => DnsCheckResult {
            check: DnsCheck::Spf,
            status: DnsCheckStatus::Fail,
            detail: format!("error: {e}"),
        },
    }
}

async fn check_dkim(
    resolver: &hickory_resolver::TokioResolver,
    domain: &str,
    selector: Option<&str>,
    expected_pub_b64: Option<&str>,
) -> DnsCheckResult {
    let selector = match selector {
        Some(s) if !s.is_empty() => s,
        _ => {
            return DnsCheckResult {
                check: DnsCheck::Dkim,
                status: DnsCheckStatus::Skip,
                detail: "no DKIM selector provided".into(),
            };
        }
    };

    let dkim_domain = format!("{selector}._domainkey.{domain}");
    match resolver.txt_lookup(&dkim_domain).await {
        Ok(txts) => {
            let records: Vec<String> = txt_strings(&txts);
            let has_dkim = records
                .iter()
                .any(|t| t.contains("v=DKIM1") && t.contains("p="));

            if !has_dkim {
                return DnsCheckResult {
                    check: DnsCheck::Dkim,
                    status: DnsCheckStatus::Fail,
                    detail: format!(
                        "no valid DKIM record at {dkim_domain}: {}",
                        if records.is_empty() {
                            "no TXT records".to_string()
                        } else {
                            records.join(" | ")
                        }
                    ),
                };
            }

            // If an expected public key was provided, verify it appears in the record
            if let Some(expected) = expected_pub_b64
                && !expected.is_empty()
            {
                let key_match = records.iter().any(|t| t.contains(expected));
                if !key_match {
                    return DnsCheckResult {
                        check: DnsCheck::Dkim,
                        status: DnsCheckStatus::Warn,
                        detail: format!(
                            "DKIM record exists at {dkim_domain} but public key does not match expected value"
                        ),
                    };
                }
            }

            DnsCheckResult {
                check: DnsCheck::Dkim,
                status: DnsCheckStatus::Pass,
                detail: records.join(" | "),
            }
        }
        Err(e) => DnsCheckResult {
            check: DnsCheck::Dkim,
            status: DnsCheckStatus::Fail,
            detail: format!("error looking up {dkim_domain}: {e}"),
        },
    }
}

async fn check_dmarc(
    resolver: &hickory_resolver::TokioResolver,
    domain: &str,
) -> DnsCheckResult {
    let dmarc_domain = format!("_dmarc.{domain}");
    match resolver.txt_lookup(&dmarc_domain).await {
        Ok(txts) => {
            let records: Vec<String> = txt_strings(&txts);
            let has_dmarc = records.iter().any(|t| t.contains("v=DMARC1"));

            if !has_dmarc {
                return DnsCheckResult {
                    check: DnsCheck::Dmarc,
                    status: DnsCheckStatus::Fail,
                    detail: if records.is_empty() {
                        format!("no TXT records at {dmarc_domain}")
                    } else {
                        records.join(" | ")
                    },
                };
            }

            // Check policy strength
            let policy_none = records.iter().any(|t| t.contains("p=none"));
            DnsCheckResult {
                check: DnsCheck::Dmarc,
                status: if policy_none {
                    DnsCheckStatus::Warn
                } else {
                    DnsCheckStatus::Pass
                },
                detail: records.join(" | "),
            }
        }
        Err(e) => DnsCheckResult {
            check: DnsCheck::Dmarc,
            status: DnsCheckStatus::Fail,
            detail: format!("error looking up {dmarc_domain}: {e}"),
        },
    }
}

/// Extract TXT record strings from a generic `Lookup` (hickory 0.26).
/// Pre-0.26 a `TxtLookup` had a typed `.iter()` returning `&TXT`; the
/// new generic `Lookup` only exposes `&[Record]`, so we filter for
/// `RData::TXT` variants and convert each to a `String` via its
/// `Display` impl.
fn txt_strings(lookup: &hickory_resolver::lookup::Lookup) -> Vec<String> {
    use hickory_resolver::proto::rr::RData;
    lookup
        .answers()
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::TXT(txt) => Some(txt.to_string()),
            _ => None,
        })
        .collect()
}
