use crate::error::DirectToMxError;

/// A generated DKIM RSA keypair with all the information needed for DNS
/// configuration and email signing.
///
/// # Security
///
/// This struct derives `Debug`, which **will include the private key** in
/// debug output. Avoid logging `DkimKeyPair` in production.
#[derive(Clone, Debug)]
pub struct DkimKeyPair {
    /// RSA private key in PKCS#1 PEM format (for signing — store securely).
    pub private_key_pem: String,
    /// RSA public key in base64-encoded DER format (for the DNS TXT record `p=` value).
    pub public_key_base64: String,
    /// Ready-to-use DNS TXT record value, e.g. `"v=DKIM1; k=rsa; p=MIIBIjAN..."`.
    pub dns_txt_value: String,
    /// The full DNS record name, e.g. `"sel1._domainkey.mail.example.com"`.
    pub dns_record_name: String,
    /// The DKIM selector used.
    pub selector: String,
}

/// Generate a new DKIM RSA keypair.
///
/// # Arguments
///
/// * `selector` — DKIM selector (the `s=` tag), e.g. `"sel1"`.
/// * `domain` — Signing domain (the `d=` tag), e.g. `"mail.example.com"`.
/// * `bits` — RSA key size. Pass `None` for the default of 2048 bits.
///
/// # Example
///
/// ```rust,no_run
/// let kp = direct_to_mx::generate_dkim_keypair("sel1", "mail.example.com", None).unwrap();
/// println!("Add this DNS TXT record:");
/// println!("  Name:  {}", kp.dns_record_name);
/// println!("  Value: {}", kp.dns_txt_value);
/// ```
pub fn generate_dkim_keypair(
    selector: &str,
    domain: &str,
    bits: Option<usize>,
) -> Result<DkimKeyPair, DirectToMxError> {
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::pkcs8::EncodePublicKey;

    let bits = bits.unwrap_or(2048);
    if selector.is_empty() {
        return Err(DirectToMxError::Config("DKIM selector must not be empty".into()));
    }
    if domain.is_empty() {
        return Err(DirectToMxError::Config("DKIM domain must not be empty".into()));
    }

    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| DirectToMxError::Dkim(format!("RSA key generation failed: {e}")))?;
    let public_key = rsa::RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| DirectToMxError::Dkim(format!("PEM encoding failed: {e}")))?;
    let public_der = public_key
        .to_public_key_der()
        .map_err(|e| DirectToMxError::Dkim(format!("DER encoding failed: {e}")))?;
    let public_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        public_der.as_bytes(),
    );

    let dns_record_name = format!("{selector}._domainkey.{domain}");
    let dns_txt_value = format!("v=DKIM1; k=rsa; p={public_b64}");

    Ok(DkimKeyPair {
        private_key_pem: private_pem.to_string(),
        public_key_base64: public_b64,
        dns_txt_value,
        dns_record_name,
        selector: selector.to_string(),
    })
}
