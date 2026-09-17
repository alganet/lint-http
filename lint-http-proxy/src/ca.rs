// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::aws_lc_rs::sign::any_supported_type as aws_any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer as PrivateKey, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::fs;
use tracing::info;

/// Write a CA private key readable only by the user that owns it.
///
/// This key signs certificates the proxy asks a client to trust, so anyone who
/// can read it can mint one that the same client accepts. `fs::write` leaves it
/// at whatever the process umask allows — commonly `0644` or `0664`, which is
/// world-readable — and the file often lands somewhere shared: the working
/// directory of a checkout, or, for a wrapped run, a directory under `/tmp`.
///
/// The mode is set at creation *and* after the write. The creation mode does
/// nothing when the file already exists, which is exactly the case where a key
/// written by an earlier version is sitting there with the old permissions.
///
/// Non-Unix platforms fall back to a plain write: the permission model is not
/// the same one, and pretending otherwise with a no-op would read as a
/// guarantee this function cannot make there.
async fn write_private_key(path: &Path, pem: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::AsyncWriteExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .await
            .context("failed to create CA key file")?;
        file.write_all(pem.as_bytes())
            .await
            .context("failed to write CA key")?;
        file.flush().await.context("failed to flush CA key")?;
        drop(file);

        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .context("failed to restrict CA key permissions")?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, pem)
            .await
            .context("failed to write CA key")?;
        Ok(())
    }
}

/// Manages the Certificate Authority (CA) and generates leaf certificates for intercepted domains.
pub struct CertificateAuthority {
    ca_cert_pem: String,
    /// The same certificate in DER, because every forged chain now carries a
    /// copy of it and re-parsing the PEM per domain would be work for nothing.
    ca_cert_der: CertificateDer<'static>,
    /// The CA private key used for signing.
    ca_key_pair: KeyPair,
    /// Cache of generated certificates for domains to avoid expensive regeneration.
    /// Key is the domain name.
    cache: Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
}

impl CertificateAuthority {
    /// Loads the CA from the specified paths, or generates a new one if they don't exist.
    pub async fn load_or_generate(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        if cert_path.exists() && key_path.exists() {
            info!("Loading existing CA from {:?}", cert_path);
            Self::load(cert_path, key_path).await
        } else {
            info!("Generating new CA at {:?}", cert_path);
            Self::generate_and_save(cert_path, key_path).await
        }
    }

    /// Load an existing CA, failing if either half is missing.
    ///
    /// Public because a caller that only wants to *read* an existing CA must
    /// have a way to say so. [`Self::load_or_generate`] answers a missing file
    /// by minting a new authority, which is right at startup and wrong
    /// everywhere else: doing it against a proxy that is already serving
    /// replaces the key it signs with, and every certificate it then presents
    /// is signed by an authority nobody was told about.
    pub async fn load(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        let cert_pem = fs::read_to_string(cert_path)
            .await
            .context("failed to read CA cert")?;
        let key_pem = fs::read_to_string(key_path)
            .await
            .context("failed to read CA key")?;

        let key_pair =
            KeyPair::from_pem(&key_pem).context("failed to parse CA key pair from PEM")?;

        Self::new(cert_pem, key_pair)
    }

    /// Assemble from a certificate and the key that signed it.
    ///
    /// Shared by the load and generate paths so the DER is derived in exactly
    /// one place: it is on the wire in every forged chain, and two derivations
    /// would be two chances for it to disagree with the PEM beside it.
    fn new(ca_cert_pem: String, ca_key_pair: KeyPair) -> Result<Arc<Self>> {
        let ca_cert_der = CertificateDer::from_pem_slice(ca_cert_pem.as_bytes())
            .context("failed to parse the CA certificate")?;
        Ok(Arc::new(Self {
            ca_cert_pem,
            ca_cert_der,
            ca_key_pair,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    async fn generate_and_save(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        let mut params = CertificateParams::new(vec![])?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "lint-http CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "lint-http");

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::write(cert_path, &cert_pem).await?;
        write_private_key(key_path, &key_pem).await?;

        Self::new(cert_pem, key_pair)
    }

    /// The base64 SHA-256 of this CA's `SubjectPublicKeyInfo`.
    ///
    /// The value Chromium's `--ignore-certificate-errors-spki-list` takes, and
    /// the same digest HPKP pins named. It lives here because it is a fact
    /// about the key, and this is the only type that holds one.
    ///
    /// **Why a pin rather than installing the CA.** Chromium on Linux verifies
    /// through NSS, whose database is per-*user* and not per-profile, so a
    /// throwaway `--user-data-dir` does not isolate a certificate installed
    /// into it — trusting the CA that way would edit the user's own trust store
    /// and leave it edited. The pin is scoped to one launch and to this key
    /// alone, and it is the reason `browse` can be run without installing
    /// anything. It is emphatically not `--ignore-certificate-errors`, which
    /// turns verification off wholesale and would make the session worthless
    /// for judging TLS.
    pub fn spki_pin(&self) -> Result<String> {
        use base64::Engine;
        use sha2::Digest;

        // `public_key_pem` is the SPKI, PEM-wrapped; the DER inside it is what
        // gets hashed. Going through PEM rather than reaching for the DER
        // accessor keeps this on rcgen's public surface.
        let pem = self.ca_key_pair.public_key_pem();
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .context("failed to decode the CA public key")?;

        let digest = sha2::Sha256::digest(&der);
        Ok(base64::engine::general_purpose::STANDARD.encode(digest))
    }

    /// Generates a leaf certificate for the given domain, signed by this CA.
    pub fn gen_cert_for_domain(&self, domain: &str) -> Result<Arc<rustls::sign::CertifiedKey>> {
        // Check cache first
        {
            let cache = self
                .cache
                .read()
                .map_err(|e| anyhow::anyhow!("CA cache RwLock poisoned: {}", e))?;
            if let Some(cert) = cache.get(domain) {
                return Ok(cert.clone());
            }
        }

        // Generate new cert
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);
        params.use_authority_key_identifier_extension = false;

        // Create key pair for the leaf cert
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        // Sign with CA
        let issuer = Issuer::new(self.ca_params()?, &self.ca_key_pair);
        let cert = params.signed_by(&key_pair, &issuer)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Parse the leaf (first PEM object of each type) via rustls-pki-types'
        // `PemObject`, which we already depend on through rustls.
        let leaf_cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .context("no certificates parsed from PEM")?;
        let leaf_key = PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes())
            .context("no private keys parsed from PEM")?;
        let leaf_key_der = PrivateKey::from(leaf_key);

        let signer = aws_any_supported_type(&leaf_key_der)
            .map_err(|e| anyhow::anyhow!("failed to create leaf key signer: {}", e))?;
        // Leaf *and* the CA that signed it. A chain of one is what a client
        // gets from a server that forgot its intermediates, and it costs two
        // things here. A client verifying against a bundle has to hold the
        // issuer already — true for the bundle these commands write, and not
        // true in general. And Chromium's `--ignore-certificate-errors-spki-list`
        // matches a public key *in the presented chain*: with the CA absent
        // from it, the pin `browse` computes can never match, and every
        // interception fails with an authority error that looks like a broken
        // proxy. Sending the signer is what a server is supposed to do anyway.
        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(
            vec![leaf_cert, self.ca_cert_der.clone()],
            signer,
        ));

        // Update cache
        {
            let mut cache = self
                .cache
                .write()
                .map_err(|e| anyhow::anyhow!("CA cache RwLock poisoned: {}", e))?;
            cache.insert(domain.to_string(), certified_key.clone());
        }

        Ok(certified_key)
    }

    pub fn get_ca_cert_pem(&self) -> String {
        self.ca_cert_pem.clone()
    }

    fn ca_params(&self) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(vec![]).context("failed to create CA params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "lint-http CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "lint-http");
        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    /// The pin is a base64 SHA-256, and it identifies *this* key.
    ///
    /// The value was checked once against
    /// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`
    /// and matched; what a test can hold without shelling out to openssl is
    /// that it is the right shape, that reloading the same CA reproduces it,
    /// and that a different CA does not — the three ways a wrong pin would
    /// reach Chromium, which rejects one silently by simply not trusting the
    /// certificate.
    #[tokio::test]
    async fn spki_pin_identifies_the_key_that_made_it() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("lint-http-pin-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;
        let (cert, key) = (dir.join("ca.crt"), dir.join("ca.key"));

        let pin = CertificateAuthority::load_or_generate(&cert, &key)
            .await?
            .spki_pin()?;
        // 32 bytes of digest, base64: 44 characters with one pad.
        assert_eq!(pin.len(), 44, "pin was {pin:?}");
        assert!(pin.ends_with('='), "pin was {pin:?}");

        // Loading the same CA again reproduces it.
        let again = CertificateAuthority::load_or_generate(&cert, &key)
            .await?
            .spki_pin()?;
        assert_eq!(pin, again);

        // A different CA does not.
        let other = dir.join("other");
        std::fs::create_dir_all(&other)?;
        let different =
            CertificateAuthority::load_or_generate(&other.join("ca.crt"), &other.join("ca.key"))
                .await?
                .spki_pin()?;
        assert_ne!(pin, different);

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// The key this writes signs certificates clients are told to trust, so it
    /// must not be readable by other users on the machine — the working
    /// directory of a checkout and a directory under `/tmp` are both shared.
    #[cfg(unix)]
    #[tokio::test]
    async fn generated_ca_key_is_private_to_its_owner() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("lint-http-ca-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;
        let cert = dir.join("ca.crt");
        let key = dir.join("ca.key");

        CertificateAuthority::load_or_generate(&cert, &key).await?;

        let mode = std::fs::metadata(&key)?.permissions().mode() & 0o777;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, 0o600, "CA key mode was {mode:o}");
        Ok(())
    }

    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn test_generate_and_save_ca() -> Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let cert_path = temp.path("test_ca", "crt");
        let key_path = temp.path("test_ca", "key");

        // Generate new CA
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;

        // Verify files were created
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verify PEM contains certificate
        let pem = ca.get_ca_cert_pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_load_existing_ca() -> Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let cert_path = temp.path("test_ca", "crt");
        let key_path = temp.path("test_ca", "key");

        // First generate a CA
        let ca1 = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;
        let pem1 = ca1.get_ca_cert_pem();

        // Now load it again (should load, not generate)
        let ca2 = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;
        let pem2 = ca2.get_ca_cert_pem();

        // Should have the same certificate
        assert_eq!(pem1, pem2);

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_gen_cert_for_domain() -> Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let cert_path = temp.path("test_ca", "crt");
        let key_path = temp.path("test_ca", "key");

        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;

        // Generate cert for domain
        let cert = ca.gen_cert_for_domain("example.com")?;

        // Verify it's not None and has certificates
        assert!(!cert.cert.is_empty());

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_cert_cache_hit() -> Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let cert_path = temp.path("test_ca", "crt");
        let key_path = temp.path("test_ca", "key");

        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;

        // Generate cert for domain first time
        let cert1 = ca.gen_cert_for_domain("example.com")?;

        // Generate cert for same domain second time (should use cache)
        let cert2 = ca.gen_cert_for_domain("example.com")?;

        // Should return the same Arc (same pointer)
        assert!(Arc::ptr_eq(&cert1, &cert2));

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_domains() -> Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let cert_path = temp.path("test_ca", "crt");
        let key_path = temp.path("test_ca", "key");

        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;

        // Generate certs for different domains
        let cert1 = ca.gen_cert_for_domain("example.com")?;
        let cert2 = ca.gen_cert_for_domain("google.com")?;
        let cert3 = ca.gen_cert_for_domain("github.com")?;

        // Should all be different
        assert!(!Arc::ptr_eq(&cert1, &cert2));
        assert!(!Arc::ptr_eq(&cert1, &cert3));
        assert!(!Arc::ptr_eq(&cert2, &cert3));

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
        Ok(())
    }
}
