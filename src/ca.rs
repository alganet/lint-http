// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::aws_lc_rs::sign::any_supported_type as aws_any_supported_type;
use rustls::pki_types::PrivateKeyDer as PrivateKey;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::fs;
use tracing::info;

/// Manages the Certificate Authority (CA) and generates leaf certificates for intercepted domains.
pub struct CertificateAuthority {
    ca_cert_pem: String,
    /// The CA private key used for signing.
    ca_key_pair: KeyPair,
    /// Cache of generated certificates for domains to avoid expensive regeneration.
    /// Key is the domain name.
    cache: Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
}

// rcgen::Certificate is Send + Sync.

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

    async fn load(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        let cert_pem = fs::read_to_string(cert_path)
            .await
            .context("failed to read CA cert")?;
        let key_pem = fs::read_to_string(key_path)
            .await
            .context("failed to read CA key")?;

        let key_pair =
            KeyPair::from_pem(&key_pem).context("failed to parse CA key pair from PEM")?;

        Ok(Arc::new(Self {
            ca_cert_pem: cert_pem,
            ca_key_pair: key_pair,
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
        fs::write(key_path, &key_pem).await?;

        Ok(Arc::new(Self {
            ca_cert_pem: cert_pem,
            ca_key_pair: key_pair,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }))
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

        let certs: Vec<_> =
            rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let leaf_cert = certs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no certificates parsed from PEM"))?;

        let keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        let leaf_key_bytes = keys
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no private keys parsed from PEM"))?;
        let leaf_key_der = PrivateKey::from(leaf_key_bytes);

        let signer = aws_any_supported_type(&leaf_key_der)
            .map_err(|e| anyhow::anyhow!("failed to create leaf key signer: {}", e))?;
        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(vec![leaf_cert], signer));

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
    use super::*;
    use anyhow::Result;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_generate_and_save_ca() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

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
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

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
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

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
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

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
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

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
