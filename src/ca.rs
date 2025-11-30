// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::{Certificate as RustlsCertificate, PrivateKey};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::fs;
use tracing::info;

/// Manages the Certificate Authority (CA) and generates leaf certificates for intercepted domains.
pub struct CertificateAuthority {
    ca_cert_pem: String,
    /// The CA certificate object used for signing.
    /// It must be wrapped in a mutex because rcgen::Certificate might not be Sync/Send or we want interior mutability?
    /// Actually rcgen::Certificate is Send + Sync if the key pair is. Ring key pairs are.
    /// But to be safe and allow shared access if needed (though we only read), we can keep it direct if it's Sync.
    /// However, `Certificate` doesn't implement `Clone`, so we wrap it in Arc if we need to share it, but here it's owned by `CertificateAuthority`.
    ca_cert: Certificate,
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

        // Reconstruct CA certificate object
        // Note: We are assuming the CA DN is "lint-http CA".
        // If the user provides a custom CA, this might cause issuer mismatch in generated certs
        // unless we parse the DN from the PEM. For MVP, we assume standard lint-http CA.
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "lint-http CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "lint-http");
        params.key_pair = Some(key_pair);
        params.alg = &PKCS_ECDSA_P256_SHA256;

        let ca_cert = Certificate::from_params(params)?;

        Ok(Arc::new(Self {
            ca_cert_pem: cert_pem,
            ca_cert,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    async fn generate_and_save(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "lint-http CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "lint-http");
        params.alg = &PKCS_ECDSA_P256_SHA256;

        let cert = Certificate::from_params(params)?;
        let cert_pem = cert.serialize_pem()?;
        let key_pem = cert.serialize_private_key_pem();

        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::write(cert_path, &cert_pem).await?;
        fs::write(key_path, &key_pem).await?;

        // We need to reconstruct the certificate object because `cert` is consumed?
        // No, `serialize_pem` takes `&self`. So we can reuse `cert`.
        // But `Certificate` is not Clone.
        // So we can just return it.

        Ok(Arc::new(Self {
            ca_cert_pem: cert_pem,
            ca_cert: cert,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    /// Generates a leaf certificate for the given domain, signed by this CA.
    pub fn gen_cert_for_domain(&self, domain: &str) -> Result<Arc<rustls::sign::CertifiedKey>> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(cert) = cache.get(domain) {
                return Ok(cert.clone());
            }
        }

        // Generate new cert
        let mut params = CertificateParams::new(vec![domain.to_string()]);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);
        params.use_authority_key_identifier_extension = false;
        params.alg = &PKCS_ECDSA_P256_SHA256;

        // Create key pair for the leaf cert
        // Note: Certificate::from_params will generate a key pair if we don't provide one.
        // But we need to sign it with the CA.

        // rcgen 0.11: Certificate::from_params creates a self-signed cert (conceptually).
        // To sign it with a CA, we use `serialize_pem_with_signer`.

        let cert = Certificate::from_params(params)?;

        // Sign with CA
        let cert_pem = cert.serialize_pem_with_signer(&self.ca_cert)?;
        let key_pem = cert.serialize_private_key_pem();

        let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())?;
        let leaf_cert = RustlsCertificate(certs.into_iter().next().unwrap());

        let keys = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())?;
        let leaf_key = PrivateKey(keys.into_iter().next().unwrap());

        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(
            vec![leaf_cert],
            rustls::sign::any_supported_type(&leaf_key).unwrap(),
        ));

        // Update cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(domain.to_string(), certified_key.clone());
        }

        Ok(certified_key)
    }

    pub fn get_ca_cert_pem(&self) -> String {
        self.ca_cert_pem.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_generate_and_save_ca() {
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

        // Generate new CA
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path)
            .await
            .expect("failed to generate CA");

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
    }

    #[tokio::test]
    async fn test_load_existing_ca() {
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

        // First generate a CA
        let ca1 = CertificateAuthority::load_or_generate(&cert_path, &key_path)
            .await
            .expect("failed to generate CA");
        let pem1 = ca1.get_ca_cert_pem();

        // Now load it again (should load, not generate)
        let ca2 = CertificateAuthority::load_or_generate(&cert_path, &key_path)
            .await
            .expect("failed to load CA");
        let pem2 = ca2.get_ca_cert_pem();

        // Should have the same certificate
        assert_eq!(pem1, pem2);

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
    }

    #[tokio::test]
    async fn test_gen_cert_for_domain() {
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path)
            .await
            .expect("failed to generate CA");

        // Generate cert for domain
        let cert = ca
            .gen_cert_for_domain("example.com")
            .expect("failed to gen cert");

        // Verify it's not None and has certificates
        assert!(!cert.cert.is_empty());

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
    }

    #[tokio::test]
    async fn test_cert_cache_hit() {
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path)
            .await
            .expect("failed to generate CA");

        // Generate cert for domain first time
        let cert1 = ca
            .gen_cert_for_domain("example.com")
            .expect("failed to gen cert");

        // Generate cert for same domain second time (should use cache)
        let cert2 = ca
            .gen_cert_for_domain("example.com")
            .expect("failed to gen cert");

        // Should return the same Arc (same pointer)
        assert!(Arc::ptr_eq(&cert1, &cert2));

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
    }

    #[tokio::test]
    async fn test_multiple_domains() {
        let temp_dir = std::env::temp_dir();
        let test_id = Uuid::new_v4();
        let cert_path = temp_dir.join(format!("test_ca_{}.crt", test_id));
        let key_path = temp_dir.join(format!("test_ca_{}.key", test_id));

        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path)
            .await
            .expect("failed to generate CA");

        // Generate certs for different domains
        let cert1 = ca
            .gen_cert_for_domain("example.com")
            .expect("failed to gen cert");
        let cert2 = ca
            .gen_cert_for_domain("google.com")
            .expect("failed to gen cert");
        let cert3 = ca
            .gen_cert_for_domain("github.com")
            .expect("failed to gen cert");

        // Should all be different
        assert!(!Arc::ptr_eq(&cert1, &cert2));
        assert!(!Arc::ptr_eq(&cert1, &cert3));
        assert!(!Arc::ptr_eq(&cert2, &cert3));

        // Cleanup
        let _ = tokio::fs::remove_file(&cert_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
    }
}
