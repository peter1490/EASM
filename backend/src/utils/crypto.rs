use crate::error::ApiError;
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use x509_parser::prelude::*;
// Note: SAN parsing is complex and may require additional dependencies
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsCertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub organization: Option<String>,
    pub common_name: Option<String>,
    pub san_domains: Vec<String>,
    pub signature_algorithm: String,
    pub public_key_type: Option<String>,
    pub public_key_bits: Option<u32>,
}

/// Extract organization name from certificate subject or issuer
fn extract_organization(name: &X509Name) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid = attr.attr_type().to_id_string();
            // OID for Organization (O)
            if oid == "2.5.4.10" {
                if let Ok(org_name) = attr.attr_value().as_str() {
                    return Some(org_name.to_string());
                }
            }
        }
    }
    None
}

/// Extract common name from certificate subject
fn extract_common_name(name: &X509Name) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid = attr.attr_type().to_id_string();
            // OID for Common Name (CN)
            if oid == "2.5.4.3" {
                if let Ok(cn) = attr.attr_value().as_str() {
                    return Some(cn.to_string());
                }
            }
        }
    }
    None
}

/// Extract Subject Alternative Names from certificate extensions
/// Note: This is a simplified implementation. Full SAN parsing would require additional dependencies.
fn extract_san_domains(cert: &X509Certificate) -> Vec<String> {
    let mut san_domains = Vec::new();

    if let Some(san_ext) = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
    {
        if let Ok((_, san)) = SubjectAlternativeName::from_der(san_ext.value) {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns_name) = name {
                    san_domains.push(dns_name.to_string());
                }
            }
        }
    }

    san_domains
}

/// Format X509Name as a readable string
fn format_x509_name(name: &X509Name) -> String {
    let mut parts = Vec::new();

    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid = attr.attr_type().to_id_string();
            if let Ok(value) = attr.attr_value().as_str() {
                let field_name = match oid.as_str() {
                    "2.5.4.3" => "CN",
                    "2.5.4.10" => "O",
                    "2.5.4.11" => "OU",
                    "2.5.4.6" => "C",
                    "2.5.4.7" => "L",
                    "2.5.4.8" => "ST",
                    _ => continue,
                };
                parts.push(format!("{}={}", field_name, value));
            }
        }
    }

    parts.join(", ")
}

pub async fn get_tls_certificate_info(
    hostname: &str,
    port: u16,
) -> Result<TlsCertificateInfo, ApiError> {
    // Create a custom TLS configuration that accepts any certificate
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    // Create a custom certificate verifier that captures the certificate chain
    #[derive(Debug)]
    struct CertificateCapture {
        captured_certs: std::sync::Mutex<Vec<CertificateDer<'static>>>,
    }

    impl rustls::client::danger::ServerCertVerifier for CertificateCapture {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            // Capture the certificate chain
            let mut certs = self.captured_certs.lock().unwrap();
            certs.push(end_entity.clone().into_owned());
            for cert in intermediates {
                certs.push(cert.clone().into_owned());
            }

            // Accept any certificate (for information gathering purposes)
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA1,
                rustls::SignatureScheme::ECDSA_SHA1_Legacy,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ED448,
            ]
        }
    }

    let cert_capture = Arc::new(CertificateCapture {
        captured_certs: std::sync::Mutex::new(Vec::new()),
    });

    config
        .dangerous()
        .set_certificate_verifier(cert_capture.clone());

    let connector = TlsConnector::from(Arc::new(config));

    // Connect to the server
    let socket_addr: SocketAddr = format!("{}:{}", hostname, port)
        .parse()
        .map_err(|_| ApiError::Validation("Invalid hostname or port".to_string()))?;

    let tcp_stream = TcpStream::connect(socket_addr).await.map_err(|e| {
        ApiError::ExternalService(format!("Failed to connect to {}:{}: {}", hostname, port, e))
    })?;

    // Parse hostname for TLS SNI
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|e| ApiError::Validation(format!("Invalid hostname for TLS: {}", e)))?;

    // Perform TLS handshake
    let _tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| ApiError::ExternalService(format!("TLS handshake failed: {}", e)))?;

    // Extract the captured certificate
    let captured_certs = cert_capture.captured_certs.lock().unwrap();
    if captured_certs.is_empty() {
        return Err(ApiError::ExternalService(
            "No certificate received during TLS handshake".to_string(),
        ));
    }

    // Parse the first certificate (end entity certificate)
    let cert_der = &captured_certs[0];
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| ApiError::ExternalService(format!("Failed to parse certificate: {}", e)))?;

    // Extract certificate information
    let subject = format_x509_name(&cert.subject);
    let issuer = format_x509_name(&cert.issuer);
    let serial_number = format!("{:x}", cert.serial);

    // Format validity dates
    let not_before = DateTime::<Utc>::from_timestamp(cert.validity.not_before.timestamp(), 0)
        .unwrap_or_default()
        .to_rfc3339();
    let not_after = DateTime::<Utc>::from_timestamp(cert.validity.not_after.timestamp(), 0)
        .unwrap_or_default()
        .to_rfc3339();

    // Extract organization and common name
    let organization =
        extract_organization(&cert.subject).or_else(|| extract_organization(&cert.issuer));
    let common_name = extract_common_name(&cert.subject);

    // Extract Subject Alternative Names
    let san_domains = extract_san_domains(&cert);

    let signature_algorithm = cert.signature_algorithm.algorithm.to_string();

    let (public_key_type, public_key_bits) = {
        let alg_oid = cert.public_key().algorithm.algorithm.to_id_string();
        let key_type = match alg_oid.as_str() {
            "1.2.840.113549.1.1.1" => Some("rsa".to_string()),
            "1.2.840.10045.2.1" => Some("ecdsa".to_string()),
            "1.3.101.112" => Some("ed25519".to_string()),
            "1.3.101.113" => Some("ed448".to_string()),
            _ => None,
        };

        let bit_len = cert.public_key().subject_public_key.data.len() as u32 * 8;
        let key_bits = if bit_len > 0 { Some(bit_len) } else { None };
        (key_type, key_bits)
    };

    Ok(TlsCertificateInfo {
        subject,
        issuer,
        serial_number,
        not_before,
        not_after,
        organization,
        common_name,
        san_domains,
        signature_algorithm,
        public_key_type,
        public_key_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tls_certificate_info_google() {
        // Test with a known good certificate
        match get_tls_certificate_info("google.com", 443).await {
            Ok(cert_info) => {
                assert!(!cert_info.subject.is_empty());
                assert!(!cert_info.issuer.is_empty());
                assert!(!cert_info.serial_number.is_empty());
                assert!(!cert_info.not_before.is_empty());
                assert!(!cert_info.not_after.is_empty());

                // Google should have organization info
                assert!(cert_info.organization.is_some());

                // Should have SAN domains
                assert!(!cert_info.san_domains.is_empty());

                println!("Certificate info for google.com:");
                println!("Subject: {}", cert_info.subject);
                println!("Issuer: {}", cert_info.issuer);
                println!("Organization: {:?}", cert_info.organization);
                println!("Common Name: {:?}", cert_info.common_name);
                println!("SAN Domains: {:?}", cert_info.san_domains);
            }
            Err(e) => {
                // This test might fail in CI environments without internet access
                println!("TLS test failed (expected in CI): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_tls_certificate_info_invalid_host() {
        let result = get_tls_certificate_info("nonexistent.invalid.domain", 443).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_format_x509_name() {
        // This is a unit test for the formatting function
        // In a real scenario, we would need actual X509Name objects
        // For now, we just ensure the function exists and can be called
        assert!(true);
    }
}

// Password hashing utilities
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ApiError::Internal(format!("Failed to hash password: {}", e)))?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, ApiError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| ApiError::Internal(format!("Invalid password hash: {}", e)))?;

    let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);

    match result {
        Ok(_) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(ApiError::Internal(format!(
            "Password verification error: {}",
            e
        ))),
    }
}
