use crate::cert::{CertificateService, SerialNumber};
use crate::utils::errors::{Result, VaultCliError};
use crate::vault::client::VaultClient;

/// Format hex serial number with colons (e.g., "46a891..." -> "46:a8:91:...")
pub fn format_serial_with_colons(serial: &str) -> String {
    serial
        .chars()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(":")
}

/// Find certificate by identifier (CN or serial)
/// Returns (certificate_pem, serial, pki_mount)
pub async fn find_certificate_by_identifier(
    client: &VaultClient,
    identifier: &str,
    pki_mount_filter: Option<&str>,
) -> Result<(String, SerialNumber, String)> {
    // Check if identifier looks like a serial number (hex string, typically 30+ chars)
    let serial = SerialNumber::parse(identifier);
    let pki_mounts = if let Some(mount) = pki_mount_filter {
        vec![mount.to_string()]
    } else {
        client.list_pki_mounts().await?
    };

    if let Ok(serial) = serial {
        // Try to find certificate by serial across all PKI mounts
        for mount in &pki_mounts {
            // Try both formats: raw hex and colon-separated hex

            tracing::trace!("Trying to find serial {serial} in mount {mount}");
            match client.get_certificate_pem(mount, &serial).await {
                Ok(cert_data) => {
                    tracing::debug!("Found certificate with serial {serial} in mount {mount}");
                    return Ok((
                        cert_data.certificate,
                        SerialNumber::new(identifier),
                        mount.clone(),
                    ));
                }
                Err(e) => {
                    tracing::trace!("Failed to find serial {serial} in mount {mount}: {e}");
                    continue;
                }
            }
        }

        Err(VaultCliError::CertNotFound(format!(
            "Certificate with serial '{}' not found{}",
            identifier,
            if let Some(mount) = pki_mount_filter {
                format!(" in PKI mount '{mount}'")
            } else {
                " in any PKI mount".to_string()
            }
        )))
    } else {
        // Search by CN - find latest certificate with matching CN
        tracing::debug!("Searching for certificate by CN: '{}'", identifier);
        let cert_service = CertificateService::new().await?;
        let mut matching_certs = Vec::new();

        for mount in &pki_mounts {
            tracing::debug!("Searching for CN '{}' in mount '{}'", identifier, mount);
            match cert_service
                .list_certificates_with_metadata(Some(mount))
                .await
            {
                Ok(certificates) => {
                    tracing::debug!(
                        "Found {} certificates in mount '{}'",
                        certificates.len(),
                        mount
                    );
                    for cert in certificates {
                        tracing::trace!("Checking certificate CN: '{}'", cert.cn);
                        if cert.cn == identifier {
                            tracing::debug!(
                                "Found matching certificate: {} (serial: {})",
                                cert.cn,
                                cert.serial
                            );
                            matching_certs.push((cert, mount.clone()));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to list certificates in mount {}: {}", mount, e);
                    continue;
                }
            }
        }

        if matching_certs.is_empty() {
            return Err(VaultCliError::CertNotFound(format!(
                "No certificate found with CN '{}'{}",
                identifier,
                if let Some(mount) = pki_mount_filter {
                    format!(" in PKI mount '{mount}'")
                } else {
                    " in any PKI mount".to_string()
                }
            )));
        }

        // Sort by not_after date (newest first) and take the latest
        matching_certs.sort_by(|a, b| b.0.not_after.cmp(&a.0.not_after));
        let (latest_cert, mount) = &matching_certs[0];

        // Fetch the PEM data for the latest certificate
        let cert_data = client
            .get_certificate_pem(mount, &latest_cert.serial)
            .await?;

        tracing::debug!(
            "Found latest certificate for CN '{}': serial {} in mount {}",
            identifier,
            latest_cert.serial,
            mount
        );

        Ok((
            cert_data.certificate,
            latest_cert.serial.clone(),
            mount.clone(),
        ))
    }
}
