use crate::utils::errors::Result;
use crate::vault::client::VaultClient;

pub struct RevokeRequest {
    pub identifier: String,
    pub pki_mount: Option<String>,
}

pub async fn revoke_certificate(
    client: &VaultClient,
    token: &str,
    request: RevokeRequest,
) -> Result<()> {
    use crate::cert::lookup::find_certificate_by_identifier;

    // Find the certificate first
    let (serial, mount, _cn) = find_certificate_by_identifier(
        client,
        token,
        &request.identifier,
        request.pki_mount.as_deref(),
    )
    .await?;

    eprintln!("Revoking certificate serial: {serial}");
    eprintln!("PKI mount: {mount}");

    // Revoke the certificate
    client.revoke_certificate(token, &mount, &serial).await?;
    eprintln!("✓ Certificate revoked successfully");

    Ok(())
}
