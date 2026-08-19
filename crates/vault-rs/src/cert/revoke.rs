use crate::utils::errors::Result;
use crate::utils::prompt::confirm;
use crate::vault::client::VaultClient;
use crate::vault::PkiClient;

pub struct RevokeRequest {
    pub identifier: String,
    pub pki_mount: Option<String>,
    pub yes: bool,
}

pub async fn revoke_certificate(client: &VaultClient, request: RevokeRequest) -> Result<()> {
    use crate::cert::lookup::find_certificate_by_identifier;

    // Find the certificate first
    let (_cert_pem, serial, mount) =
        find_certificate_by_identifier(client, &request.identifier, request.pki_mount.as_deref())
            .await?;

    eprintln!("Revoking certificate serial: {serial}");
    eprintln!("PKI mount: {mount}");

    confirm(
        &format!("Revoke certificate serial {serial} in {mount}?"),
        request.yes,
    )?;

    // Revoke the certificate
    tracing::debug!("Trying to revoke with serial {serial}");
    match client.revoke_certificate(&mount, &serial).await {
        Ok(_) => {
            eprintln!("✓ Certificate revoked successfully");
            Ok(())
        }
        Err(e) => {
            tracing::debug!("Revocation failed for '{serial}': {e}");
            Err(e)
        }
    }
}
