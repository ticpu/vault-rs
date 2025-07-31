use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;
use crate::vault::client::VaultClient;

pub async fn show_certificate(
    client: &VaultClient,
    identifier: &str,
    pki_mount: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    use crate::cert::{find_certificate_by_identifier, CertificateParser};

    let (pem, _serial, mount) =
        find_certificate_by_identifier(client, identifier, pki_mount).await?;

    let metadata = CertificateParser::parse_pem(&pem, &mount)?;

    // Use OutputFormat to handle raw vs formatted output properly
    let cert_data = vec![vec![
        metadata.cn,
        metadata.serial,
        metadata.not_before.format("%Y-%m-%d %H:%M").to_string(),
        metadata.not_after.format("%Y-%m-%d %H:%M").to_string(),
        metadata.sans.join(","),
        mount,
    ]];

    output.print_table(&cert_data);
    Ok(())
}
