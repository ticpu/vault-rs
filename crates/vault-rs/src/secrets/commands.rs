use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;
use crate::vault::client::VaultClient;

/// List the enabled secret engines.
///
/// The mount listing and the verdict on whether this token may read it are
/// different answers: the checklist in `session status` reports the second
/// and this reports the first.
pub async fn list(output: &OutputFormat) -> Result<()> {
    let client = VaultClient::new().await?;

    // Asserting a permission verdict for what may be a refused connection,
    // and exiting 1 where 1 means a match, not an error.
    let mounts = client.list_mounts().await?;

    output.print_table(&mounts.as_table_data());
    Ok(())
}
