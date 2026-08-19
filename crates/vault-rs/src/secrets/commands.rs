use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;
use crate::vault::mounts::{MountInfo, MountsResponse};

/// List the enabled secret engines.
///
/// The mount listing and the verdict on whether this token may read it are
/// different answers: the checklist in `session status` reports the second
/// and this reports the first.
pub async fn list(output: &OutputFormat) -> Result<()> {
    let client = crate::vault::operator_client().await?;

    let mounts = client.list_mounts().await?;

    output.print_table(&as_table_data(&mounts));
    Ok(())
}

fn as_table_data(mounts: &MountsResponse) -> Vec<Vec<String>> {
    let mut rows: Vec<_> = mounts.data.iter().collect();
    rows.sort_by_key(|(path, _)| *path);

    rows.iter()
        .map(|(path, info)| vec![path.trim_end_matches('/').to_string(), display_name(info)])
        .collect()
}

/// A KV mount's layout is part of what distinguishes it, since the two address
/// a secret through different prefixes; every other engine has only its type.
fn display_name(info: &MountInfo) -> String {
    match info.is_kv() {
        true => format!("{} v{}", info.mount_type, info.get_version().unwrap_or("1")),
        false => info.mount_type.clone(),
    }
}
