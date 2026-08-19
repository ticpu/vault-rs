//! Confirmation prompts for writes to a certificate authority (see
//! docs/design-rationale.md, "Writes to a certificate authority are
//! rehearsed; reads are not").

use crate::utils::errors::{Result, VaultCliError};
use std::io::{self, IsTerminal, Write};

/// Ask for confirmation before a write, on stderr since it is for a person,
/// not data. `assume_yes` (`--yes`) skips the prompt outright. Without it, a
/// non-interactive stdin errors rather than blocking on a question nobody can
/// see or answer.
pub fn confirm(message: &str, assume_yes: bool) -> Result<()> {
    if assume_yes {
        return Ok(());
    }

    if !io::stdin().is_terminal() {
        return Err(VaultCliError::InvalidInput(format!(
            "{message} needs confirmation, and stdin is not a terminal; pass --yes to proceed"
        )));
    }

    eprint!("{message} [y/N] ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    if matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(VaultCliError::InvalidInput(
            "aborted: not confirmed".to_string(),
        ))
    }
}
