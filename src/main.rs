use vault_rs::cli::{handle_command, Cli};
use vault_rs::utils::errors::Result;

#[tokio::main]
async fn main() -> Result<()> {
    use clap::Parser;
    let cli = Cli::parse();

    if let Err(e) = handle_command(cli).await {
        // Handle broken pipe errors gracefully (e.g., when piping to head)
        if let vault_rs::utils::errors::VaultCliError::Io(io_err) = &e {
            if io_err.kind() == std::io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
        }
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    Ok(())
}
