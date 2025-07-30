use vault_rs::cli::{handle_command, Cli};
use vault_rs::utils::errors::Result;

#[tokio::main]
async fn main() -> Result<()> {
    use clap::Parser;
    let cli = Cli::parse();

    if let Err(e) = handle_command(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    Ok(())
}
