use vault_rs::cli::{handle_command, Cli};

#[tokio::main]
async fn main() {
    use clap::Parser;
    let cli = Cli::parse();

    if let Err(e) = handle_command(cli).await {
        // Piping into head closes the pipe under us; that is the reader's
        // choice, not a failure of this command.
        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
        }
        if let Some(vault_rs::utils::errors::VaultCliError::Io(io_err)) =
            e.downcast_ref::<vault_rs::utils::errors::VaultCliError>()
        {
            if io_err.kind() == std::io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
        }

        // `{:#}` prints every cause: a refused connection, an expired server
        // certificate and a name that does not resolve otherwise render as
        // the same line.
        eprintln!("Error: {e:#}");
        std::process::exit(2);
    }
}
