use vault_rs::cli::{handle_command, Cli};

#[tokio::main]
async fn main() {
    // Rust masks SIGPIPE, so a reader that goes away (`| head`) turns the next
    // write into EPIPE, and whichever writer hits it first panics — including
    // ones inside dependencies, which no error handling here can intercept.
    // Restoring the default disposition ends the process quietly, as every
    // other Unix tool does: the reader closing the pipe is its choice.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    use clap::Parser;
    let cli = Cli::parse();

    if let Err(e) = handle_command(cli).await {
        // Still reachable for a write that reports EPIPE without raising the
        // signal, which is not the `| head` case above.
        let broken_pipe = e
            .downcast_ref::<std::io::Error>()
            .or_else(
                || match e.downcast_ref::<vault_rs::utils::errors::VaultCliError>() {
                    Some(vault_rs::utils::errors::VaultCliError::Io(io)) => Some(io),
                    _ => None,
                },
            )
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe);
        if broken_pipe {
            std::process::exit(0);
        }

        // `{:#}` prints every cause: a refused connection, an expired server
        // certificate and a name that does not resolve otherwise render as
        // the same line.
        eprintln!("Error: {e:#}");
        std::process::exit(2);
    }
}
