// The binary installs no rustls provider, so it needs the backend that installs
// itself. `rustls-ring` is for a dependent whose own process does that, and a
// binary built on it panics inside rustls at the first request.
#[cfg(not(feature = "rustls-aws-lc-rs"))]
compile_error!(
    "the vault-rs binary needs the `rustls-aws-lc-rs` backend; `rustls-ring` leaves the process \
     to install a rustls provider, and this one installs none"
);

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
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
            || e.downcast_ref::<vault_rs::utils::errors::VaultCliError>()
                .is_some_and(vault_rs::utils::errors::VaultCliError::is_broken_pipe);
        if broken_pipe {
            std::process::exit(0);
        }

        // `{:#}` prints every cause in the chain, not just the top.
        eprintln!("Error: {e:#}");
        std::process::exit(2);
    }
}
