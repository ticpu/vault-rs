//! Showing an operator the authorization URL, which is this tool's job rather
//! than the library's: a program linking it may have no terminal, no browser
//! and no business launching one.

use std::env;
use vault_session::{LoginPresenter, Result};

/// Prints the URL and, unless told not to, asks the desktop to open it.
pub struct Console {
    pub open_browser: bool,
}

impl LoginPresenter for Console {
    fn present(&self, auth_url: &str) -> Result<()> {
        // Printed whether or not a browser is launched, so a session that has
        // none is an ordinary case rather than a failure.
        eprintln!("Open this URL to authenticate:\n\n{auth_url}\n");

        if self.open_browser {
            open_in_browser(auth_url);
        }
        Ok(())
    }
}

/// A launcher that is absent or refuses costs nothing: the URL is already on
/// stderr.
fn open_in_browser(url: &str) {
    // Without a display `xdg-open` reaches for a terminal browser, which takes
    // over the terminal this login is reporting to.
    if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("No display session; open the URL above yourself.");
        return;
    }

    if let Err(e) = std::process::Command::new("xdg-open").arg(url).spawn() {
        eprintln!("Could not launch a browser with xdg-open ({e}); open the URL above yourself.");
    }
}
