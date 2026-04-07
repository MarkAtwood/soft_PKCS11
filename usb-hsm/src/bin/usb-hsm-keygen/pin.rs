/// Hidden PIN prompt helpers for usb-hsm-keygen.
///
/// When stdin is a TTY, `rpassword` reads from `/dev/tty` so the PIN never
/// appears on screen. When stdin is not a TTY (scripted / piped use), a plain
/// line is read from stdin -- the caller owns the pipe and is responsible for
/// not logging it.
use std::io::{self, IsTerminal, Write};

const MIN_PIN_LEN: usize = 6;

/// Read one PIN: suppress echo if stdin is a TTY, otherwise read a plain line
/// from stdin.  Prints `prompt` to stderr either way.
fn read_once(prompt: &str) -> io::Result<String> {
    if io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)
    } else {
        eprint!("{prompt}");
        io::stderr().flush()?;
        // io::stdin() shares one global buffered reader; read_line is safe
        // across multiple calls unlike creating a new BufReader each time.
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches('\n').trim_end_matches('\r').to_string())
    }
}

/// Prompt for an existing PIN once.  Used for `key-add`, `key-remove`, and
/// the old-PIN half of `pin-change` where no confirmation is needed.
pub fn prompt_pin(prompt: &str) -> io::Result<Vec<u8>> {
    Ok(read_once(prompt)?.into_bytes())
}

/// Prompt for a passphrase for key decryption (e.g. encrypted PKCS#8).
/// Uses the same TTY-safe behaviour as [`prompt_pin`]: reads from `/dev/tty`
/// when stdin is a TTY, otherwise from stdin (for scripted/piped use).
pub fn prompt_passphrase(prompt: &str) -> io::Result<String> {
    read_once(prompt)
}

/// Prompt for a new PIN, enforce the minimum length, and ask again to
/// confirm.  Loops until the user enters a valid, matching pair.
/// Returns the PIN as bytes.
///
/// Used for `create` and the new-PIN half of `pin-change`.
pub fn prompt_new_pin() -> io::Result<Vec<u8>> {
    loop {
        let pin = read_once("Enter new PIN: ")?;
        if pin.len() < MIN_PIN_LEN {
            eprintln!(
                "PIN must be at least {MIN_PIN_LEN} characters. Try again."
            );
            continue;
        }
        let confirm = read_once("Confirm new PIN: ")?;
        if pin != confirm {
            eprintln!("PINs do not match. Try again.");
            continue;
        }
        return Ok(pin.into_bytes());
    }
}
