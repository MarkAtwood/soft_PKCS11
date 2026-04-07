// build.rs
// Link libudev via pkg-config. Fail fast with a clear error if not found.
fn main() {
    pkg_config::Config::new()
        .atleast_version("204")
        .probe("libudev")
        .expect("libudev not found. Install libudev-dev (Debian) or systemd-devel (Fedora).");
}
