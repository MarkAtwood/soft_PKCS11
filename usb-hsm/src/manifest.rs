//! `.usb-hsm` manifest -- opt-in registry of `.p11k` keystore files on a USB drive.
//!
//! When a USB drive is inserted, the library stats `<mount_point>/<manifest_name>`
//! instead of scanning the directory. This makes rejection of non-token drives a
//! single `stat(2)` call rather than a full directory enumeration.
//!
//! # Format
//!
//! Plain text, one entry per line:
//!
//! ```text
//! # .usb-hsm -- usb-hsm token manifest
//! signing.p11k My Signing Token
//! auth.p11k    Authentication
//! ```
//!
//! - **filename** -- basename of the `.p11k` file; no directory separators allowed
//! - **label** -- rest of the line after the first whitespace; human-readable slot name
//! - Lines starting with `#` (optionally preceded by whitespace) and blank lines are ignored
//! - Line order determines slot assignment: line 1 -> slot 0, line 2 -> slot 1, etc.
//!
//! The default manifest filename is `.usb-hsm`. It can be overridden per-device via
//! the `USB_HSM_MANIFEST` udev property (set in udev rules).

/// Default manifest filename at the root of a USB drive.
pub const DEFAULT_MANIFEST_NAME: &str = ".usb-hsm";

/// One entry in a `.usb-hsm` manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Basename of the `.p11k` file (no directory components).
    pub filename: String,
    /// Human-readable label for this slot.
    pub label: String,
}

/// Parse manifest text into a list of [`ManifestEntry`] values.
///
/// Lines starting with `#` (optionally preceded by whitespace) and blank lines
/// are skipped. Each remaining line must begin with the filename followed by
/// whitespace and the label (rest of line, trimmed). Lines with no whitespace
/// after the filename receive an empty label.
pub fn parse_manifest(content: &str) -> Vec<ManifestEntry> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let mut parts = trimmed.splitn(2, |c: char| c.is_ascii_whitespace());
            let filename = parts.next()?.to_string();
            if filename.is_empty() {
                return None;
            }
            let label = parts.next().map(|s| s.trim().to_string()).unwrap_or_default();
            Some(ManifestEntry { filename, label })
        })
        .collect()
}

/// Serialize a list of entries to manifest text (one `<filename> <label>` per line).
///
/// Does not append a trailing newline.
pub fn format_manifest(entries: &[ManifestEntry]) -> String {
    entries
        .iter()
        .map(|e| format!("{} {}", e.filename, e.label))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Return `content` with the entry for `filename` updated to `label`, or with a
/// new `<filename> <label>` line appended if no matching entry exists.
///
/// Comment lines and blank lines are preserved in place.
pub fn upsert_entry(content: &str, filename: &str, label: &str) -> String {
    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return line.to_string();
            }
            let first = trimmed.split_ascii_whitespace().next().unwrap_or("");
            if first == filename {
                found = true;
                format!("{filename} {label}")
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.push(format!("{filename} {label}"));
    }

    lines.join("\n")
}

/// Return `content` with every line whose filename matches `filename` removed.
///
/// If no matching entry exists the content is returned unchanged.
pub fn remove_entry(content: &str, filename: &str) -> String {
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return true;
            }
            trimmed.split_ascii_whitespace().next().unwrap_or("") != filename
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_entries() {
        let content = "signing.p11k My Signing Token\nauth.p11k Authentication\n";
        let entries = parse_manifest(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename, "signing.p11k");
        assert_eq!(entries[0].label, "My Signing Token");
        assert_eq!(entries[1].filename, "auth.p11k");
        assert_eq!(entries[1].label, "Authentication");
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let content = "# comment\n\nsigning.p11k Key\n# another\nauth.p11k Auth\n";
        let entries = parse_manifest(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename, "signing.p11k");
        assert_eq!(entries[1].filename, "auth.p11k");
    }

    #[test]
    fn parse_empty_content_returns_empty() {
        assert!(parse_manifest("").is_empty());
    }

    #[test]
    fn parse_only_comments_returns_empty() {
        assert!(parse_manifest("# comment\n# another\n").is_empty());
    }

    #[test]
    fn parse_label_with_spaces() {
        let entries = parse_manifest("token.p11k My USB Token Label\n");
        assert_eq!(entries[0].label, "My USB Token Label");
    }

    #[test]
    fn parse_leading_whitespace_on_comment_line() {
        let entries = parse_manifest("   # indented comment\ntoken.p11k T\n");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn upsert_appends_new_entry_to_non_empty_content() {
        let content = "existing.p11k Existing\n";
        let result = upsert_entry(content, "new.p11k", "New Label");
        let entries = parse_manifest(&result);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].filename, "new.p11k");
        assert_eq!(entries[1].label, "New Label");
    }

    #[test]
    fn upsert_updates_existing_entry_label() {
        let content = "signing.p11k Old Label\n";
        let result = upsert_entry(content, "signing.p11k", "New Label");
        let entries = parse_manifest(&result);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].label, "New Label");
    }

    #[test]
    fn upsert_on_empty_content() {
        let result = upsert_entry("", "first.p11k", "First");
        let entries = parse_manifest(&result);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "first.p11k");
        assert_eq!(entries[0].label, "First");
    }

    #[test]
    fn upsert_preserves_comments_and_blanks() {
        let content = "# header comment\n\nexisting.p11k E\n";
        let result = upsert_entry(content, "new.p11k", "N");
        let entries = parse_manifest(&result);
        assert_eq!(entries.len(), 2);
        // Comment and blank line must still be present in the output text.
        assert!(result.contains("# header comment"));
    }

    #[test]
    fn remove_existing_entry() {
        let content = "signing.p11k Signing\nauth.p11k Auth\n";
        let result = remove_entry(content, "signing.p11k");
        let entries = parse_manifest(&result);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "auth.p11k");
    }

    #[test]
    fn remove_nonexistent_entry_unchanged() {
        let content = "signing.p11k Signing\n";
        let result = remove_entry(content, "nonexistent.p11k");
        assert_eq!(parse_manifest(&result).len(), 1);
    }

    #[test]
    fn format_manifest_roundtrip() {
        let entries = vec![
            ManifestEntry { filename: "a.p11k".into(), label: "Alpha".into() },
            ManifestEntry { filename: "b.p11k".into(), label: "Beta".into() },
        ];
        let text = format_manifest(&entries);
        let parsed = parse_manifest(&text);
        assert_eq!(parsed, entries);
    }
}
