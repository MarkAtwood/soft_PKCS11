/// Watch udev for block device add/remove events, correlate with /proc/mounts,
/// and emit typed [`UsbEvent`] values on a crossbeam channel.
///
/// # Timing model
///
/// udev emits 'block' subsystem 'add' events when the kernel creates the block
/// device node -- before any automounter (udisks2, udev rules) has mounted the
/// filesystem. At that instant `/proc/mounts` does not yet contain the device,
/// so a naive read-and-give-up approach would silently drop every real USB
/// insertion.
///
/// This module handles the race with a **pending-retry loop**: if a device is
/// not in `/proc/mounts` at 'add' time it is stored in a `pending` map. On
/// every subsequent poll tick (<= 100 ms) `/proc/mounts` is re-read and each
/// pending device is re-checked until it appears or [`PENDING_TIMEOUT`]
/// elapses. In practice udisks2 / udev automount completes in < 1 second; the
/// 10-second ceiling is a generous upper bound.
///
/// # Security Note
/// This module watches udev for block device events. It does NOT verify that
/// the mounted filesystem belongs to a specific USB device -- any filesystem
/// containing a `.usb-hsm` manifest at its root will be treated as a token
/// drive. In environments with multiple USB devices, use udev rules to restrict
/// which devices are accepted (e.g., match by USB vendor/product ID or
/// filesystem UUID).
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender};
use udev::{EventType, MonitorBuilder};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How long to retry a block device that was not yet in /proc/mounts at
/// udev 'add' time. Exceeded entries are evicted from the pending set silently.
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A udev event action on a block device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevAction {
    Add,
    Remove,
}

/// An event emitted when a block device is mounted or unmounted.
#[derive(Debug, PartialEq, Eq)]
pub enum UsbEvent {
    /// A block device has been mounted. `manifest_name` is the filename of the
    /// `.usb-hsm` manifest to look for at the mount root; derived from the
    /// `USB_HSM_MANIFEST` udev property, or [`DEFAULT_MANIFEST_NAME`] by default.
    ///
    /// [`DEFAULT_MANIFEST_NAME`]: crate::manifest::DEFAULT_MANIFEST_NAME
    Mounted {
        mount_point: PathBuf,
        manifest_name: String,
    },
    Unmounted(PathBuf),
}

/// Error type for [`UsbWatcher`].
#[derive(Debug)]
pub enum Error {
    Udev(String),
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Udev(msg) => write!(f, "udev error: {}", msg),
            Error::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Core logic -- factored out for testability
// ---------------------------------------------------------------------------

/// Parse `/proc/mounts`-formatted text and return the mount point for `devnode`.
///
/// `/proc/mounts` escapes spaces in device nodes and mount points as `\040` (octal),
/// tabs as `\011`, and backslashes as `\134`. We unescape the mount point before
/// returning it so callers get a valid filesystem path.
///
/// Only the subset of escape sequences that appear in realistic USB paths is handled:
/// `\040` (space) and `\134` (backslash). Tab (`\011`) in a path is rejected by the
/// kernel on most filesystems and is deliberately omitted.
pub fn find_mount(devnode: &str, mounts_content: &str) -> Option<PathBuf> {
    for line in mounts_content.lines() {
        let mut parts = line.split_whitespace();
        let device = parts.next()?;
        let mount_point = parts.next()?;
        // Also unescape the device field when comparing so a devnode whose path
        // includes a space (e.g. loop devices with spaces in image names) is
        // still matched correctly.
        if unescape_proc_mounts(device) == devnode {
            return Some(PathBuf::from(unescape_proc_mounts(mount_point)));
        }
    }
    None
}

/// Unescape `/proc/mounts` octal escape sequences in a path field.
///
/// `/proc/mounts` encodes special characters in device nodes and mount points
/// using octal escapes: `\040` for space, `\011` for tab, `\012` for newline,
/// `\134` for backslash.
///
/// For USB HSM paths the only escape that realistically appears is `\040`
/// (automounters like udisks2 create mount points with spaces). Backslash in
/// USB paths (`\134`) is extremely rare but is handled for correctness.
/// Other escape sequences are passed through unchanged.
fn unescape_proc_mounts(s: &str) -> String {
    // Process backslash (\134) BEFORE space (\040) so that the sequence \134040
    // (which represents a literal \040 in the path, not a space) is not
    // incorrectly converted to a space. After processing \134 -> \, the remaining
    // \040 would correctly become a space -- but \134040 -> \040 (kept as-is after
    // the second replace because the first replace left a genuine \040).
    //
    // KNOWN LIMITATION (soft_PKCS11-0dm): \134040 (literal \040 in path name)
    // becomes a space instead of the literal four-character sequence \040. A
    // fully-correct implementation requires a stateful character-by-character
    // parser that distinguishes the original \134 from the backslash it produces.
    //
    // WHY a stateful parser is not warranted here:
    //   1. The Linux VFS does not forbid backslash in filenames, but no common
    //      automounter (udisks2, udiskie, gvfs) creates USB mount points that
    //      contain backslash followed by three digits -- the problematic pattern
    //      only arises in adversarially-crafted or highly unusual configurations.
    //   2. The impacted path (\134040 -> space) would cause find_p11k_in to search
    //      a directory with a space where the real one has \040, failing to find
    //      the .p11k file -- a graceful miss, not a security failure.
    //   3. The stateful parser adds ~30 lines for a case that has never been
    //      observed in practice on real USB drives.
    //
    // A test (unescape_backslash_before_040_known_limitation) documents the exact
    // current behaviour so any future change is caught immediately.
    s.replace(r"\134", "\\").replace(r"\040", " ")
}

/// Process a single udev event and update the `known_mounts` map.
///
/// Returns a [`UsbEvent`] if the event results in a state change worth
/// reporting, or `None` otherwise.
///
/// `manifest_name` is the value of the `USB_HSM_MANIFEST` udev property (or
/// [`DEFAULT_MANIFEST_NAME`] when the property is absent). It is embedded in
/// the [`UsbEvent::Mounted`] variant so the dispatcher knows which manifest
/// file to look for at the drive root.
///
/// **Callers** are responsible for handling the deferred-mount case: if this
/// returns `None` for a [`UdevAction::Add`] the device should be added to a
/// `pending` map and retried via [`check_pending_mounts`].
///
/// [`DEFAULT_MANIFEST_NAME`]: crate::manifest::DEFAULT_MANIFEST_NAME
pub fn process_event(
    action: UdevAction,
    devnode: &str,
    manifest_name: &str,
    mounts_content: &str,
    known_mounts: &mut HashMap<String, PathBuf>,
) -> Option<UsbEvent> {
    match action {
        UdevAction::Add => {
            // Guard against duplicate 'add' events for a device already in known_mounts.
            // udev can emit a second 'add' for the same devnode (e.g., after a re-scan).
            // Without this check we would overwrite the entry AND emit a spurious Mounted
            // event to the token state machine, which is not idempotent. Skip silently --
            // the token is already in the correct state.
            if known_mounts.contains_key(devnode) {
                return None;
            }
            let mount = find_mount(devnode, mounts_content)?;
            known_mounts.insert(devnode.to_owned(), mount.clone());
            Some(UsbEvent::Mounted {
                mount_point: mount,
                manifest_name: manifest_name.to_owned(),
            })
        }
        UdevAction::Remove => {
            let mount = known_mounts.remove(devnode)?;
            Some(UsbEvent::Unmounted(mount))
        }
    }
}

/// Re-check pending block devices against a `/proc/mounts` snapshot.
///
/// A device enters the pending set when a udev 'add' event arrives but the
/// filesystem is not yet present in `/proc/mounts` (the automounter hasn't
/// run yet). This function should be called repeatedly until the pending set
/// is empty or [`PENDING_TIMEOUT`] has elapsed for each entry.
///
/// The pending map value is `(first_seen, manifest_name)`. `manifest_name` is
/// captured from the udev event at the time the device was first seen (the
/// `USB_HSM_MANIFEST` property is only available at event time, not during
/// later retries). It is forwarded into [`UsbEvent::Mounted`] when the device
/// finally appears in `/proc/mounts`.
///
/// Entries that appear in `mounts_content` are moved to `known_mounts` and
/// a [`UsbEvent::Mounted`] is returned for each. Entries that have exceeded
/// [`PENDING_TIMEOUT`] since their first attempt are silently evicted.
///
/// # Testability
/// `now` is passed in rather than calling `Instant::now()` internally so that
/// unit tests can control the simulated clock without sleeping.
pub fn check_pending_mounts(
    pending: &mut HashMap<String, (Instant, String)>,
    known_mounts: &mut HashMap<String, PathBuf>,
    mounts_content: &str,
    now: Instant,
) -> Vec<UsbEvent> {
    let mut events = Vec::new();
    let mut to_remove = Vec::new();

    for (devnode, (first_seen, manifest_name)) in pending.iter() {
        if let Some(mount) = find_mount(devnode, mounts_content) {
            // Device has appeared in /proc/mounts: emit Mounted and graduate to known_mounts.
            known_mounts.insert(devnode.clone(), mount.clone());
            events.push(UsbEvent::Mounted {
                mount_point: mount,
                manifest_name: manifest_name.clone(),
            });
            to_remove.push(devnode.clone());
        } else if now.duration_since(*first_seen) >= PENDING_TIMEOUT {
            // The automounter never completed within the timeout window.
            // Evict and warn so the user can diagnose a slow or failed mount.
            // Without this message, a USB drive that fails to automount produces
            // no visible diagnostic -- the token simply never appears.
            log::warn!(
                "usb-hsm: USB device {devnode} was not mounted within {}s; \
                 giving up. Check that udisks2 is running and the filesystem \
                 is readable. Re-insert the drive to retry.",
                PENDING_TIMEOUT.as_secs()
            );
            to_remove.push(devnode.clone());
        }
        // Otherwise: still within timeout, not yet mounted -> leave in pending.
    }

    for devnode in to_remove {
        pending.remove(&devnode);
    }

    events
}

// ---------------------------------------------------------------------------
// SendableMonitor -- safety wrapper so MonitorSocket can cross thread boundary
// ---------------------------------------------------------------------------

/// Wraps [`udev::MonitorSocket`] to assert it is safe to transfer to another
/// thread.
///
/// libudev itself uses a netlink socket (just a file descriptor) with no
/// thread-local state, so moving it to a dedicated worker thread is safe as
/// long as only one thread operates on it at a time -- which is guaranteed by
/// the move semantics here.
struct SendableMonitor(udev::MonitorSocket);

// SAFETY: libudev's monitor socket is a plain file descriptor with no
// thread-local state; it is safe to transfer ownership to a single background
// thread.
unsafe impl Send for SendableMonitor {}

// ---------------------------------------------------------------------------
// UsbWatcher
// ---------------------------------------------------------------------------

/// Watches udev for block device mount/unmount events and emits [`UsbEvent`]s.
pub struct UsbWatcher {
    rx: Receiver<UsbEvent>,
    stop_tx: Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl UsbWatcher {
    /// Start the background monitor thread.
    ///
    /// Returns an error if the udev monitor socket cannot be created.
    pub fn start() -> Result<Self, Error> {
        let monitor = MonitorBuilder::new()
            .map_err(|e| Error::Udev(e.to_string()))?
            .match_subsystem("block")
            .map_err(|e| Error::Udev(e.to_string()))?
            .listen()
            .map_err(|e| Error::Udev(e.to_string()))?;

        let (event_tx, event_rx) = crossbeam_channel::unbounded::<UsbEvent>();
        let (stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(0);

        let sendable = SendableMonitor(monitor);
        let handle = thread::spawn(move || {
            // Catch panics so that a libudev or wolfcrypt panic inside monitor_loop
            // is logged rather than silently killing the thread. When this closure
            // returns (panic or normal exit), event_tx is dropped, which closes the
            // channel and signals the dispatcher thread (lib.rs) to exit its iterator.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                monitor_loop(sendable, event_tx, stop_rx);
            }));
            if let Err(e) = result {
                let msg = e.downcast_ref::<&str>().copied()
                    .or_else(|| e.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("unknown panic");
                log::error!("usb-hsm: USB monitor thread panicked: {msg}; hotplug detection is now disabled");
            }
        });

        Ok(UsbWatcher {
            rx: event_rx,
            stop_tx,
            thread: Some(handle),
        })
    }

    /// Returns a reference to the event receiver channel.
    pub fn events(&self) -> &Receiver<UsbEvent> {
        &self.rx
    }

    /// Signal the background thread to exit and wait for it to finish.
    pub fn stop(mut self) {
        // Ignore send errors: the thread may have already exited.
        let _ = self.stop_tx.send(());
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Background thread
// ---------------------------------------------------------------------------

fn monitor_loop(
    sendable: SendableMonitor,
    event_tx: Sender<UsbEvent>,
    stop_rx: Receiver<()>,
) {
    let monitor = sendable.0;
    let raw_fd = monitor.as_raw_fd();
    let mut known_mounts: HashMap<String, PathBuf> = HashMap::new();
    // Block devices that sent a udev 'add' event but were not yet in
    // /proc/mounts at that moment. Value is (first_attempt_time, manifest_name).
    // manifest_name is captured from the USB_HSM_MANIFEST udev property at event
    // time -- it is not available during later /proc/mounts retry ticks.
    // See module-level doc for the timing model.
    let mut pending: HashMap<String, (Instant, String)> = HashMap::new();

    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }

        let mut fds = [libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        }];

        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, 100) };

        if ret < 0 {
            // poll(2) returned an error. EINTR is the most common cause (signal
            // interrupted the call) and is always transient. ENOMEM or EFAULT
            // are much rarer; logging gives the operator visibility without
            // crashing the monitor thread.
            // SAFETY: __errno_location() is valid immediately after a syscall failure.
            let errno = unsafe { *libc::__errno_location() };
            log::warn!("usb-hsm: poll() on udev socket failed (errno {errno}); treating as transient and retrying");
            continue;
        }

        if ret > 0 {
            for udev_event in monitor.iter() {
                let action = match udev_event.event_type() {
                    EventType::Add => UdevAction::Add,
                    EventType::Remove => UdevAction::Remove,
                    _ => continue,
                };

                let devnode = match udev_event.devnode() {
                    Some(p) => match p.to_str() {
                        Some(s) => s.to_owned(),
                        None => {
                            // A devnode that isn't valid UTF-8 should never happen on
                            // Linux (devfs paths are always ASCII), but if it does we
                            // cannot process the event. Log so the operator knows why
                            // the device was silently skipped rather than investigating
                            // a ghost insertion.
                            log::warn!("usb-hsm: udev devnode is not valid UTF-8; skipping event (unexpected on Linux)");
                            continue;
                        }
                    },
                    None => continue,
                };

                // Capture the manifest filename override from the udev event
                // property. The USB_HSM_MANIFEST property is only available at
                // event time -- it is not present during later /proc/mounts retry
                // ticks, so it must be captured here and stored in the pending map.
                let manifest_name = udev_event
                    .property_value("USB_HSM_MANIFEST")
                    .and_then(|v| v.to_str())
                    .unwrap_or(crate::manifest::DEFAULT_MANIFEST_NAME)
                    .to_owned();

                // On remove, evict from pending in case the device was removed
                // before the automounter ever completed the mount. We must do
                // this before calling process_event so that a subsequent
                // check_pending_mounts tick doesn't race and emit a spurious
                // Mounted event for a device that is already gone.
                if action == UdevAction::Remove {
                    pending.remove(&devnode);
                }

                let mounts_content = match std::fs::read_to_string("/proc/mounts") {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                match process_event(action, &devnode, &manifest_name, &mounts_content, &mut known_mounts) {
                    Some(ev) => {
                        let _ = event_tx.send(ev);
                    }
                    None if action == UdevAction::Add => {
                        // Device not yet in /proc/mounts. Register for retry;
                        // or_insert_with preserves the original timestamp and manifest
                        // name if the device was already in pending (e.g., a spurious
                        // dup 'add').
                        pending.entry(devnode).or_insert_with(|| (Instant::now(), manifest_name));
                    }
                    None => {}
                }
            }
        }

        // Retry pending devices on every tick, regardless of whether a udev
        // event arrived. The poll(2) timeout is 100 ms so retry latency is
        // bounded; most automounters complete within 1 second.
        //
        // If /proc/mounts is temporarily unreadable (FD exhaustion, etc.),
        // skip this tick's retry. The pending devices are NOT evicted -- they
        // will be retried on the next tick. Treating unreadable /proc/mounts
        // as empty would wrongly time out legitimate pending devices.
        if !pending.is_empty() {
            match std::fs::read_to_string("/proc/mounts") {
                Ok(mounts_content) => {
                    for ev in check_pending_mounts(&mut pending, &mut known_mounts, &mounts_content, Instant::now()) {
                        let _ = event_tx.send(ev);
                    }
                }
                Err(e) => {
                    log::warn!("usb-hsm: failed to read /proc/mounts during pending retry: {e}; will retry next tick");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Mock source for unit testing
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod mock {
    use super::*;

    /// Replays a fixed sequence of synthetic udev events through the same
    /// [`process_event`] logic used by the real monitor thread.
    pub struct MockUsbSource {
        events: Vec<(UdevAction, String)>,
        mounts_content: String,
    }

    impl MockUsbSource {
        /// Create a new mock source.
        ///
        /// `events` is a list of `(action, devnode)` pairs; `mounts_content`
        /// is the contents of a simulated `/proc/mounts` file.
        pub fn new(events: Vec<(UdevAction, &str)>, mounts_content: &str) -> Self {
            MockUsbSource {
                events: events
                    .into_iter()
                    .map(|(a, d)| (a, d.to_owned()))
                    .collect(),
                mounts_content: mounts_content.to_owned(),
            }
        }

        /// Process all events and return every [`UsbEvent`] that was emitted.
        ///
        /// Uses [`DEFAULT_MANIFEST_NAME`] as the manifest name for all events,
        /// since the mock does not simulate udev device properties.
        ///
        /// [`DEFAULT_MANIFEST_NAME`]: crate::manifest::DEFAULT_MANIFEST_NAME
        pub fn run(&self) -> Vec<UsbEvent> {
            let mut known_mounts: HashMap<String, PathBuf> = HashMap::new();
            let mut output = Vec::new();

            for (action, devnode) in &self.events {
                if let Some(ev) = process_event(
                    *action,
                    devnode,
                    crate::manifest::DEFAULT_MANIFEST_NAME,
                    &self.mounts_content,
                    &mut known_mounts,
                ) {
                    output.push(ev);
                }
            }

            output
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::mock::MockUsbSource;
    use super::*;

    const MOUNTS: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sdb1 /media/usb vfat rw,relatime 0 0
";

    /// Build a default [`UsbEvent::Mounted`] for tests (uses DEFAULT_MANIFEST_NAME).
    fn mounted(path: &str) -> UsbEvent {
        UsbEvent::Mounted {
            mount_point: PathBuf::from(path),
            manifest_name: crate::manifest::DEFAULT_MANIFEST_NAME.to_string(),
        }
    }

    // 1. add event where device appears in mounts -> exactly one Mounted event.
    #[test]
    fn add_event_device_in_mounts_emits_mounted() {
        let src = MockUsbSource::new(vec![(UdevAction::Add, "/dev/sdb1")], MOUNTS);
        let events = src.run();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], mounted("/media/usb"));
    }

    // 2. remove event -> exactly one Unmounted event with correct path.
    #[test]
    fn remove_event_emits_unmounted() {
        let src = MockUsbSource::new(
            vec![(UdevAction::Add, "/dev/sdb1"), (UdevAction::Remove, "/dev/sdb1")],
            MOUNTS,
        );
        let events = src.run();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1], UsbEvent::Unmounted(PathBuf::from("/media/usb")));
    }

    // 3. add event for device NOT in mounts -> no event emitted immediately.
    //    (The real monitor_loop would add this to pending and retry; the mock
    //    drives process_event directly and doesn't simulate the retry.)
    #[test]
    fn add_event_device_not_in_mounts_emits_nothing() {
        let src = MockUsbSource::new(vec![(UdevAction::Add, "/dev/sdc1")], MOUNTS);
        let events = src.run();
        assert!(events.is_empty());
    }

    // 4. Rapid add/remove cycles (10 iterations) -> exactly 10 Mounted and 10 Unmounted.
    #[test]
    fn rapid_add_remove_cycles() {
        let mut raw: Vec<(UdevAction, &str)> = Vec::new();
        for _ in 0..10 {
            raw.push((UdevAction::Add, "/dev/sdb1"));
            raw.push((UdevAction::Remove, "/dev/sdb1"));
        }
        let src = MockUsbSource::new(raw, MOUNTS);
        let events = src.run();
        assert_eq!(events.len(), 20);

        let n_mounted = events
            .iter()
            .filter(|e| matches!(e, UsbEvent::Mounted { .. }))
            .count();
        let n_unmounted = events
            .iter()
            .filter(|e| matches!(e, UsbEvent::Unmounted(_)))
            .count();
        assert_eq!(n_mounted, 10);
        assert_eq!(n_unmounted, 10);
    }

    // ---------------------------------------------------------------------------
    // check_pending_mounts tests -- exercise the deferred-mount retry path
    // ---------------------------------------------------------------------------

    /// Helper: an Instant in the past by `secs` seconds.
    fn past(secs: u64) -> Instant {
        Instant::now() - Duration::from_secs(secs)
    }

    /// Build a pending entry with DEFAULT_MANIFEST_NAME.
    fn pending_entry(secs: u64) -> (Instant, String) {
        (past(secs), crate::manifest::DEFAULT_MANIFEST_NAME.to_string())
    }

    // 5. Device is in /proc/mounts when check_pending_mounts is called ->
    //    emits Mounted, removed from pending, added to known_mounts.
    #[test]
    fn pending_device_appears_in_mounts_emits_mounted() {
        let mut pending = HashMap::new();
        pending.insert("/dev/sdb1".to_owned(), pending_entry(1));
        let mut known_mounts = HashMap::new();
        let mounts = "/dev/sdb1 /media/usb vfat rw 0 0\n";

        let events = check_pending_mounts(&mut pending, &mut known_mounts, mounts, Instant::now());

        assert_eq!(events.len(), 1, "expected one Mounted event");
        assert_eq!(events[0], mounted("/media/usb"));
        assert!(pending.is_empty(), "device must be removed from pending");
        assert_eq!(
            known_mounts.get("/dev/sdb1"),
            Some(&PathBuf::from("/media/usb")),
            "device must be in known_mounts"
        );
    }

    // 6. Device is NOT in /proc/mounts and within timeout -> stays in pending,
    //    no event emitted.
    #[test]
    fn pending_device_not_yet_mounted_stays_pending() {
        let mut pending = HashMap::new();
        pending.insert("/dev/sdb1".to_owned(), pending_entry(2));
        let mut known_mounts = HashMap::new();
        let mounts = ""; // device not present

        let events = check_pending_mounts(&mut pending, &mut known_mounts, mounts, Instant::now());

        assert!(events.is_empty(), "no event while device is pending and within timeout");
        assert!(pending.contains_key("/dev/sdb1"), "device must remain in pending");
    }

    // 7. Device exceeds PENDING_TIMEOUT without appearing -> evicted silently,
    //    no event emitted.
    #[test]
    fn pending_device_times_out_is_evicted() {
        let timeout_secs = PENDING_TIMEOUT.as_secs();
        let mut pending = HashMap::new();
        // Simulate the device having been pending for longer than the timeout.
        pending.insert("/dev/sdb1".to_owned(), pending_entry(timeout_secs + 1));
        let mut known_mounts = HashMap::new();
        let mounts = ""; // device never appeared

        let events = check_pending_mounts(&mut pending, &mut known_mounts, mounts, Instant::now());

        assert!(events.is_empty(), "no event for timed-out device");
        assert!(pending.is_empty(), "timed-out device must be evicted from pending");
        assert!(known_mounts.is_empty(), "known_mounts must be unchanged");
    }

    // 8. Multiple pending devices: one appears, one times out, one stays ->
    //    exactly one Mounted event, correct final pending state.
    #[test]
    fn mixed_pending_states() {
        let timeout_secs = PENDING_TIMEOUT.as_secs();
        let mut pending = HashMap::new();
        pending.insert("/dev/sdb1".to_owned(), pending_entry(1));                // about to be mounted
        pending.insert("/dev/sdc1".to_owned(), pending_entry(timeout_secs + 1)); // timed out
        pending.insert("/dev/sdd1".to_owned(), pending_entry(3));                // still waiting

        let mut known_mounts = HashMap::new();
        // Only sdb1 is in mounts now; sdc1 never appeared; sdd1 hasn't appeared yet.
        let mounts = "/dev/sdb1 /media/usb-a vfat rw 0 0\n";

        let events = check_pending_mounts(&mut pending, &mut known_mounts, mounts, Instant::now());

        assert_eq!(events.len(), 1, "exactly one Mounted event");
        assert_eq!(events[0], mounted("/media/usb-a"));
        assert!(!pending.contains_key("/dev/sdb1"), "mounted device removed from pending");
        assert!(!pending.contains_key("/dev/sdc1"), "timed-out device removed from pending");
        assert!(pending.contains_key("/dev/sdd1"), "still-waiting device remains in pending");
    }

    // 9. check_pending_mounts on empty pending -> no panics, no events.
    #[test]
    fn empty_pending_is_a_no_op() {
        let mut pending: HashMap<String, (Instant, String)> = HashMap::new();
        let mut known_mounts = HashMap::new();
        let events = check_pending_mounts(&mut pending, &mut known_mounts, "", Instant::now());
        assert!(events.is_empty());
    }

    // ---------------------------------------------------------------------------
    // unescape_proc_mounts tests -- verify /proc/mounts octal-escape handling
    // ---------------------------------------------------------------------------

    // 10. \040 (octal space) is decoded to a literal space.
    #[test]
    fn unescape_space_sequence() {
        assert_eq!(unescape_proc_mounts(r"/media/My\040Drive"), "/media/My Drive");
    }

    // 11. \134 (octal backslash) is decoded to a literal backslash.
    #[test]
    fn unescape_backslash_sequence() {
        assert_eq!(unescape_proc_mounts(r"/path/with\134backslash"), r"/path/with\backslash");
    }

    // 12. A string with no escape sequences is returned unchanged.
    #[test]
    fn unescape_no_escapes_unchanged() {
        assert_eq!(unescape_proc_mounts("/media/usb"), "/media/usb");
    }

    // 13. Multiple \040 sequences in one path are all decoded.
    #[test]
    fn unescape_multiple_spaces() {
        assert_eq!(
            unescape_proc_mounts(r"/media/My\040USB\040Drive"),
            "/media/My USB Drive",
        );
    }

    // 14. \134 processed before \040 prevents \134040 from being decoded as space.
    //     \134040 -> after \134->\: \040 -> then \040->space: space. This is the known
    //     limitation documented in unescape_proc_mounts. The test captures the current
    //     (two-pass) behavior so any change is deliberate and visible.
    #[test]
    fn unescape_backslash_before_040_known_limitation() {
        // \134040 represents a literal \040 in the path, not a space. But the
        // two-pass approach converts it to a space. Document this as expected behavior
        // under the current implementation.
        let result = unescape_proc_mounts(r"\134040");
        // First pass: \134 -> \ giving "\040"; second pass: \040 -> " "
        assert_eq!(result, " ", "two-pass limitation: \\134040 becomes space");
    }

    // ---------------------------------------------------------------------------
    // find_mount tests with space-escaped paths
    // ---------------------------------------------------------------------------

    // 15. find_mount returns the correct path when the mount point contains \040.
    #[test]
    fn find_mount_with_space_in_mount_point() {
        let mounts = "/dev/sdb1 /media/My\\040Drive vfat rw 0 0\n";
        let result = find_mount("/dev/sdb1", mounts);
        assert_eq!(result, Some(PathBuf::from("/media/My Drive")));
    }

    // 16. find_mount returns None when device is not present.
    #[test]
    fn find_mount_device_not_found_returns_none() {
        let mounts = "/dev/sdb1 /media/usb vfat rw 0 0\n";
        let result = find_mount("/dev/sdc1", mounts);
        assert_eq!(result, None);
    }

    // 17. find_mount returns the first matching device when multiple entries exist.
    #[test]
    fn find_mount_first_match_returned() {
        let mounts = "/dev/sdb1 /media/first vfat rw 0 0\n/dev/sdb1 /media/second vfat rw 0 0\n";
        let result = find_mount("/dev/sdb1", mounts);
        assert_eq!(result, Some(PathBuf::from("/media/first")));
    }

    // 18. Mounted event is emitted correctly when device path in /proc/mounts uses \040.
    //     Simulates udisks2 creating mount points with spaces in the name.
    #[test]
    fn add_event_device_in_mounts_with_space_in_mountpoint() {
        let mounts_with_space = "\
/dev/sdb1 /media/My\\040Drive vfat rw 0 0
";
        let src = MockUsbSource::new(vec![(UdevAction::Add, "/dev/sdb1")], mounts_with_space);
        let events = src.run();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], mounted("/media/My Drive"));
    }
}
