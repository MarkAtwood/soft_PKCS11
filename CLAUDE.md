# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains `usb-hsm`, a PKCS#11 soft-token library written in
Rust that turns a USB flash drive into a cryptographic key possession factor.
Keys are stored AES-256-GCM encrypted on the drive and loaded into mlock'd
memory only while the drive is present and a PIN has been verified.

**Language:** Rust (edition 2021, MSRV 1.75)
**Output:** `target/release/libusb_hsm.so` (cdylib)

## Key Files

| File | Purpose |
|------|---------|
| `src/lib.rs` | PKCS#11 C ABI entry points, session management |
| `src/token.rs` | Slot/token state machine (Absent → Present → LoggedIn) |
| `src/keystore.rs` | `.p11k` encrypted keystore: AES-256-GCM + PBKDF2, mlock, zeroize |
| `src/ops.rs` | sign / verify / encrypt / decrypt against loaded key material |
| `src/usb_watch.rs` | udev USB mount/unmount detection |
| `src/bin/usb-hsm-keygen/` | Key import: PEM, PKCS#12, OpenSSH, OpenPGP, PPK, JKS, GCP JSON |
| `src/manifest.rs` | `.usb-hsm` manifest for fast keystore discovery |

## Build and Test

All commands run from the repo root:

```bash
cargo build           # debug build
cargo build --release # release build
cargo t               # full test suite (enables test-helpers feature)
cargo test --lib      # unit tests only
```

`wolfssl-rs` must be checked out adjacent to this repo. See `README.md`.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking -- do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge -- do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->

## usb-hsm: Removed Mechanisms

### CKM_RSA_PKCS (removed)

`CKM_RSA_PKCS` is **not** in `MECHANISMS` or `SIGN_VERIFY_MECHANISMS` in `src/lib.rs`.

**Why:** wolfcrypt's `sign_pkcs1v15_with_digest` hashes the input internally before
applying PKCS#1 v1.5 padding. PKCS#11 callers are required (spec s.11.11) to pre-hash
and DER-encode a DigestInfo block before passing data to `C_Sign`. If the token advertised
`CKM_RSA_PKCS`, those callers would pass a pre-formed DigestInfo, wolfcrypt would hash it
again, and the result would be a silent wrong signature -- valid-looking but verifying under
no standard key.

**To restore:** wolfssl-rs must expose `wc_RsaSSL_Sign` (or equivalent) -- a path that
pads the caller-supplied block without hashing. Any test must verify against an independent
oracle (e.g. `openssl rsautl -raw`), never a round-trip through this token.
