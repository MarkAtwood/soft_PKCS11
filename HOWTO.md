# usb-hsm How-To Guide

All operations that modify a `.p11k` keystore are **out of band** -- the
`usb-hsm` token is read-only at runtime. Keystore management is done with
`usb-hsm-keygen` (or `openssl` for key generation) while the USB drive is
mounted on a trusted machine, before inserting it for use.

Throughout this guide:
- `$LIB` = `/usr/local/lib/libusb_hsm.so`
- `$P11K` = full path to your `.p11k` file (e.g. `/media/usb/token.p11k`)

---

## Contents

1. [Generating private keys](#1-generating-private-keys)
2. [Creating a keystore](#2-creating-a-keystore)
3. [Adding a key to an existing keystore](#3-adding-a-key-to-an-existing-keystore)
4. [Removing a key from a keystore](#4-removing-a-key-from-a-keystore)
5. [Changing the PIN](#5-changing-the-pin)
6. [Attaching a certificate to a key](#6-attaching-a-certificate-to-a-key)
7. [Inspecting a keystore](#7-inspecting-a-keystore)
8. [Exporting a public key](#8-exporting-a-public-key)
9. [Getting PKCS#11 URIs](#9-getting-pkcs11-uris)
10. [Generating a certificate signing request (CSR)](#10-generating-a-certificate-signing-request-csr)
11. [Using with OpenSSH](#11-using-with-openssh)
12. [Using with curl](#12-using-with-curl)
13. [Using with openssl](#13-using-with-openssl)
14. [Using with GPG](#14-using-with-gpg)
15. [Using with Firefox / Chrome](#15-using-with-firefox--chrome)
16. [Using with cosign / sigstore](#16-using-with-cosign--sigstore)
17. [Auditing token use](#17-auditing-token-use)
18. [Destroying a keystore](#18-destroying-a-keystore)

---

## 1. Generating private keys

Generate keys with `openssl` on a trusted machine. Keys are imported into the
keystore in the next step -- the private key exists on disk only until it is
imported, after which you should delete the file.

**RSA-2048:**
```bash
openssl genrsa -out private.pem 2048
```

**RSA-4096:**
```bash
openssl genrsa -out private.pem 4096
```

**EC P-256:**
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
```

Convert to the DER format expected by `usb-hsm-keygen` if needed:
```bash
openssl pkey -in private.pem -out private.der -outform DER
```

Delete the key file after import:
```bash
shred -u private.pem private.der 2>/dev/null; rm -f private.pem private.der
```

---

## 2. Creating a keystore

```bash
usb-hsm-keygen create private-signing.pem private-auth.pem \
  --label signing --label auth \
  --output $P11K
```

You will be prompted to enter and confirm a PIN (minimum 6 characters).
The keystore uses PBKDF2-HMAC-SHA256 with >= 100,000 iterations. On a modern
CPU this takes approximately 0.5-1 second.

Copy the `.p11k` file to the USB drive root:
```bash
cp token.p11k /media/usb/
```

`usb-hsm-keygen create` automatically writes or updates the `.usb-hsm`
manifest in the same directory. The library reads the manifest on insert
instead of scanning the directory, so no manual registration step is needed.

---

## 3. Adding a key to an existing keystore

```bash
usb-hsm-keygen key-add $P11K new-key.pem --label new-label
```

You will be prompted for the existing PIN. The keystore is decrypted,
the new entry appended, and the file re-encrypted with a fresh nonce.
The operation is atomic (written to a temp file then renamed).

---

## 4. Removing a key from a keystore

```bash
usb-hsm-keygen key-remove $P11K --label signing
# or by key ID:
usb-hsm-keygen key-remove $P11K --id cafebabe01020304
```

The removed key's bytes are zeroized before re-encryption.

---

## 5. Changing the PIN

```bash
usb-hsm-keygen pin-change $P11K
```

You will be prompted for the current PIN and then to enter and confirm the
new PIN. The keystore is re-encrypted with a fresh random salt and nonce.

---

## 6. Attaching a certificate to a key

Once you have a signed certificate from your CA:

```bash
usb-hsm-keygen cert-add $P11K signed-cert.pem --label signing
```

The certificate DER bytes are stored alongside the key entry. The token
exposes it as a `CKO_CERTIFICATE` object, which TLS client auth, S/MIME,
and code-signing tools expect to find next to the private key.

---

## 7. Inspecting a keystore

List the unencrypted header fields (format version, KDF parameters) without
a PIN using `usb-hsm-info`:

```bash
usb-hsm-info $P11K
```

List all objects in the loaded token using `pkcs11-tool`:

```bash
pkcs11-tool --module $LIB --login --list-objects
```

---

## 8. Exporting a public key

The token must be inserted and logged in.

**SSH `authorized_keys` format** -- for provisioning servers:
```bash
ssh-keygen -D $LIB
```

**DER then PEM** -- for CAs, openssl, web servers:
```bash
pkcs11-tool --module $LIB --login \
  --read-object --type pubkey \
  --label <label> \
  --output-file pubkey.der
openssl pkey -inform DER -pubin -in pubkey.der -out pubkey.pem
```

---

## 9. Getting PKCS#11 URIs

`p11tool` (GnuTLS package) prints RFC 7512 `pkcs11:` URIs for every object:

```bash
p11tool --list-all --provider $LIB
```

Example output:
```
pkcs11:token=usb-hsm;object=signing;type=private
pkcs11:token=usb-hsm;object=signing;type=public
```

Use these URIs anywhere a tool accepts `--key pkcs11:...`.

---

## 10. Generating a certificate signing request (CSR)

```bash
openssl req \
  -engine pkcs11 -keyform engine \
  -key "pkcs11:object=<label>;type=private" \
  -new -subj "/CN=your-common-name" \
  -out request.csr.pem
```

With Subject Alternative Names:
```bash
openssl req \
  -engine pkcs11 -keyform engine \
  -key "pkcs11:object=<label>;type=private" \
  -new -subj "/CN=your-common-name" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com" \
  -out request.csr.pem
```

---

## 11. Using with OpenSSH

**Per-session:**
```bash
ssh -I $LIB user@host
```

**Permanent (`~/.ssh/config`):**
```
PKCS11Provider /usr/local/lib/libusb_hsm.so
```

**ssh-agent:**
```bash
ssh-add -s $LIB
```

The agent will prompt for the PIN once and hold the session open. Removing
the USB drive invalidates the session; the next operation returns an error.

---

## 12. Using with curl

**TLS client authentication** (private key on token, cert in file):
```bash
curl --key "pkcs11:object=<label>;type=private" \
     --cert /path/to/client-cert.pem \
     https://example.com/
```

**Key and certificate both on token:**
```bash
curl --key  "pkcs11:object=<label>;type=private" \
     --cert "pkcs11:object=<label>;type=cert" \
     https://example.com/
```

Requires curl built with OpenSSL and the `pkcs11` engine, or with GnuTLS
and `p11-kit` configured.

---

## 13. Using with openssl

**TLS client connection:**
```bash
openssl s_client \
  -engine pkcs11 -keyform engine \
  -key  "pkcs11:object=<label>;type=private" \
  -cert /path/to/client-cert.pem \
  -connect example.com:443
```

**Sign a file (raw PKCS#11 sign via pkcs11-tool):**
```bash
pkcs11-tool --module $LIB --login \
  --sign --mechanism SHA256-RSA-PKCS-PSS \
  --label <label> \
  --input-file data.bin \
  --output-file data.sig
```

**Verify the signature:**
```bash
openssl dgst -sha256 -verify pubkey.pem \
  -sigopt rsa_padding_mode:pss \
  -signature data.sig \
  data.bin
```

---

## 14. Using with GPG

GPG communicates with PKCS#11 tokens through `gpg-pkcs11-scd`, a drop-in
replacement for `scdaemon`.

Install and configure:
```bash
# Debian/Ubuntu
apt-get install gpg-pkcs11-scd

# Add to ~/.gnupg/scdaemon.conf:
echo "providers usb-hsm" >> ~/.gnupg/scdaemon.conf
echo "provider-usb-hsm-library $LIB" >> ~/.gnupg/scdaemon.conf
```

Reload the agent:
```bash
gpg-connect-agent "scd serialno" "learn --force" /bye
```

---

## 15. Using with Firefox / Chrome

Firefox and Chrome load PKCS#11 modules through their security device
manager.

**Firefox:**
1. Open Preferences -> Privacy & Security -> Security Devices
2. Click **Load** and browse to `$LIB`
3. The token appears as a security device; Firefox will prompt for the PIN
   when a client certificate is required

**Chrome / Chromium** (Linux):
Chrome uses the system NSS database. Register the module system-wide:
```bash
modutil -dbdir sql:$HOME/.pki/nssdb -add "usb-hsm" -libfile $LIB
```

Or for all users:
```bash
modutil -dbdir /etc/pki/nssdb -add "usb-hsm" -libfile $LIB
```

---

## 16. Using with cosign / sigstore

Sign a container image:
```bash
cosign sign \
  --key "pkcs11:object=<label>;type=private" \
  <image-ref>
```

Verify:
```bash
cosign verify \
  --key "pkcs11:object=<label>;type=public" \
  <image-ref>
```

cosign requires the `COSIGN_PKCS11_PIN` environment variable or will prompt
interactively.

---

## 17. Auditing token use

`usb-hsm` does not emit its own audit log. Use system-level logging:

| Application          | Where to look                                       |
|----------------------|-----------------------------------------------------|
| OpenSSH              | `/var/log/auth.log` or `journalctl -u ssh`          |
| PAM (`pam_pkcs11`)   | syslog / `journalctl`                               |
| Any systemd service  | `journalctl -u <service>`                           |
| Firefox / Chrome     | Browser console or OS keychain log                  |

For per-operation audit (every `C_Sign` call), configure logging in the
application using the token, not in the token itself.

---

## 18. Destroying a keystore

```bash
shred -u $P11K
```

**Flash storage caveat:** USB drives use flash with wear-leveling firmware.
`shred` overwrites at the filesystem layer, but the flash translation layer
may keep the old data in unmapped blocks that `shred` cannot reach. This is
best-effort. The only guaranteed destruction is:

1. Full drive format: `mkfs.vfat /dev/sdX` (replaces the filesystem)
2. Secure erase via `hdparm` if the drive supports ATA Secure Erase
3. Physical destruction of the drive

For high-assurance key destruction do not rely on `shred` alone.
