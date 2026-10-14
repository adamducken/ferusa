# Ferusa

Ferusa is an experimental two-factor password vault. It combines a Unix command-line
client with an Android approval companion so that the local master password alone is
not enough to decrypt the vault.

> [!WARNING]
> Ferusa is a prototype, has not been independently audited, and is not ready for
> irreplaceable secrets. Read the security limitations before using it.

## How it works

The CLI derives a local secret from the master password with Argon2. The Android app
holds a second share protected by Android Keystore and releases it through an
authenticated pairing and approval flow. The shares are combined to decrypt the
local vault, which uses authenticated encryption.

The phone and CLI communicate over an encrypted peer-to-peer connection provided by
iroh. Pairing includes QR-code exchange, a verification code, and signed state
transitions. Read and write requests use separate phone PINs, and sensitive Android
operations can require biometric authentication.

| Path | Purpose |
| --- | --- |
| `ferusa-core/` | Shared protocol, framing, cryptography, and message types |
| `cli/` | Unix CLI and encrypted local vault storage |
| `app/` | Svelte 5 and Tauri 2 Android approval companion |

## Platform support

- Android companion application
- Linux CLI with mounted USB recovery storage (ext4, FAT32, or kernel exFAT)

Other Unix systems can read legacy installations, but mandatory recovery creation
requires the Linux storage resolver. Unknown, network, FUSE, loop-backed, and
unresolved multi-device layouts fail closed. Hardware recovery validation remains
required before treating this prototype as ready for irreplaceable secrets.

iOS, Windows, and a desktop graphical application are not currently supported.
The repository does not distribute compiled APKs; Android builds must be produced
and signed locally.

## Prerequisites

- A current stable Rust toolchain
- `pnpm`
- Android SDK and NDK, `adb`, and a USB-debuggable Android device
- Network connectivity between the CLI and phone, either directly or through the
  transport used by iroh

## Build and install

Install the CLI from the repository root:

```bash
cargo install --path cli --locked
```

Install the app dependencies and run a development build:

```bash
cd app
pnpm install --frozen-lockfile
pnpm tauri android dev
```

See [the Android build and signing guide](app/build_install.md) for release APK
instructions. Signing keys and generated binaries must remain outside Git.

## First setup

1. Install and open the Android app.
2. Mount a separate recovery USB drive. Run
   `ferusa init --recovery-dir /media/USER/RECOVERY` and choose a strong master password.
3. Scan the displayed QR code with the app and confirm that the verification codes
   match.
4. Complete the PIN and biometric setup on the phone.
5. Approve **Create recovery file** on the phone. Enter the same master password
   and both phone PINs on the laptop; wait for verified recovery and pairing completion.
6. Safely eject and securely store the recovery drive. Configure a clipboard command
   with `ferusa config set`.

`ferusa init` verifies recovery material before activating its candidate vault and
phone pairing. New installations cannot unlock while mandatory recovery is incomplete.
Use `ferusa pair` only to replace or repair pairing; replacing a healthy pairing
requires approval from the currently paired phone. Start
`ferusa pair --recovery-dir /media/USER/RECOVERY`, then choose
**Replace paired desktop** in the unlocked phone app. The current generation remains
active until the desktop vault has been re-encrypted with the new phone share and
both devices have durably committed the replacement.

If setup, replacement, password change, or recovery is interrupted, retain the
data directory and rerun the same command with its original paths. Paste the same
public enrollment token on the phone to resume its exact generation with fresh
code confirmation and biometric authentication. Resume reuses the original phone
PINs; it does not establish new PINs. Recovery always requires fresh consent and
both PINs. Do not reset a pending phone or delete its desktop transaction.

Common commands:

```bash
ferusa add github
ferusa get github
ferusa edit github
ferusa remove github
ferusa list
# `lock` is available inside the interactive `ferusa` shell only.
ferusa
# then enter: lock
ferusa passwd
ferusa config set --clear-after 30 wl-copy
```

Running `ferusa` without a subcommand opens the interactive shell. On Linux, vault
data is normally stored below `~/.local/share/ferusa/`.

## Recovery

For an existing paired vault, `ferusa recovery create --to DIR` requests fresh
phone consent and both PINs, then writes a v1 file to a positively identified
USB drive. `ferusa recovery create --confirm FILE` asks the phone to confirm an
exact file again after an uncertain acknowledgement. Recovery creation never
copies vault entries or a vault snapshot to the drive. Existing legacy installations
retain access until explicit successful recovery enrollment upgrades their policy.

`ferusa recovery verify --from FILE --vault VAULT` can check a v1 recovery file
against a separately stored encrypted vault without contacting a phone. It asks
for the file's master password and both phone PINs, then offers one separate vault
password prompt if the vault was re-encrypted later. It rejects sources on the same
physical storage device or an unknown Linux storage layout. This command does not
complete an interrupted creation transaction. Offline compatibility verification
does not substitute for fresh phone consent when confirming creation.

Restore after losing or reinstalling the phone app:

```bash
ferusa recover --from /media/USER/RECOVERY/ferusa-recovery-ID.frb \
  --vault /path/to/vault.enc --into /path/to/new-private-installation \
  --recovery-dir /media/USER/RECOVERY
```

The first stage opens the recovery file and supplied vault offline. It does not
contact the original phone or read its pairing metadata. It preserves both source
files, creates a fresh desktop identity, enrolls a replacement phone, and reencrypts
the validated entries under a fresh salt and the replacement phone's share. Choose
the restored master password and establish the replacement phone's PINs. New,
phone-approved recovery material must be verified before activation completes.
The target must be fresh or belong to this exact interrupted restore; an unrelated
installation is never overwritten. Use the reported `FERUSA_DATA_DIR` value for
normal commands afterward. No normal unlocked session is exposed during restoration.

`ferusa passwd --recovery-dir DIR` also verifies new recovery material before
committing the new password. Entry changes need no recovery refresh. In the REPL,
`recovery create`, `passwd`, and `pair` prompt for the external destination.

Keep this recovery drive in a secure location, separate from your phone, laptop,
and any vault backups. Do not carry it around with your phone.

Recovery uses your master password and both phone PINs. No new password.

This drive restores access, not your vault data. If you lose the vault and have
no separate copy, recovery cannot restore your passwords.

A copied recovery file permits offline credential guesses without the phone's
biometric checks or PIN attempt limits. Vault backups must be consistent committed
encrypted copies, made while vault writes are stopped or the vault lock is held,
and kept on a different physical device from recovery material. `FERUSA_DATA_DIR`
selects an installation's data directory for ordinary CLI commands.

Refresh your recovery file when your master password or either phone PIN changes.
Older copies still require the password and PINs used when they were created;
changing your credentials does not revoke those copies. An older same-share file
can still recover a newer vault with its separate vault password. Share replacement
protects future ciphertext, not old copies. No standalone PIN-change UI is provided.

The master password and two PINs are one knowledge factor. The file supplies an
alternative possession credential; copied files permit offline guessing without
the phone's protections. Entering PINs on the laptop trusts that computer with
them. Recovery password input is capped at 65,536 UTF-8 bytes and is not trimmed or
normalized. Consider a second independently created recovery file on another
external drive, or a direct external-to-external copy followed by full offline
verification against a separately stored vault.

Recovery format remains v1 (148 bytes); both apps use protocol v5. New pairing
metadata uses v4, credential journals v3, and phone generation records v2. Legacy
pairing v3, journal v2, and phone generation v1 remain readable. Build and install
matching CLI/phone versions. Populated lost-phone restoration and selected lifecycle
E2E scenarios passed on Android 15 with an exFAT USB drive. The full hardware,
filesystem, and crash-resume acceptance matrix remains pending.

Clipboard expiry retains the original command and target even if configuration
changes. Supported targets include Wayland primary selection and seat, X11
selection and display, and macOS pasteboard. Unknown or incompatible options
still permit copying, but the CLI reports automatic clearing as unsupported.
Clearing occurs only while the selected target still contains the copied password.

## Development checks

The Rust crates are intentionally independent rather than members of a root Cargo
workspace:

```bash
cargo fmt --manifest-path ferusa-core/Cargo.toml --all -- --check
cargo fmt --manifest-path cli/Cargo.toml --all -- --check
cargo fmt --manifest-path app/src-tauri/Cargo.toml --all -- --check

cargo test --manifest-path ferusa-core/Cargo.toml --locked
cargo test --manifest-path cli/Cargo.toml --locked --all-targets
cargo test --manifest-path app/src-tauri/Cargo.toml --locked --all-targets

cd app
pnpm check
pnpm build
pnpm check:csp
```

The fuzz targets have their own instructions in
[`cli/fuzz/README.md`](cli/fuzz/README.md).

## Security model and limitations

- The Android-held share protects the vault while it is locked. After approval and
  unlock, the desktop process receives enough key material to decrypt the vault and
  must be trusted for the lifetime of that unlocked session. The phone cannot
  cryptographically enforce every subsequent entry operation.
- Resetting the Android app, clearing its data, losing its Keystore material, or
  forgetting pairing requires compatible recovery material, its original credentials,
  and a separate encrypted vault. Losing vault data without a separate copy cannot
  be repaired by the recovery drive.
- Clearing app data or uninstalling the phone app is destructive; it is not a
  pairing-replacement workflow. Preserve access to the currently paired phone until
  `ferusa pair` reports that replacement has completed.
- Memory zeroization and platform hardening reduce exposure but cannot guarantee
  protection against a compromised operating system or process.
- The source and tests are available for review, but that is not a substitute for an
  independent security audit.

Please avoid real or irreplaceable credentials while evaluating the project.

## License

Ferusa is available under the [MIT License](LICENSE).
