# EchoVault 1.1.0-beta.1: driver-independent preview

This is an app release candidate for testing with disposable copies. It is not
a statement that the experimental driver is safe. Do not load that driver to
test this app. Driver source remains in the repository for separate research.

## Changes

- Default builds compile driver calls to inactive functions. The app cannot
  communicate with the minifilter, even if an old driver is present.
- Explorer integration is optional and respects Windows Default Apps. Setup
  registers available file types and right-click actions. It does not delete
  UserChoice, take over all file extensions, or schedule a driver guard.
  Common document, code, image, audio and video types are registered, and an
  extension encountered during encryption is registered dynamically.
  The contextual Default Apps reminder is shown only once across processes.
- Executable script types are excluded from automatic file-type registration.
  Startup repairs legacy EchoVault ownership of those associations; .bat and
  .cmd fall back to Windows' built-in batfile and cmdfile handlers.
- A native main-menu button exposes Explorer setup/status; another opens files.
- Files stay in place with their original extensions. Folder encryption covers
  existing file contents, not folder access, names, or files added later.
- Locked outputs are read-only as an accidental-save precaution, not access control.
- Temporary output is flushed before replacement, with unique temporary names.
  Failed replacement restores the original read-only flag. Backups remain essential.
- A folder decrypt derives a separate key for each file's salt. A password check
  verifies content without silently decrypting the first file as a side effect.
- New EVF4 files use Windows CNG AES-256-GCM for authenticated encryption; header
  fields are additional authenticated data. New key wraps are authenticated too.
  Old CBC files remain readable but do not gain integrity protection until rewritten.
- Empty files and damaged-header recovery have regression coverage. Password
  changes verify/decrypt content before rewriting authenticated header fields.
- Opening a document asks the user to save/close and explicitly confirm re-locking.
  An editor launcher exiting is no longer treated as proof the document closed.
  The fallback Open With dialog is modal and starts the selected app before the
  re-lock confirmation appears, eliminating the encrypted-file launch race. Its
  default-app control is hidden so the selected editor cannot displace EchoVault.
- A 127 MiB plaintext limit bounds memory allocations for this preview.
- Files with multiple hard links or named streams are refused rather than
  leaving an unencrypted alias or silently dropping stream contents.
- Installer configuration is per-user, without an administrator requirement.
- A separate app workflow builds, tests and packages the app without loading a driver.

## Still required before a general stable release

- Complete NVDA/keyboard walkthrough with disposable files and folders.
- Run the new app workflow; confirm the Microsoft-compiler build and installer.
- Review Explorer setup/uninstall and default-app selection on supported Windows
  versions. Automated file tests do not validate this UI or registry lifecycle.
- Independent review of crypto, filesystem races, interruption/recovery behaviour,
  large files, special NTFS metadata, and backup/restore.
- Code signing is not supplied by this change.

## Boundaries that must remain visible to users

No transparent folder interception or per-app allow/block enforcement is provided.
Those kernel-driver features are not replaced by a watcher.
An interrupted editing session can leave plaintext at the original location.
Concurrent saves, cloud sync, other file writers, autosaves and disk failure are
outside the promise of atomic replacement; close other apps and keep backups.
File names are not concealed. No secure deletion or malware resistance is promised.
PBKDF2-HMAC-SHA256 remains at 100,000 iterations for existing-format compatibility;
use strong unique passwords. This change is not a cryptographic audit.
New EVF4 files require this version or a compatible newer version.
Do not overwrite the only working copy of an old encrypted file while trying this beta.

## Why there is no forced association repair

Microsoft requires user consent through supported default-app interfaces and
protects user-choice settings. A watcher cannot guarantee that every Open With
operation returns to EchoVault.

- [Windows app defaults platform](https://learn.microsoft.com/en-us/windows/apps/develop/windows-integration/default-apps-platform)
- [Default Apps settings page](https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-default-apps-settings)
