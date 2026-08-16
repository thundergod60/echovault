# EchoVault — Minifilter Driver Plan (optional)

User-mode interception handles **double-clicks** (via file associations) but
cannot gate two other open paths:

1. **Right-click → "Open with" → pick a program** — Windows routes the file
   directly to that program. The association handler is never consulted.
2. **Opening a folder** — Explorer opens directories natively; there is no
   user-mode extension point for the default open of a folder.
3. (Also ungated: a program opening a file by path — `notepad file.txt`,
   File → Open inside an app, scripts, drag-and-drop onto an app icon.)

Only a **filesystem minifilter driver** (kernel mode) can gate all of these.
This document is the plan for it. It is optional — everything below is
**additive**; the EVF3 file format, vault, master password, and all current
user-mode behavior stay exactly as they are.

---

## What the driver does (one sentence)

On **every file open** (IRP_MJ_CREATE), the driver checks whether the file is
an EchoVault-encrypted file (EVF3 header) and, if so, whether it is in the
current session's **unlock allow-list**; if not, the open is **denied**.

## Design

### Kernel side (the filter)

- Registers a pre-operation callback on `IRP_MJ_CREATE` (file open/create).
- Reads only the **first 16 bytes** of the file to check the magic `EVF3`
  (this is a cached/stream context lookup — no full-file I/O, no buffers held
  across calls; the check is a few instructions for non-encrypted files).
- For encrypted files: consult an in-memory allow-list keyed by file ID
  (volume serial + file ID), holding a per-session random **epoch GUID**.
  - Not in the list → return `STATUS_ACCESS_DENIED`. The opening app shows
    "Access is denied." (The file's contents are never exposed.)
  - In the list → allow the open normally.
- Exposes a **communication port** (`FltSendMessage`) so the user-mode service
  can add/remove files from the allow-list and set the epoch.
- On boot / epoch change: the allow-list is empty, so **everything encrypted
  is locked until EchoVault unlocks it**.

### User-mode side (EchoVault service)

- A tiny always-running service (`EchoVaultSvc.exe`, started by the driver
  notification or at logon) holds the allow-list updates.
- When an open is denied and the file is encrypted, the driver posts a
  notification to the service → the service pops the **same password dialog
  EchoVault already uses** (screen-reader friendly, beep-free, focus lands in
  the box).
- Password verified → service tells the driver to allow the file → file is
  decrypted in place (existing `UnlockFileForOpen` logic) → the user's app
  opens the now-plain file.
- Viewer closes → existing auto re-lock runs → file removed from allow-list.

### Behavior summary

| Open path | Today (user mode) | With minifilter |
|---|---|---|
| Double-click (default) | Intercepted ✓ | Intercepted ✓ |
| "Open with" first click | Bypasses (garbage shown) | **Denied → prompt → opens in chosen app** |
| Folder open | Browsable (contents locked) | **Prompt on folder open** (filter checks any EVF3 file, incl. inside folders) |
| Program opens by path | Bypasses | **Denied → prompt** |

## Build & signing

- **Toolchain:** Visual Studio (2022 Community, free) + Windows Driver Kit (WDK).
  Kernel drivers cannot be built with the current MinGW toolchain — this is the
  one real requirement of the project.
- **Signing:** attestation signing via Microsoft Partner Center is **free**
  (the ~$100/yr EV cert is only needed for Windows Update/WHQL distribution —
  not for handing out the driver directly).
- **Dev/test machines:** enable test-signing (`bcdedit /set testsigning on`,
  admin + reboot) during development; production builds use the attestation
  signature (no test-signing mode needed for users).

## Failure modes & mitigations (the honest part)

- A kernel driver bug can bugcheck the system (BSOD) — including, in the worst
  case, audio glitches/freezes, which is your stated concern. This is inherent
  to ring-0, not a quality problem.
- Mitigations to keep risk minimal:
  - The filter **never writes** to files and never buffers data across calls —
    it only inspects a fixed 16-byte header and returns allow/deny.
  - Non-EVF3 files cost a few instructions and are fully pass-through.
  - The allow-list lives in kernel memory keyed by file ID + epoch; a stale
    entry can only *allow* an open, never corrupt data.
  - If the driver fails to load (bad signature, missing dependency), the system
    **boots normally and EchoVault falls back to today's user-mode behavior** —
    the driver is never a hard dependency.
  - Uninstall removes the filter (with a reboot), restoring exact current
    behavior.
- Design review + test matrix (open types, offline USB copies, locked files,
  memory-mapped reads) before any release.

## Phased plan

1. **Phase 1 (prototype):** deny-only filter on IRP_MJ_CREATE for EVF3 files
   + manual unlock via `--unlock` CLI. Proves the gate and the signing flow.
2. **Phase 2 (product):** service + communication port + auto-prompt on deny +
   folder-level gate; integrate with existing unlock/re-lock/relock logic.
3. **Phase 3 (release):** attestation-signed installer integration, Watcher
   task awareness, README updates.

## What does NOT change

- EVF3 format, vault.db, master password, recovery key — all unchanged.
- All current user-mode interception stays (the driver is belt-and-braces on top).
- Portability: an encrypted file still unlocks on any machine (password is in
  the file header; no machine binding).

## Status — Phase 2 + 3 written, safety + watcher fixes verified (August 2026)

- `driver/EchoVaultFilter.c` — the Phase 2 minifilter: deny + allow-list
  (incl. folder/prefix entries), per-boot epoch, fail-open, zero
  file-content access, and the deny notification (work item + port).
- `driver/EchoVaultFilter.inf` — service registration INF.
- `shared/evfilter.h` — kernel/user message protocol + notify struct.
- `filterctl/filterctl.c` — user-mode control tool (`add`/`allow`/
  `disallow`/`remove`/`clear`/`status`, plus the safety verbs
  `load`/`disable`/`enable`); builds and runs here with MinGW.
- `filterio.h/.cpp` — user-mode port helper wired into EchoVault itself:
  auto-register on encrypt, allow/disallow around unlock & re-lock, the
  `--guard` service (auto-prompt on denied opens), `--filter-status`.
  Guard + watcher both self-heal via scheduled tasks. All best-effort
  no-ops when the driver is absent — verified (selftest passes, guard
  exits cleanly without the driver).
- `driver/README-DRIVER.md` — build (VS + WDK), signing (test-signing for
  dev, free attestation for release), install, safety analysis.

**Phase 3 (app fidelity) written:** the deny notification now carries the
requestor's image base name; the guard reopens the unlocked file in the SAME
app ("Open with → Notepad" stays Notepad). User-mode launch verified here;
kernel capture reviewed but unbuilt (needs WDK, as always).

**App-exclusion list added (backup/indexer tools):** the driver now has a
small allow-list of image base names (`filterctl exclude backup.exe`) that
may open locked files — safe by construction because they only ever see
ciphertext without the password, and it makes backups of locked files
possible (blocking them would be a data-loss risk). The matching logic
lives in `shared/evtable.h` and is verified: **48/48** logic checks pass
(add/remove/check, case-insensitivity, exact-match semantics, idempotence,
overflow, over-long names). Kernel wiring reviewed but unbuilt (needs WDK).

**Watcher CPU bug found and fixed (verified):** the association watcher was
burning ~6% of a core continuously — a 1-second polling sweep that touched
67 extensions' `UserChoice` paths per second, and those accesses are slow
(~0.5 ms each) because Defender's tamper protection hooks them; the sweep
also unconditionally fired a shell notification that looped back into
itself. Fixed by (1) only notifying when a `UserChoice` was actually
removed, (2) probing existence before deleting, and (3) making the watcher
event-driven — a registry notification on `FileExts` + the existing shell
notification are the triggers, the timer is now a 30-second safety net, and
sweeps are throttled to once per second. Verified: watcher CPU went from
~0.8 s per 15 s to **0.000 s per 20 s**, and an injected "Open with"
override is still reverted in ~0.3 s.

**Crash-safety layer (added August 2026, all user mode, all tested on this
machine):** `filterstate.h/.c` + the `filterctl load/disable/enable` verbs
and `status` report make a driver crash *survivable*: the driver never
auto-loads (demand-start), `disable` is a persistent off-switch, `status`
detects unexpected shutdowns via the Event Log (6008) and warns loudly if
the machine crashed while the driver was loaded, and `load` refuses to
restart the driver after such a crash unless given `--force`. Verified
end-to-end here with an injected fake event log: crash warning, load
refusal, `--force` bypass, off-switch cycle, clean-unload branch — all
correct.

The kernel source cannot be compiled in this environment (no WDK); it must
be built on a Windows machine with Visual Studio + WDK and tested first in a
VM or non-critical machine, exactly as the guide describes.
