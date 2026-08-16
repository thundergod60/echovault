# EchoVault Minifilter Driver — Phase 2 Build & Test Guide

This folder contains the **Phase 2 prototype** of the optional kernel driver
that gates *every* file open — including "Open with", folder opens, and
programs opening files by path. Phase 2 = **deny + auto-prompt**: when an
open of a locked file is denied, the driver notifies the **guard service**
(`EchoVault.exe --guard`, self-healing via a scheduled task), which pops
EchoVault's normal password dialog, unlocks, opens the file with its normal
program, and re-locks when the viewer closes.

**You do not need any of this for EchoVault to work.** The driver is purely
additive. If it is not loaded, EchoVault behaves exactly as it does today
(driver-less mode: double-click interception + the watcher).

---

## What the driver does

- On every file open (`IRP_MJ_CREATE`), it looks up the opened path in an
  in-memory table.
- Paths registered as **encrypted** are **denied** (`Access is denied`)
  unless they are in the current session's **allow-list**.
- Everything else passes through with a few instructions of overhead.

```
open file → driver checks path
  ├─ not registered encrypted  → ALLOW (99.99% of opens, zero effect)
  ├─ registered + allow-listed → ALLOW (while the user is viewing it)
  └─ registered + not allowed  → DENY  (STATUS_ACCESS_DENIED)
```

## Safety design (why this one is low-risk)

1. **The filter never touches file contents.** No reads, no writes, no
   buffers held across calls. It only compares path strings. There is no
   code path where encrypted data passes through the kernel.
2. **Fail-open.** Any error, unknown path, or uncertain state → the open is
   allowed. Denial happens *only* for paths explicitly registered as
   encrypted that are not allow-listed. The worst case of a driver bug is
   today's behavior (file opens, shows garbage) — never data loss.
3. **Bounded, tiny work.** The hot path is a fast-mutex + case-insensitive
   string compare over a small table. No I/O under the lock, no spin loops,
   no interrupts touched. **Nothing in this design interacts with the audio
   stack at all** — it does not hold IRQL, does not run timers, and does not
   touch devices. Your sound/screen-reader concern applies to kernel bugs in
   general, not to this code path specifically.
4. **Per-boot epoch.** The allow-list is stamped with a random value created
   at driver load, so nothing stays unlocked across a reboot.
5. **Optional by construction.** If the driver fails to load, is unsigned,
   or is uninstalled, the system boots and EchoVault keeps working
   (user-mode mode). The driver never writes to disk, so there is no state
   to corrupt.

Residual risk (honest): any kernel code can bugcheck if it has a bug. This
driver is deliberately minimal, but it must still be **tested in a VM or a
non-critical machine before touching a production system** — that is step 1
below, not optional.

## What it gates (Phase 1)

| Open path | Today (user mode) | With driver loaded |
|---|---|---|
| Double-click (default) | Intercepted | Intercepted |
| "Open with" → pick app | First click bypasses | **Denied → prompt → opens in chosen app** |
| Folder open (Explorer) | Browsable | **Denied → prompt** |
| Program opens by path | Bypasses | **Denied → prompt → opens** |
| Non-encrypted files | Pass-through | Pass-through (unaffected) |

## Building (requires a Windows machine with the WDK)

Kernel drivers **cannot** be built with the MinGW toolchain used by the rest
of EchoVault. You need:

1. Visual Studio 2022 Community (free) with the **Desktop development with
   C++** workload.
2. **Windows Driver Kit (WDK)** for Windows 10/11 (free, from Microsoft),
   installed with the VS integration.
3. Create a new project: **File → New → Project → "Kernel Mode Driver,
   Empty"** (C++), name it `EchoVaultFilter`.
4. Add `EchoVaultFilter.c` from this folder and the shared header
   `..\shared\evfilter.h` to the project.
5. Set the solution platform to **x64**, build.
   → produces `EchoVaultFilter.sys`.

`EchoVaultFilter.inf` is included for registering the driver as a service;
for quick development you can also load it directly (below).

## Signing

- **Development:** enable test-signing once (admin):
  `bcdedit /set testsigning on` then **reboot**. With test-signing on,
  unsigned kernel drivers load.
- **Production (free):** Microsoft **attestation signing** via Partner Center
  — free, no $100 EV certificate needed for a driver you distribute directly
  (EV signing is only required for Windows Update / WHQL distribution).
  After attestation signing, users do NOT need test-signing mode.

## Installing & loading (development)

```bat
:: Register as a service (from the driver folder):
fltmc load EchoVaultFilter        :: after INF install, or
sc create EchoVaultFilter type= kernel binPath= <full path to .sys>
fltmc load EchoVaultFilter

:: Verify:
fltmc filters                   :: lists loaded filters
fltmc instances                 :: attached volumes

:: Remove:
fltmc unload EchoVaultFilter
sc delete EchoVaultFilter
```

## Using it — driver control (filterctl)

Build the control tool: `cd filterctl && mingw32-make` (any toolchain).

```bat
:: Gate control (need the driver loaded):
filterctl add     C:\secret\file.txt     :: register as encrypted
filterctl allow   C:\secret\file.txt     :: unlock BEFORE decrypting
filterctl disallow C:\secret\file.txt    :: lock again after re-encrypt
filterctl remove  C:\secret\file.txt     :: unregister after full decrypt
filterctl clear                         :: forget everything (paths + exclusions)
filterctl exclude   backup.exe          :: let an app open locked files
filterctl unexclude backup.exe          :: revoke that

:: Safety control (work even without the driver):
filterctl status                        :: full state report — is the
                                          driver loaded? off-switch set?
                                          was the last shutdown clean?
filterctl load [--force] [path-to-sys]  :: start the driver (admin).
                                          REFUSES after a crash unless
                                          --force.
filterctl disable                       :: panic off-switch: unload now,
                                          keep it unloaded across reboots
filterctl enable                        :: clear the off-switch
```

## App exclusions (backup / indexer tools)

By default the driver denies **every** un-allow-listed open of a locked
file — including backup and indexing tools. That would silently prevent
backups of locked files, which is itself a data-loss risk. Use:

```
filterctl exclude backup.exe
filterctl exclude Everything.exe
```

An excluded app may open locked files. **This is safe by construction:**
without the master password the file on disk is ciphertext, so an excluded
app can copy/read it but can never see the contents. Exclusions match the
process image base name, case-insensitively and exactly
(`backup.exe` matches `BACKUP.EXE`, not `backup2.exe`). They are global
and persist for the driver session; `filterctl unexclude` or
`filterctl clear` revokes them.

## Security notes (what actually protects your files)

- **Confidentiality** (nobody reads your data): the EVF3 encryption itself
  — ciphertext is useless without the master password, whether read by a
  virus, a person, or an excluded backup tool.
- **Integrity / anti-tamper** (nobody modifies or deletes): every read,
  write, and delete must open the file first, and the driver gates that
  open — so while it is loaded, an un-allow-listed app cannot modify or
  delete a locked file through the filesystem. (Without the driver, use
  Windows' built-in Controlled Folder Access for this layer.)
- Backups of locked files are possible via exclusions, so a lost disk does
  not mean lost data.

## What if it crashes? (the survivability layer)

Any kernel code can bugcheck — no design changes that. What this project
adds is a **survivability layer** so a crash is never permanent, never
silent, and never repeated by accident:

1. **The driver is demand-start and never auto-loads.** After any reboot —
   clean or crashed — the driver is simply not running. The machine always
   boots; your screen reader always comes back. A crash's cost is one
   reboot, and only while the driver was explicitly loaded.
2. **The driver never touches file contents.** There is no data-loss path:
   a crash interrupts an open, it cannot corrupt encrypted data.
3. **The off-switch survives reboots.** `filterctl disable` unloads it and
   writes a persistent marker; `filterctl load` refuses to start while the
   marker is set (cleared by `filterctl enable`). One command, works even
   with the driver absent.
4. **Crashes are detected, not guessed.** `filterctl load` records when it
   loads the driver and when it is cleanly unloaded. `filterctl status`
   checks Windows' own Event Log (Event 6008 = unexpected shutdown) and, if
   the machine went down abnormally while the driver was loaded and never
   cleanly unloaded, prints a clear WARNING and `filterctl load` **refuses**
   to restart it unless you pass `--force`. The driver stays off after a
   crash until you explicitly choose to reload it.

The state lives in plain user-mode registry values
(`HKCU\Software\EchoVault\Filter`), so all of this works even when the
kernel component isn't installed.

## How EchoVault itself uses the driver (Phase 2 integration)

All of this is **automatic and best-effort** — silent no-ops when the driver
is not loaded, so the driver-less experience is unchanged:

- **Encrypt** (`EncryptTarget`): allow → encrypt → `add` (locked).
  Folders are registered as prefix entries (trailing `\`), so the folder
  itself AND everything under it is gated.
- **Unlock on open** (`--open`, `--guard`): allow → prompt → decrypt → open
  with the normal program → viewer closes → re-encrypt → deny.
- **Remove from Vault / change password**: allow → decrypt → `remove`
  (or re-`add` after re-encrypting with the new password).
- **Guard service** (`EchoVault.exe --guard`): sits on the driver's
  notification port. Every denied open pops the normal password dialog,
  unlocks, opens the file, and re-locks on close. **Phase 3 (app
  fidelity):** the deny notification carries the requesting program's
  base name (e.g. `notepad.exe`), so after unlock the file reopens in
  the SAME app the user chose ("Open with → Notepad" stays Notepad),
  falling back to the default program only if that app is gone.
  Self-healing: scheduled task `EchoVaultGuard` (logon + every 1 minute
  + restart on failure), same pattern as the watcher task.

## Who survives being killed? (user-mode vs kernel)

A user-mode process (watcher, guard) can be killed by any process running
as the same user — that is unavoidable without a Microsoft-signed
protected process. The impact is bounded, though:

- **Killing them never exposes contents.** Encryption is the wall; the
  watcher only reverts "Open with" overrides and the guard only pops the
  password prompt. Their loss costs convenience, never confidentiality.
- **The kernel driver cannot be killed from user mode at all.** Only an
  administrator can unload it (`fltmc unload`), which the `filterctl
  status` report surfaces. This is why the driver is the strong gate and
  the user-mode pieces are its convenience layer.
- **Recovery is now tight and verified:** both tasks refire every 1
  minute and at logon (each firing exits instantly if the process is
  already running, so this is nearly free), and every double-click
  (`--open`) revives the watcher on the spot. Verified live: killed
  watcher → revived instantly by a double-click; killed watcher → revived
  by the task refire within seconds.
- **Diagnostics**: `EchoVault.exe --filter-status` (exit 0 = driver
  reachable; prints the full state report when run from a console),
  `EchoVault.exe --guard` (run the guard in the foreground). The same
  report plus the safety verbs live in `filterctl status / load / disable /
  enable`.

## Known limitations (by design)

- The denied app shows its own **"Access is denied"** dialog for the open
  that was denied, and EchoVault then opens the file itself after unlock
  (with the same app, Phase 3).
- Files encrypted **on another machine** and copied here are not registered,
  so they pass through until EchoVault touches them. (The driver gates what
  EchoVault knows about; it never guesses by reading file contents.)
- While a file is unlocked (viewing), its entry stays allow-listed, so
  anything can open it until the viewer closes and it re-locks.
- A cancelled unlock re-denies the path (the RAII gate in the vault code).
- Denies ALL opens of a locked path (including backup tools). This
  is a feature — encrypted content is not readable by anything — but it is
  stricter than the final design may want.
- The driver resolves the requesting app by its **image base name**
  (`PsGetProcessImageFileName`), which is path-less; user mode finds the
  exe via App Paths / the standard search. Ambiguous base names (rare) fall
  back to the default program.

## Phase 3 — written (August 2026)

- **Requesting-app fidelity** (done): the driver captures the requestor's
  image base name in the deny notification (`EVFILTER_NOTIFY.RequesterApp`);
  the guard reopens the unlocked file with that app via `ShellExecuteEx`
  (App Paths resolution). The user-mode half is built and verified here
  (`ShellExecuteEx("notepad.exe", file)` launches Notepad with the file);
  the kernel capture is written and reviewed but must be compiled and
  VM-tested with the rest of the driver.
- Remaining: optional exclusions (backup / indexer), and installation of
  the attestation-signed driver by the setup program.
