# EchoVault Minifilter — Build & Test Runbook

How to actually compile the driver and test it, on your machine (i3, 4 GB
RAM, screen reader). Written as numbered, keyboard-friendly steps.

**The golden rule: all driver testing happens inside a Virtual Machine.
A crash there costs nothing (the VM just restarts). Your real machine and
your screen reader are never at risk from testing.**

> **Storage reality check (August 2026):** this laptop has only ~0.1 GB
> free, so a VM is NOT possible right now, and the local toolchain
> (EWDK/VS) is too heavy too. **The build does not need your machine at
> all:** use the cloud workflow (Part B, Option C) — GitHub Actions builds
> the driver for free and you download only the finished ~50 KB `.sys`.
>
> **Good news:** the driver's *gate logic* is already verified WITHOUT a VM
> (`driver/test-evtable.exe` — 32/32 checks, compiled and run on this
> machine; the driver uses the exact same shared logic). The VM's only
> remaining job is to test the kernel plumbing end-to-end — worthwhile,
> but not a blocker for trusting the deny/allow decisions, and it can be
> done on ANY machine with space (a friend's computer, a lab machine),
> not necessarily this one.

---

## Part A — Set up the VM (one-time)

Your machine is **Windows 10 Home** (so Hyper-V and Windows Sandbox are not
available) with an i3-1005G1 (virtualization-capable). Two fully
screen-reader-friendly options:

### Option A (recommended): VirtualBox, driven by VBoxManage (no GUI ever)

VirtualBox's *manager window* is the inaccessible part — so we never open
it. Everything is typed commands; the only normal window is the VM itself
when Windows installs (and Narrator works fine inside a plain VM window).

1. Install VirtualBox (free, virtualbox.org). Ignore the manager window.
2. Create the VM — all from a command prompt in the folder where you want
   the disk:
   ```
   VBoxManage createvm --name WinTest --ostype Windows10_64 --register
   VBoxManage modifyvm WinTest --memory 2048 --cpus 1 --graphicscontroller vmsvga
   VBoxManage createmedium disk --filename WinTest.vdi --size 40960
   VBoxManage storagectl WinTest --name SATA --add sata --controller IntelAhci
   VBoxManage storageattach WinTest --storagectl SATA --port 0 --device 0 --type hdd --medium WinTest.vdi
   VBoxManage storageattach WinTest --storagectl SATA --port 1 --device 0 --type dvddrive --medium "C:\path\to\Win10.iso"
   VBoxManage modifyvm WinTest --boot1 dvd --boot2 disk
   VBoxManage startvm WinTest
   ```
   (Memory is 2 GB — keep it there; your host needs the rest.)
3. Install Windows 10 in the VM window. Narrator is built into Windows, so
   you can drive the installer by voice/keys like on your real machine.
   Inside the VM: Settings → Ease of Access → turn off animations.
4. Inside the VM, enable test-signing (admin Command Prompt):
   ```
   bcdedit /set testsigning on
   ```
   then shut the VM down (`shutdown /s /t 0`) and start it again with
   `VBoxManage startvm WinTest`.
5. Share the project folder so both machines see it:
   ```
   VBoxManage sharedfolder add WinTest --name project --hostpath "C:\Users\Lenovo\Desktop\password manager" --automount
   ```
   Inside the VM it appears as `E:\project\...`.

### Option B: QEMU (pure command line) — if your machine allows it

QEMU is completely command-line, so it is fully accessible too. It needs
an acceleration feature first (admin command prompt):

```
dism /online /enable-feature /featurename:HypervisorPlatform /all /norestart
```

If that succeeds (it works on many Home installs), reboot and use:

```
qemu-img create -f qcow2 WinTest.qcow2 40G
qemu-system-x86_64 -machine q35 -accel whpx -cpu max -m 2048 -smp 2 ^
  -drive file=WinTest.qcow2 -cdrom C:\path\to\Win10.iso -boot d ^
  -netdev user,id=n0,hostfwd=tcp::2222-:22 -device e1000,netdev=n0
```

If `HypervisorPlatform` refuses to enable on Home, just use Option A —
VirtualBox does not need it. (QEMU without acceleration is too slow on
this hardware.)

Either way: the VM only runs while you test; shut it down when done so it
doesn't eat your 4 GB.

## Part B — Build the driver

### Option C (recommended, zero storage): build in the cloud

Push this project to a GitHub repository, then open the **Actions** tab →
**Build EchoVault driver** → **Run workflow**. GitHub installs the WDK on
its own machine, builds `EchoVaultFilter.sys`, and offers it as a download
("Artifacts") — a file of a few dozen KB. Nothing is installed or stored
on your laptop. This is free and works for private or public repos.

### Option A (no Visual Studio): the Enterprise WDK (EWDK)

Microsoft publishes a self-contained, command-line-only driver toolchain:
the **EWDK**. No installation, no VS — just download an ISO, mount it,
build.

1. Download the latest **EWDK** ISO from Microsoft
   (learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk —
   the "Enterprise WDK" section; it's a few GB, one-time download).
2. Right-click the ISO → Mount (it becomes a drive, e.g. `F:`).
3. Open a command prompt and run the build environment:
   ```
   F:\LaunchBuildEnv.cmd
   cd /d C:\Users\Lenovo\Desktop\"password manager"\driver
   msbuild EchoVaultFilter.vcxproj /p:Configuration=Release /p:Platform=x64
   ```
4. The driver appears at `x64\Release\EchoVaultFilter.sys`.

That's the whole build — three commands, fully keyboard-driven.

### Option B: Visual Studio 2022 Community (GUI, larger)

1. Install **VS 2022 Community** (free) with only the **"Desktop development
   with C++"** workload, then the **Windows Driver Kit (WDK)**. The
   download is big and the install is slow on an i3 — expect 30-60 minutes
   once. Disk usage ~8 GB.
2. Open **`EchoVaultFilter.vcxproj`** (already configured for the WDK
   toolset, x64) and Build Solution → `x64\Release\EchoVaultFilter.sys`.
   If the project file gives any trouble: New → "Kernel Mode Driver,
   Empty" → add `EchoVaultFilter.c` + `..\shared\evfilter.h` → x64 → build.

Build the user-mode tools (already built for you, redo if changed):
```
cd filterctl
mingw32-make
```
This produces `filterctl.exe`. Also copy `EchoVault.exe` from the project
root.

## Part C — Copy into the VM and test

1. In VirtualBox, enable a **Shared Folder** (Device menu → Shared Folders)
   pointing at this project folder. Inside the VM it appears as e.g.
   `E:\`.
2. Inside the VM, open an **administrator** Command Prompt. The control
   tool wraps the raw driver commands (and records load/unload state for
   the crash safety layer), so prefer it:
   ```
   cd /d E:\filterctl
   filterctl load E:\driver\x64\Release\EchoVaultFilter.sys
   filterctl status
   ```
   `filterctl status` shows the driver as loaded. If load fails, check
   `sc query EchoVaultFilter` — usually it means test-signing is not on
   (Part A, step 4). The raw commands are `sc create EchoVaultFilter
   type= kernel binPath= E:\driver\x64\Release\EchoVaultFilter.sys` and
   `fltmc load EchoVaultFilter`.
3. Test the gate (this is the whole point):
   ```
   cd /d E:\filterctl
   filterctl status
   echo secret stuff > C:\test.txt
   filterctl add C:\test.txt
   notepad C:\test.txt
   ```
   Notepad should show **"Access is denied"** (or nothing). Then:
   ```
   filterctl allow C:\test.txt
   notepad C:\test.txt
   ```
   Notepad opens it (if EchoVault's association interception is active in
   the VM, you'll get the password prompt instead — either way the file
   must NOT open while locked).
   ```
   filterctl disallow C:\test.txt
   notepad C:\test.txt
   ```
   Denied again. `filterctl remove C:\test.txt` unregisters.

   Try the safety verbs too — they work without the driver:
   ```
   filterctl disable    :: panic off-switch (unload + keep unloaded)
   filterctl status     :: report shows the off-switch
   filterctl load ...   :: refuses while the off-switch is set
   filterctl enable     :: clear it, then load again
   ```
   To test the crash stand-off: load the driver, then pull the VM's power
   (VM menu: close → power off — a fake crash), restart, and run
   `filterctl status`. It should warn that the last shutdown was
   unexpected while the driver was loaded, and `filterctl load` should
   refuse until you pass `--force`.
4. Test the full EchoVault flow: run `EchoVault.exe` in the VM, encrypt
   `C:\test.txt`, then try opening it with Notepad and via "Open with" —
   with the driver loaded, both must refuse until the password is entered,
   then open, then re-lock.
5. Optionally run **Driver Verifier** for deeper checking (advanced):
   ```
   verifier /standard /driver EchoVaultFilter.sys
   ```
   then restart the VM and run the tests again. Driver Verifier makes the
   system catch kernel API misuse that would otherwise pass silently.
6. When done: shut down the VM. Nothing on your real machine has changed.

## Part C½ — Snapshot (do this once, saves reinstall forever)

Right after Windows is installed and test-signing is on, take a snapshot:

```
VBoxManage snapshot WinTest take "clean-base"
```

Now every driver test starts from a known-good state: if a test blue-screens
the VM or leaves it in a weird state, restore in seconds:

```
VBoxManage snapshot WinTest restore "clean-base"
VBoxManage startvm WinTest
```

No reinstall, ever. This also fixes the NVDA freeze worry: the freezing
happens during the one-time Windows install (heavy disk + CPU on a 4 GB
machine). Run that install when you don't need the host (e.g. overnight),
and from then on the VM is light enough to use while your screen reader
runs.

## Storage tips

- Delete the Windows ISO after install (saves ~5 GB).
- The VM disk (VDI) only grows as it is used — start it at 40 GB virtual,
it will actually occupy ~15-20 GB.
- Snapshot also uses disk; keep just the one "clean-base".
- If the laptop is chronically full, put the VM folder on an **external
  USB drive** (slower, but fine for testing).

## Part D — Cleanup / recovery

- In the VM: `fltmc unload EchoVaultFilter`, `sc delete EchoVaultFilter`.
- If the VM ever blue-screens: just restart the VM (or restore the
  "clean-base" snapshot). The VM's hard disk is isolated — your real
  machine is untouched.
- Because this driver is **demand-start** (it only runs when you explicitly
  load it), it can never break Windows booting. If you ever want it off:
  `sc delete EchoVaultFilter` from Safe Mode if needed.

## Part E — Production signing (free) — only if you ship the driver

- Microsoft **attestation signing** via Partner Center is free and does NOT
  need the $100 EV certificate. After signing, users load the driver
  WITHOUT test-signing mode.
- Details: search "attestation signing kernel driver" on Microsoft's
  driver-signing docs (or ask me for a step-by-step when you get there).

---

## The honest risk picture

- **In the VM:** a bug = a VM restart. Cost: a minute. This is why the VM
  step is mandatory, not optional.
- **On your real machine:** the driver only ever runs when you load it
  (it does not auto-start at boot), it is fail-open, and it never touches
  file contents — so the residual risk after VM testing + signing is small.
  "Small" is not "zero": any kernel code can bugcheck. The final call on
  loading it on your daily machine is always yours, and it stays fully
  optional — EchoVault works without it.
