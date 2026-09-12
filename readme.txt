EchoVault 1.1 beta - driver-free preview
By Thundercloud

START HERE
This build does not install, start, or communicate with EchoVault's experimental
kernel driver. No test-signing change, reboot, or virtual machine is required.
It does not remove an older driver already installed on your computer.
Use copies of unimportant files for your first test. This is not a security-audited
or crash-certified release. Keep independent, tested backups.

FIRST RUN
Run EchoVault.exe, or install with the versioned Setup.exe if provided.
Create a strong master password and save the recovery key somewhere private.
Do not use a date of birth or another easily guessed password.
The optional Explorer setup adds right-click actions and registers EchoVault
as an available app. It does not change Windows' current default apps.

ENCRYPT FILES OR FOLDERS
Choose Add to Vault (Encrypt), select a file or folder, and confirm.
Set the file password, then enter your master password when asked.
Files keep their paths, names, and extensions. Locked files are marked read-only
to reduce accidental overwriting by an editor. This attribute is not a security
boundary: other software or a person can remove it.

A folder is a batch of files, NOT a locked container. Existing file contents
are encrypted recursively. Folder names and file names remain visible and the
folder still opens in Explorer. Newly added files are NOT automatically encrypted.
Do not select system folders, application folders, cloud placeholders, or links.
Hard-linked files and files with named NTFS streams (including download-origin
metadata) are refused rather than silently dropping metadata or leaving aliases.
Inaccessible entries and links cause the initial folder scan to stop without changes.
Keep all programs using the selected files closed until the operation finishes.
A batch is not all-or-nothing: check the succeeded/failed counts.
There is a 127 MiB limit per plaintext file in this low-memory preview.
Encrypted input is limited to 128 MiB. Larger files are refused without replacement.

OPEN, EDIT AND RE-LOCK
Use Open encrypted file in EchoVault, or right-click > Open with EchoVault.
Enter that file's password. EchoVault decrypts it in its original location and
launches its original app, or offers Windows' Open With picker.
Save and close the document, then return to EchoVault's waiting dialog and press OK.
Wait for confirmation that the file is encrypted again.

Do NOT close EchoVault or shut down while editing an unlocked file.
If EchoVault or Windows crashes during this interval, the file can remain plain.
Temporary files, editor backups, autosaves and old SSD copies can contain plaintext.
EchoVault does not provide secure erasure or protection from malware on an unlocked PC.

DECRYPT PERMANENTLY
Choose Remove from Vault (Decrypt), or use the Lock/Unlock right-click action.
For folders, the entered password is tried on each encrypted file using its own salt.
Files using a different password or damaged data remain unchanged; inspect failures.
Successfully decrypted files stay unlocked until you encrypt them again.

DOUBLE-CLICK AND OPEN WITH
Choose Explorer setup and status in the main menu to register EchoVault and open
Windows Default Apps. Select EchoVault for the file types you want. This affects
all files of that type, not just encrypted ones. Plain files are forwarded to the
previous app when that app can be resolved. Setup registers common document, code,
image, audio and video types; encrypting another extension adds that type too.
Executable script types such as .bat, .cmd, .ps1, .vbs, .js and .py are excluded
from automatic default-app registration. Encrypt them only through EchoVault's
menu or right-click action; Windows must retain their normal execution handlers.
The Default Apps reminder is recorded after it is shown, so separate right-click
operations do not repeatedly display it.

If you choose Notepad or Notepad++ as the default later, future double-clicks may
show encrypted bytes rather than a password prompt. EchoVault cannot silently
override Windows' choice. Use Open with EchoVault, the main menu, or change the
default back in Windows Settings. Do not edit or save the encrypted bytes.
If no original application is known, EchoVault shows Windows' single-file Open
With dialog while the file is unlocked, then waits for you to save and close it.
That picker is for the current unlocked session only: it cannot make the editor
the extension's default and therefore cannot displace EchoVault for the next open.
There is no background takeover, scheduled guard, or startup watcher in this build.
The compatibility --watch mode only updates association-status.txt; it is not
started automatically. Explorer setup and status refreshes the same report.

TAKE FILES TO ANOTHER COMPUTER
Copy the WHOLE encrypted file (or the folder and all its files), install this
version or a newer compatible EchoVault, and use the file password.
The file password does not depend on the original path or vault.db.
The other computer's newly created master password cannot recover the old file.
Master recovery additionally needs the original vault.db and its matching master
password or recovery key. Back up vault.db from:
%LOCALAPPDATA%\EchoVault\vault.db
The recovery key by itself is not a substitute for that database.

COMPATIBILITY AND DAMAGE
New writes use EVF4: AES-256-GCM with authenticated headers and content, plus a
redundant header. Old EVF2/EVF3 files can still be decrypted; those old formats
do not authenticate their content. To migrate, decrypt and re-encrypt a backed-up copy.
Old EchoVault versions cannot read the new EVF4 files or newly GCM-wrapped master keys.
Never delete signatures or header fields. Redundancy may recover some header
damage, but damaged content, lost key material, or deleted files still require backups.

UNINSTALL
Choose another default app in Windows Settings for any types assigned to EchoVault.
Use the installer uninstaller, or run EchoVault.exe --uninstall-open to remove
EchoVault's Explorer entries. The app does not delete encrypted files or vault.db.
Decrypt/export files first or keep a compatible EchoVault executable and passwords.

TEST REPORTS
Automated file tests use a unique disposable directory and never need the driver.
A copyable report is produced by tests\test-app.ps1 in the source checkout.
See RELEASE-NOTES.md for the current validation boundary.
