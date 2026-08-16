;----------------------------------------------------------------------------
; EchoVault installer - Inno Setup 6 script
;
; 1. Install Inno Setup 6: https://jrsoftware.org/isinfo.php
; 2. Put this file next to EchoVault.exe and README.md, then either
;    open it in the Inno Setup IDE and press Build, or run:
;       ISCC.exe installer.iss
; 3. Output: output\EchoVault-Setup.exe
;
; The installer is per-user (no administrator prompt), uses standard
; Windows wizard dialogs (keyboard / screen-reader friendly), and its
; uninstaller restores the user's original file associations.
;----------------------------------------------------------------------------

#define MyAppName    "EchoVault"
#define MyAppVersion "1.0.0"
#define MyAppExeName "EchoVault.exe"

[Setup]
AppId=0C1A2B3C-4D5E-4F6A-8B9C-0D1E2F3A4B5C
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Thundercloud
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=high
OutputDir=output
OutputBaseFilename=EchoVault-Setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
; "uninsneveruninstall" keeps EchoVault.exe available while the uninstaller
; runs the association cleanup below; [UninstallDelete] removes it after.
Source: "EchoVault.exe"; DestDir: "{app}"; Flags: ignoreversion uninsneveruninstall
Source: "README.txt";     DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Restore the user's original file associations (notepad, etc.) before
; the program files are removed. Silent: returns via exit code only.
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall-open"; Flags: runhidden

[UninstallDelete]
Type: files; Name: "{app}\{#MyAppExeName}"
