#pragma once

#include <filesystem>
#include <string>

// --- Password dialog result ---

enum class PasswordResult { OK, Cancel, ForgotPassword };

struct PasswordAnswer {
    PasswordResult result = PasswordResult::Cancel;
    std::wstring   password;
};

// --- Main-menu actions ---

enum class MenuAction { Add, Remove, ChangeFilePw, ChangeMasterPw, Setup, Open, Exit };

// Shows the custom file/folder selection dialog.
// Returns an empty path if cancelled.
std::filesystem::path SelectTarget();

// Installs Windows Explorer right-click context menu hooks in the registry.
bool InstallRegistryHooks();

// Repairs only hazardous script associations previously owned by EchoVault.
// Leaves every unrelated user choice unchanged.
bool RepairScriptAssociations();

// --- Optional, user-controlled Explorer integration ---

// Shows setup/status and offers Windows Default Apps.
void ManageOpenInterception();

// Registers an AVAILABLE handler; Windows defaults are left to the user.
bool InstallOpenInterception();

// Removes integration entries, not encrypted files or the vault database.
bool UninstallOpenInterception();

bool IsOpenInterceptionInstalled();

// Adds/removes an extension as a candidate in Windows Default Apps.
bool AddOpenInterceptionExt(const std::wstring& ext);
bool RemoveOpenInterceptionExt(const std::wstring& ext);

// Registers a file type only when Explorer integration was explicitly enabled.
// Does not change the chosen default or start a background process.
void EnsureExtensionIntercepted(const std::wstring& ext);

// Compatibility name: refreshes a status report; never writes UserChoice.
void ReassertInterception();

// Opens a file with the program associated with it before interception
// was installed (falls back to the current registered handler, or the
// standard "Open with" picker if there is none). Returns the process id
// of the launched program, or 0 if nothing was launched (picker shown,
// launch failed, or the file is still encrypted and was refused).
// Opens a decrypted file with its normal (pre-interception) program.
// If appOverride is non-empty (the driver told us which app tried to
// open it — "Open with" fidelity), that app is used instead; falls
// back to the default program if it cannot be launched.
unsigned long OpenWithOriginalApp(const std::filesystem::path& filePath,
                                  const std::wstring& appOverride = L"");

// --- Background association watcher ---
//
// Compatibility mode only: refreshes association-status.txt every 30 seconds.
// Never changes defaults. Normal builds do not auto-start or schedule it.

// Starts the watcher process if it isn't already running. No-op otherwise.
bool StartAssocWatcher();
// Signals a running watcher to exit (called on uninstall).
void StopAssocWatcher();
// Watcher entry point (EchoVault.exe --watch). Runs until stopped or until
// open interception is uninstalled. Returns 0.
int RunAssocWatcher();

// Shows a masked password dialog with optional customizable "Forgot" button text.
PasswordAnswer PromptPassword(
    const std::wstring& title,
    const std::wstring& message,
    bool showForgot = false,
    const std::wstring& forgotText = L"Forgot Password?"
);

// Shows a dialog to enter the 64-hex-char recovery key.
// Returns empty string on cancel.
std::wstring PromptRecoveryKey();

// Displays the recovery key (and copies it to the clipboard).
void ShowRecoveryKey(const std::wstring& recoveryKeyHex);

// Shows the main menu.
MenuAction ShowMainMenu();

// Simple message boxes.
void ShowError(const std::wstring& title, const std::wstring& message);
void ShowInfo(const std::wstring& title, const std::wstring& message);
