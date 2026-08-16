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

enum class MenuAction { Add, Remove, ChangeFilePw, ChangeMasterPw, Exit };

// Shows the custom file/folder selection dialog.
// Returns an empty path if cancelled.
std::filesystem::path SelectTarget();

// Installs Windows Explorer right-click context menu hooks in the registry.
bool InstallRegistryHooks();

// --- Open interception (auto-unlock on double-click) ---

// Shows the install/uninstall dialog for open interception.
void ManageOpenInterception();

// Registers EchoVault as the default handler for common extensions,
// backing up the original handlers first. Silent; returns success.
bool InstallOpenInterception();

// Restores the original handlers and removes all EchoVault data.
bool UninstallOpenInterception();

bool IsOpenInterceptionInstalled();

// Adds/removes an extension (e.g. ".py") to the interception list and
// re-applies the interception so it takes effect immediately.
bool AddOpenInterceptionExt(const std::wstring& ext);
bool RemoveOpenInterceptionExt(const std::wstring& ext);

// Makes sure an extension is intercepted (mapped to EchoVaultOpen, its
// UserChoice override removed). Called automatically whenever a file is
// encrypted, so ANY file type gets covered on the spot. Idempotent.
void EnsureExtensionIntercepted(const std::wstring& ext);

// Deletes any "Open with" UserChoice override for every extension
// EchoVault has taken over. Called by the watcher and at the start of
// every --open, so the mapping self-heals even if the watcher is down.
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
// When a user picks another app via "Open with", Windows writes a
// UserChoice key that overrides the extension's default handler, so the
// NEXT double-click would bypass EchoVault entirely. The watcher (a tiny
// hidden-window process, ~0% CPU when idle) re-asserts our mapping: it
// reacts to shell association-change notifications and also does a
// low-frequency sweep, deleting UserChoice overrides for every extension
// EchoVault has taken over.

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