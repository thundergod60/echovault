//------------------------------------------------------------
// main.cpp  —  EchoVault entry point
//------------------------------------------------------------

#include <windows.h>
#include <filesystem>
#include <vector>
#include <cstring>
#include <shellapi.h>

#include "vault.h"
#include "security.h"
#include "ui.h"
#include "filterio.h"
#include "filterstate.h"

// ---- Globals ----------------------------------------------------

static std::vector<unsigned char> g_MasterKey;

// ---- Forward declarations ---------------------------------------

static bool Initialize();
static void Shutdown();

static std::vector<unsigned char> Authenticate();
static std::vector<unsigned char> HandleForgotPassword(VaultHeader& hdr);

// On-demand Master Key retrieval
std::vector<unsigned char> GetMasterKeyOnDemand()
{
    if (g_MasterKey.empty())
    {
        if (IsFirstRun() && !FirstRunWizard()) return {};
        g_MasterKey = Authenticate();
    }
    return g_MasterKey;
}

// ---- Shared: unlock -> open -> wait -> re-lock ------------------
// Used by --open (double-click) and --guard (a driver-denied open).
// The driver allow-list is managed inside UnlockFileForOpen (allows for
// the duration, denies on failure); on success we keep it allow-listed
// while the viewer runs, then re-deny after re-locking.
static void HandleUnlockAndOpen(const std::filesystem::path& target,
                                const std::wstring& requesterApp = L"")
{
    auto unlock = UnlockFileForOpen(target);
    if (!unlock.success)
        return;

    if (std::filesystem::is_regular_file(target) && IsEncrypted(target))
    {
        ShowError(L"EchoVault",
            L"This file is still encrypted and could not be unlocked.\n"
            L"It was NOT opened.");
        EvDenyFor(target.wstring());
        return;
    }

    OpenWithOriginalApp(target, requesterApp);
    // Editors may reuse an existing process. A launcher PID is not evidence
    // that the document has closed; relock only after explicit confirmation.
    MessageBoxW(nullptr,
        (L"The file is now UNLOCKED in its original location:\n" + target.wstring() +
         L"\n\nSave and close the document in its app, then return here and press OK to lock it again. "
         L"Do not shut down or close EchoVault while this file is unlocked. "
         L"If EchoVault or Windows stops, the file can remain unencrypted.").c_str(),
        L"EchoVault - Save and close, then lock", MB_OK | MB_ICONWARNING);
    while (!RelockFile(target, unlock)) {
        if (MessageBoxW(nullptr,
            (L"Could not lock this file. It is still UNENCRYPTED:\n" + target.wstring() +
             L"\n\nClose apps using it and check free disk space. Retry to try locking again. "
             L"Cancel leaves it unencrypted; use Encrypt in EchoVault afterward.").c_str(),
            L"EchoVault - File still unlocked", MB_RETRYCANCEL | MB_ICONERROR) != IDRETRY) break;
    }
    if (IsEncrypted(target)) {
        EvDenyFor(target.wstring());
        ShowInfo(L"EchoVault", L"The file is encrypted again.");
    }
    SecureZeroMemory(unlock.fileKey.data(), unlock.fileKey.size());
}

// ---- Guard service (EchoVault.exe --guard) ----------------------
// Listens on the minifilter's notification port; every denied open of a
// locked file triggers the normal unlock -> open -> re-lock flow. Exits
// quietly when the driver is not loaded (the task re-fires every 5 min).
static int RunGuard()
{
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"EchoVaultGuard");
    if (!hMutex)
        return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(hMutex);   // another guard is already running
        return 0;
    }

    int rc = EvGuardLoop([](const std::wstring& path, const std::wstring& app) {
        std::filesystem::path p(path);
        if (std::filesystem::is_directory(p))
        {
            // A denied FOLDER open: prompt once and permanently decrypt
            // the whole folder (DecryptTarget handles the prompt and
            // unregisters the driver gate).
            DecryptTarget(p);
        }
        else
        {
            HandleUnlockAndOpen(p, app);
        }
    });

    CloseHandle(hMutex);
    return rc;
}

//====================================================================
// WinMain
//====================================================================

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    if (!Initialize())
        return 1;

    // ---- Headless modes (run before the first-run wizard / any UI) ----
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv)
        {
            if (argc >= 2 && wcscmp(argv[1], L"--selftest") == 0)
            {
                int rc = RunSelfTest(argc >= 3 ? std::filesystem::path(argv[2]) : std::filesystem::path{});
                LocalFree(argv);
                Shutdown();
                return rc;
            }
            if (argc >= 2 && wcscmp(argv[1], L"--uninstall-open") == 0) {
                bool ok = UninstallOpenInterception();
                LocalFree(argv); Shutdown(); return ok ? 0 : 1;
            }
            if (argc >= 2 && wcscmp(argv[1], L"--watch") == 0)
            {
                int rc = RunAssocWatcher();
                LocalFree(argv);
                Shutdown();
                return rc;
            }
            if (argc >= 2 && wcscmp(argv[1], L"--guard") == 0)
            {
                int rc = RunGuard();
                LocalFree(argv);
                Shutdown();
                return rc;
            }
            if (argc >= 2 && wcscmp(argv[1], L"--filter-status") == 0)
            {
                int rc = EvFilterAvailable() ? 0 : 1;
                // Print the full state report if we were launched from a
                // console (cmd / PowerShell); exit code stays the machine
                // check: 0 = driver reachable, 1 = not.
                if (AttachConsole(ATTACH_PARENT_PROCESS))
                {
                    wchar_t report[4096];
                    if (EvFsBuildReport(report, 4096, rc == 0))
                    {
                        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
                        DWORD written = 0;
                        WriteConsoleW(hOut, report, (DWORD)wcslen(report), &written, nullptr);
                    }
                    FreeConsole();
                }
                LocalFree(argv);
                Shutdown();
                return rc;
            }
            LocalFree(argv);
        }
    }

    if (!RepairScriptAssociations()) {
        ShowError(L"EchoVault",
            L"Windows blocked EchoVault from fully repairing an old .bat or .cmd "
            L"association. Use Windows Default Apps reset or ask for the manual "
            L"repair steps before opening scripts.");
    }

    // Serialize interactive mutations, but leave the read-only watcher separate.
    HANDLE interactive = CreateMutexW(nullptr, FALSE, L"Local\\EchoVaultInteractive");
    if (!interactive || GetLastError() == ERROR_ALREADY_EXISTS) {
        ShowInfo(L"EchoVault", L"EchoVault is already working. Return to its open dialog, finish locking the file, then try again.");
        if (interactive) CloseHandle(interactive);
        Shutdown(); return 1;
    }
    struct MutexHandle { HANDLE h; ~MutexHandle() { CloseHandle(h); } } ownership{interactive};

    // ---- CLI Arguments Parsing (Smart Context Menu + Open Interception) ----
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv)
    {
        // EchoVault.exe --open <file>   (invoked by double-clicking an
        // intercepted file): unlock if encrypted, then open normally.
        if (argc >= 3 && wcscmp(argv[1], L"--open") == 0)
        {
            std::filesystem::path target = argv[2];

            // Refresh the association report; never change Windows defaults.
            ReassertInterception();



            if (std::filesystem::exists(target))
            {
                // With the minifilter loaded, allow us (and the viewer) to
                // touch the file while this flow runs; HandleUnlockAndOpen
                // re-gates it after re-locking.
                EvAllowFor(target.wstring());

                if (std::filesystem::is_regular_file(target) && IsEncrypted(target))
                {
                    // Temporary unlock: prompt, decrypt in place, open with
                    // the normal program, then RE-LOCK automatically when the
                    // viewing program closes. Fail-safe: on any failure the
                    // file is never handed to the opener.
                    HandleUnlockAndOpen(target);
                }
                else
                {
                    OpenWithOriginalApp(target);   // plain file: pass through
                }
            }
            LocalFree(argv);
            Shutdown();
            return 0;
        }
        if (argc >= 2 && wcscmp(argv[1], L"--install-open") == 0)
        {
            // Silent CLI (exit code only); the main-menu entry shows dialogs.
            bool ok = InstallOpenInterception();
            LocalFree(argv);
            Shutdown();
            return ok ? 0 : 1;
        }
        if (argc >= 2 && wcscmp(argv[1], L"--uninstall-open") == 0)
        {
            bool ok = UninstallOpenInterception();
            LocalFree(argv);
            Shutdown();
            return ok ? 0 : 1;
        }
        if (argc >= 3 && wcscmp(argv[1], L"--add-ext") == 0)
        {
            bool ok = AddOpenInterceptionExt(argv[2]);
            LocalFree(argv);
            Shutdown();
            return ok ? 0 : 1;
        }
        if (argc >= 3 && wcscmp(argv[1], L"--remove-ext") == 0)
        {
            bool ok = RemoveOpenInterceptionExt(argv[2]);
            LocalFree(argv);
            Shutdown();
            return ok ? 0 : 1;
        }
        // EchoVault.exe <file-or-folder>   (right-click context menu)
        if (argc > 1)
        {
            std::filesystem::path target = argv[1];
            if (std::filesystem::exists(target))
            {
                if (IsEncrypted(target)) {
                    DecryptTarget(target);
                } else {
                    EncryptTarget(target);
                }
            } else {
                ShowError(L"EchoVault", L"The specified file or folder does not exist.");
            }
            LocalFree(argv);
            Shutdown();
            return 0;
        }
        LocalFree(argv);
    }

    if (IsFirstRun()) {
        if (!FirstRunWizard()) { Shutdown(); return 0; }
        ManageOpenInterception();
    }
    else if (IsOpenInterceptionInstalled()) {
        // Refresh registrations created by earlier betas (which exposed only
        // .txt). This never changes the user's Windows default choices.
        InstallOpenInterception();
    }

    // ---- Main loop ----
    for (;;)
    {
        MenuAction action = ShowMainMenu();

        if (action == MenuAction::Exit)
            break;

        if (action == MenuAction::Setup) {
            ManageOpenInterception();
        }
        else if (action == MenuAction::Open) {
            auto target = SelectTarget();
            if (!target.empty()) {
                if (std::filesystem::is_directory(target)) DecryptTarget(target);
                else if (IsEncrypted(target)) HandleUnlockAndOpen(target);
                else OpenWithOriginalApp(target);
            }
        }
        else if (action == MenuAction::Add)
        {
            auto target = SelectTarget();
            if (!target.empty())
                EncryptTarget(target);
        }
        else if (action == MenuAction::Remove)
        {
            auto target = SelectTarget();
            if (!target.empty())
                DecryptTarget(target);
        }
        else if (action == MenuAction::ChangeFilePw)
        {
            auto target = SelectTarget();
            if (!target.empty())
                ChangeFilePassword(target);
        }
        else if (action == MenuAction::ChangeMasterPw)
        {
            VaultHeader hdr;
            if (LoadVaultHeader(hdr)) {
                ChangeMasterPassword(hdr, GetMasterKeyOnDemand());
            }
        }
    }

    // ---- Wipe master key from memory ----
    if (!g_MasterKey.empty()) {
        SecureZeroMemory(g_MasterKey.data(), g_MasterKey.size());
    }

    Shutdown();
    return 0;
}

//====================================================================
// Authenticate — verify master password, return master key
//====================================================================

static std::vector<unsigned char> Authenticate()
{
    VaultHeader hdr = {};
    if (!LoadVaultHeader(hdr))
    {
        // vault.db missing or corrupted
        int choice = MessageBoxW(nullptr,
            (std::wstring(L"Your vault database (vault.db) is missing or corrupted.\n\n"
            L"If you have a backup, restore it to:\n") +
            GetVaultDBPath().wstring()).c_str(),
            L"EchoVault \u2014 Error",
            MB_RETRYCANCEL | MB_ICONERROR);

        if (choice == IDRETRY) {
            // User says they restored it — try again
            if (!LoadVaultHeader(hdr)) {
                ShowError(L"EchoVault",
                    L"Still cannot read vault.db.\n"
                    L"Please reinstall or restore from backup.");
                return {};
            }
        } else {
            return {};
        }
    }

    // Password entry loop (unlimited attempts)
    for (;;)
    {
        auto answer = PromptPassword(
            L"EchoVault \u2014 Unlock",
            L"Enter your Master Password:",
            true, L"Recover Master Password");

        if (answer.result == PasswordResult::Cancel)
            return {};

        if (answer.result == PasswordResult::ForgotPassword)
        {
            auto key = HandleForgotPassword(hdr);
            if (!key.empty()) return key;
            continue;   // back to password prompt
        }

        // Verify password
        std::vector<unsigned char> salt(hdr.salt, hdr.salt + 32);
        if (!VerifyPassword(answer.password, salt,
                std::vector<unsigned char>(hdr.pwHash, hdr.pwHash + 32)))
        {
            ShowError(L"EchoVault", L"Incorrect password. Try again.");
            continue;
        }

        // Derive key & decrypt master key
        auto pwKey = DeriveKey(answer.password, salt);
        auto masterKey = DecryptBuffer(
            std::vector<unsigned char>(hdr.encKey, hdr.encKey + 64), pwKey);

        if (masterKey.empty() || masterKey.size() != 32) {
            ShowError(L"EchoVault",
                L"Password verified but master key decryption failed.\n"
                L"Your vault.db may be corrupted.");
            return {};
        }

        // Wipe password-derived key
        SecureZeroMemory(pwKey.data(), pwKey.size());
        return masterKey;
    }
}

//====================================================================
// Forgot-password recovery flow
//====================================================================

static std::vector<unsigned char> HandleForgotPassword(VaultHeader& hdr)
{
    std::wstring recHex = PromptRecoveryKey();
    if (recHex.empty()) return {};

    // Strip spaces (user might paste formatted key)
    std::wstring cleaned;
    for (auto c : recHex)
        if (c != L' ' && c != L'\n' && c != L'\r')
            cleaned += c;

    if (cleaned.size() != 64) {
        ShowError(L"EchoVault",
            L"The recovery key must be exactly 64 hex characters.");
        return {};
    }

    // Derive recovery key
    std::vector<unsigned char> recSalt(hdr.recSalt, hdr.recSalt + 32);
    auto recKey = DeriveKey(cleaned, recSalt);

    // Try to decrypt master key with recovery key
    auto masterKey = DecryptBuffer(
        std::vector<unsigned char>(hdr.encKeyRec, hdr.encKeyRec + 64), recKey);

    if (masterKey.empty() || masterKey.size() != 32) {
        ShowError(L"EchoVault",
            L"Invalid recovery key.\n"
            L"Make sure you entered it exactly as shown during setup.");
        return {};
    }

    ShowInfo(L"EchoVault", L"Recovery key accepted!\n\nNow set a new master password.");

    // --- New password (with confirmation) ---
    std::wstring newPw;
    for (;;)
    {
        auto a1 = PromptPassword(
            L"EchoVault \u2014 New Password",
            L"Enter your new master password:");
        if (a1.result != PasswordResult::OK) return {};
        if (a1.password.empty()) {
            ShowError(L"EchoVault", L"Password cannot be empty.");
            continue;
        }

        auto a2 = PromptPassword(
            L"EchoVault \u2014 Confirm",
            L"Confirm your new master password:");
        if (a2.result != PasswordResult::OK) return {};

        if (a1.password != a2.password) {
            ShowError(L"EchoVault", L"Passwords do not match. Try again.");
            continue;
        }
        newPw = a1.password;
        break;
    }

    // Re-encrypt master key with new password
    auto newSalt = GenerateRandomBytes(32);
    if (newSalt.empty()) {
        ShowError(L"EchoVault", L"Failed to generate new salt.");
        return {};
    }

    auto newHash = HashPassword(newPw, newSalt);
    auto newKey  = DeriveKey(newPw, newSalt);
    auto newEnc  = EncryptAuthenticated(masterKey, newKey);

    if (newHash.empty() || newKey.empty() || newEnc.size() != 64) {
        ShowError(L"EchoVault", L"Failed to re-encrypt with new password.");
        return {};
    }

    // Update header (keep recovery key intact)
    std::memcpy(hdr.salt,   newSalt.data(), 32);
    std::memcpy(hdr.pwHash, newHash.data(), 32);
    std::memcpy(hdr.encKey, newEnc.data(),  64);

    if (!SaveVaultHeader(hdr)) {
        ShowError(L"EchoVault", L"Failed to save updated vault.db.");
        return {};
    }

    ShowInfo(L"EchoVault", L"Password updated successfully!");
    SecureZeroMemory(newKey.data(), newKey.size());
    return masterKey;
}

//====================================================================
// Init / Shutdown
//====================================================================

static bool Initialize()
{
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    return true;
}

static void Shutdown()
{
    CoUninitialize();
}
