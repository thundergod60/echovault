//------------------------------------------------------------
// filterctl.c — user-mode control tool for the EchoVault
// minifilter. Sends operations to EchoVaultFilter.sys over the
// filter communication port using fltlib.dll (loaded dynamically
// so this builds with any MinGW/MSVC toolchain).
//
// Usage:
//   filterctl add <path>        register as encrypted (deny unless allowed)
//   filterctl allow <path>      allow opens (call right before decrypt)
//   filterctl disallow <path>   deny again (call after re-encrypt)
//   filterctl remove <path>     unregister (file permanently decrypted)
//   filterctl clear             forget everything (paths + exclusions)
//   filterctl exclude <app>     let an app (image base name, e.g.
//                                backup.exe) open locked files — it only
//                                ever sees ciphertext without the password
//   filterctl unexclude <app>   revoke that
//   filterctl status            full state report (loaded? off-switch?
//                                last shutdown clean?)
//   filterctl load [--force] [path-to-sys]
//                               start the driver (admin). Refuses if the
//                               off-switch is set, or if the machine shut
//                               down abnormally while the driver was
//                               loaded last time, unless --force.
//   filterctl disable           panic off-switch: unload now + keep it
//                               from loading until 'filterctl enable'
//   filterctl enable            clear the off-switch
//
// The crash-safety state (load/unload record, off-switch, unexpected-
// shutdown detection) lives in filterstate.c — plain user mode, so
// this tool works even when the driver is not installed.
//------------------------------------------------------------

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include "..\shared\evfilter.h"
#include "..\filterstate.h"

typedef HRESULT(WINAPI* FnConnect)(LPCWSTR, DWORD, LPCVOID, DWORD, LPVOID, HANDLE*);
typedef HRESULT(WINAPI* FnSend)(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* FnClose)(HANDLE);

static void PrintError(const wchar_t* what, HRESULT hr)
{
    wprintf(L"%ls failed: 0x%08lx", what, (unsigned long)hr);
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        wprintf(L"  (the EchoVault filter driver is not loaded)");
    wprintf(L"\n");
}

static void Usage(void)
{
    wprintf(
        L"EchoVault filter control\n"
        L"\n"
        L"  filterctl add <path>       register a path as encrypted\n"
        L"  filterctl allow <path>     allow opens of an encrypted path (unlock)\n"
        L"  filterctl disallow <path>  deny opens again (re-lock)\n"
        L"  filterctl remove <path>    unregister a path entirely\n"
        L"  filterctl clear            forget all registrations\n"
        L"  filterctl exclude <app>    allow an app (e.g. backup.exe) to open\n"
        L"                             locked files (ciphertext only)\n"
        L"  filterctl unexclude <app>  revoke that\n"
        L"  filterctl status           full state report (driver, off-switch,\n"
        L"                             last shutdown)\n"
        L"  filterctl load [--force] [path-to-sys]   start the driver (admin)\n"
        L"  filterctl disable          panic off-switch: unload + keep unloaded\n"
        L"  filterctl enable           clear the off-switch\n");
}

// ---- small process runner (no console window) -------------------

// Returns the child exit code, or -1 if it could not be spawned.
static int RunCmd(const wchar_t* cmdline)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    wchar_t* cmd = _wcsdup(cmdline);
    BOOL ok = cmd && CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmd);
    if (!ok)
        return -1;

    WaitForSingleObject(pi.hProcess, 60000);
    DWORD code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &code))
        code = 0xFFFFFFFF;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}

// ---- verbs --------------------------------------------------------

static int CmdLoad(int argc, wchar_t** wargv)
{
    int force = 0;
    const wchar_t* sysPath = L"EchoVaultFilter.sys";
    for (int i = 2; i < argc; i++)
    {
        if (wcscmp(wargv[i], L"--force") == 0)
            force = 1;
        else
            sysPath = wargv[i];
    }

    int disabled = EvFsIsDisabled();
    if (disabled == 1)
    {
        wprintf(L"REFUSED: the off-switch is set (the driver was disabled with\n"
                L"'filterctl disable'). Run 'filterctl enable' first.\n");
        return 1;
    }
    if (disabled < 0)
        wprintf(L"(could not read the off-switch state; continuing)\n");

    // Crash stand-off: if the machine shut down abnormally while the
    // driver was loaded and never cleanly unloaded, require --force.
    EVFS_STATE st;
    EvFsGetState(&st);
    if (EvFsWasLoadedAtLastShutdown(&st))
    {
        ULONGLONG when = 0;
        int res = EvFsUnexpectedShutdownSince(st.LoadedAt, &when);
        if (res == 1 && !force)
        {
            wprintf(L"REFUSED: your machine shut down abnormally (crash or power loss)\n"
                    L"while the driver was loaded last time, and it never cleanly\n"
                    L"unloaded. The driver stays off until you explicitly reload it:\n"
                    L"\n"
                    L"    filterctl load --force\n"
                    L"\n"
                    L"Only do that if you accept the risk. Your files are NOT at\n"
                    L"risk either way (the driver never touches file contents).\n");
            return 1;
        }
        if (res == -1)
            wprintf(L"(note: could not check whether the last shutdown was clean)\n");
    }

    if (GetFileAttributesW(sysPath) == INVALID_FILE_ATTRIBUTES)
    {
    wprintf(L"ERROR: '%ls' not found. Build the driver first (see\n"
            L"driver/BUILD-TEST-RUNBOOK.md), then pass its path:\n"
            L"    filterctl load <path-to-EchoVaultFilter.sys>\n", sysPath);
        return 1;
    }

    wchar_t cmd[2048];
    // Register the kernel service if it doesn't exist yet ("already
    // exists" is fine and is ignored).
    wsprintfW(cmd, L"sc create EchoVaultFilter type= kernel binPath= \"%s\"", sysPath);
    RunCmd(cmd);

    // Attach the minifilter to Filter Manager.
    int rc = RunCmd(L"fltmc load EchoVaultFilter");
    if (rc != 0)
    {
        wprintf(L"ERROR: 'fltmc load' failed (exit %d). This command must run\n"
                L"as administrator, and the driver must be signed for test-\n"
                L"signing first (see driver/BUILD-TEST-RUNBOOK.md).\n", rc);
        return 1;
    }

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    EvFsSetLoaded(((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime);
    wprintf(L"OK: driver loaded and registered. Off-switch: 'filterctl disable'.\n");
    return 0;
}

static int CmdDisable(void)
{
    // Unload if running (best effort — may already be unloaded).
    RunCmd(L"fltmc unload EchoVaultFilter");

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    EvFsSetUnloaded(((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime);
    EvFsSetDisabled(1);
    wprintf(L"OK: driver unloaded (if it was running) and the off-switch is set.\n"
            L"It will stay unloaded across reboots until you run:\n"
            L"    filterctl enable\n"
            L"    filterctl load\n");
    return 0;
}

static int CmdEnable(void)
{
    EvFsSetDisabled(0);
    wprintf(L"OK: off-switch cleared. The driver can now be started with:\n"
            L"    filterctl load   (as administrator)\n");
    return 0;
}

// ---- main --------------------------------------------------------

int main(void)
{
    int nArgs = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (!wargv || nArgs < 2)
    {
        Usage();
        return 1;
    }

    const wchar_t* verb = wargv[1];

    // Verbs that don't need the driver port.
    if (wcscmp(verb, L"load") == 0)
    {
        int rc = CmdLoad(nArgs, wargv);
        LocalFree(wargv);
        return rc;
    }
    if (wcscmp(verb, L"disable") == 0)
    {
        int rc = CmdDisable();
        LocalFree(wargv);
        return rc;
    }
    if (wcscmp(verb, L"enable") == 0)
    {
        int rc = CmdEnable();
        LocalFree(wargv);
        return rc;
    }

    // ---- Load fltlib dynamically (for status / port ops) ----
    HMODULE hFltlib = LoadLibraryW(L"fltlib.dll");
    if (!hFltlib)
    {
        wprintf(L"fltlib.dll could not be loaded (not a Windows system?)\n");
        return 1;
    }
    FnConnect pConnect = (FnConnect)(void*)GetProcAddress(hFltlib, "FilterConnectCommunicationPort");
    FnSend    pSend    = (FnSend)(void*)GetProcAddress(hFltlib, "FilterSendMessage");
    FnClose   pClose   = (FnClose)(void*)GetProcAddress(hFltlib, "FilterClose");
    if (!pConnect || !pSend || !pClose)
    {
        wprintf(L"fltlib.dll is missing required exports\n");
        return 1;
    }

    // ---- status: full report, driver reachability is best-effort ----
    if (wcscmp(verb, L"status") == 0)
    {
        HANDLE hProbe = INVALID_HANDLE_VALUE;
        int loaded = 0;
        HRESULT hr = pConnect(EVFILTER_PORT_NAME, 0, NULL, 0, NULL, &hProbe);
        if (SUCCEEDED(hr) && hProbe != INVALID_HANDLE_VALUE && hProbe != NULL)
        {
            loaded = 1;
            pClose(hProbe);
        }
        wchar_t report[4096];
        EvFsBuildReport(report, 4096, loaded);
        wprintf(L"%ls", report);
        LocalFree(wargv);
        return 0;
    }

    // ---- Connect to the driver for the port operations ----
    HANDLE hPort = INVALID_HANDLE_VALUE;
    HRESULT hr = pConnect(EVFILTER_PORT_NAME, 0, NULL, 0, NULL, &hPort);
    if (FAILED(hr) || hPort == INVALID_HANDLE_VALUE || hPort == NULL)
    {
        PrintError(L"FilterConnectCommunicationPort", hr);
        LocalFree(wargv);
        return 2;
    }

    // ---- Build the message ----
    EVFILTER_MSG msg;
    memset(&msg, 0, sizeof(msg));

    if (wcscmp(verb, L"clear") == 0)
    {
        msg.OpCode = EVFILTER_MSG_CLEAR;
    }
    else
    {
        if (nArgs < 3)
        {
            Usage();
            pClose(hPort);
            LocalFree(wargv);
            return 1;
        }
        if (wcscmp(verb, L"add") == 0)
            msg.OpCode = EVFILTER_MSG_ADD;
        else if (wcscmp(verb, L"allow") == 0)
            msg.OpCode = EVFILTER_MSG_ALLOW;
        else if (wcscmp(verb, L"disallow") == 0)
            msg.OpCode = EVFILTER_MSG_DISALLOW;
        else if (wcscmp(verb, L"remove") == 0)
            msg.OpCode = EVFILTER_MSG_REMOVE;
        else if (wcscmp(verb, L"exclude") == 0)
            msg.OpCode = EVFILTER_MSG_EXCLUDE_ADD;
        else if (wcscmp(verb, L"unexclude") == 0)
            msg.OpCode = EVFILTER_MSG_EXCLUDE_REMOVE;
        else
        {
            wprintf(L"Unknown verb: %ls\n", verb);
            Usage();
            pClose(hPort);
            LocalFree(wargv);
            return 1;
        }

        wcsncpy(msg.Path, wargv[2], EVFILTER_MAX_PATH - 1);
        msg.Path[EVFILTER_MAX_PATH - 1] = L'\0';
    }

    DWORD pathBytes = (DWORD)((wcslen(msg.Path) + 1) * sizeof(WCHAR));
    DWORD msgSize = (DWORD)(FIELD_OFFSET(EVFILTER_MSG, Path) + pathBytes);

    // ---- Send ----
    DWORD returned = 0;
    hr = pSend(hPort, &msg, msgSize, NULL, 0, &returned);
    if (FAILED(hr))
    {
        PrintError(L"FilterSendMessage", hr);
        pClose(hPort);
        LocalFree(wargv);
        return 3;
    }

    // "clear" means forget everything: also wipe the app-exclusion list.
    if (msg.OpCode == EVFILTER_MSG_CLEAR)
    {
        EVFILTER_MSG x = {};
        x.OpCode = EVFILTER_MSG_EXCLUDE_CLEAR;
        pSend(hPort, &x, sizeof(x), NULL, 0, &returned);
    }

    if (msg.OpCode == EVFILTER_MSG_STATUS)
        wprintf(L"OK: EchoVault filter driver is loaded and responding.\n");
    else if (msg.OpCode == EVFILTER_MSG_CLEAR)
        wprintf(L"OK: cleared all path registrations and app exclusions.\n");
    else
        wprintf(L"OK: %ls: %ls\n", verb, wargv[2]);

    pClose(hPort);
    LocalFree(wargv);
    return 0;
}
