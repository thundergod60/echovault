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
#include <winsvc.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include "..\shared\evfilter.h"
#include "..\filterstate.h"

typedef HRESULT(WINAPI* FnConnect)(LPCWSTR, DWORD, LPCVOID, WORD, LPVOID, HANDLE*);
typedef HRESULT(WINAPI* FnSend)(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD);

static HRESULT ConnectControl(FnConnect connect, HANDLE* port)
{
    EVFILTER_CONNECT_CONTEXT context;
    context.Magic = EVFILTER_CONNECT_MAGIC;
    context.Role = EVFILTER_ROLE_CONTROL;
    return connect(EVFILTER_PORT_NAME, 0, &context, sizeof(context), NULL, port);
}

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

    DWORD wait = WaitForSingleObject(pi.hProcess, 15000);
    if (wait == WAIT_TIMEOUT)
    {
        // Do not leave a wedged fltmc/sc helper running forever.  The driver
        // service is changed to demand-start before unload is attempted, so
        // even this failure cannot re-arm it for the next boot.
        TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(pi.hProcess, 2000);
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &code))
        code = 0xFFFFFFFF;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}

// Query the service without relying on localized command output.
// Returns 1 on success (including "not installed"), 0 on API failure.
static int QueryDriverService(int* installed, int* running)
{
    *installed = 0;
    *running = 0;
    SC_HANDLE mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!mgr)
        return 0;

    SC_HANDLE svc = OpenServiceW(mgr, L"EchoVaultFilter",
        SERVICE_QUERY_STATUS);
    if (!svc)
    {
        DWORD err = GetLastError();
        CloseServiceHandle(mgr);
        return err == ERROR_SERVICE_DOES_NOT_EXIST;
    }

    SERVICE_STATUS_PROCESS ss;
    DWORD needed = 0;
    BOOL ok = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ss, sizeof(ss), &needed);
    if (ok)
    {
        *installed = 1;
        *running = (ss.dwCurrentState != SERVICE_STOPPED);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(mgr);
    return ok ? 1 : 0;
}

// Demote an existing service before doing anything that might hang.  This is
// the critical boot-loop breaker: after it succeeds the OS will not load the
// driver automatically, even if the current unload attempt crashes.
static int SetExistingServiceDemandStart(int* installedOut)
{
    *installedOut = 0;
    SC_HANDLE mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!mgr)
        return 0;

    SC_HANDLE svc = OpenServiceW(mgr, L"EchoVaultFilter",
        SERVICE_CHANGE_CONFIG);
    if (!svc)
    {
        DWORD err = GetLastError();
        CloseServiceHandle(mgr);
        return err == ERROR_SERVICE_DOES_NOT_EXIST;
    }

    *installedOut = 1;
    BOOL ok = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE,
        SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL);
    CloseServiceHandle(svc);
    CloseServiceHandle(mgr);
    return ok ? 1 : 0;
}

// Create or update the driver service.  It is deliberately demand-start;
// production boot-start is not permitted by this development tool.
static int EnsureDemandStartService(const wchar_t* binaryPath)
{
    SC_HANDLE mgr = OpenSCManagerW(NULL, NULL,
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!mgr)
        return 0;

    SC_HANDLE svc = CreateServiceW(mgr, L"EchoVaultFilter",
        L"EchoVaultFilter", SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS,
        SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, binaryPath, NULL, NULL, NULL, NULL, NULL);
    if (!svc && GetLastError() == ERROR_SERVICE_EXISTS)
        svc = OpenServiceW(mgr, L"EchoVaultFilter",
            SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);

    BOOL ok = FALSE;
    if (svc)
    {
        ok = ChangeServiceConfigW(svc, SERVICE_FILE_SYSTEM_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, binaryPath,
            NULL, NULL, NULL, NULL, NULL, L"EchoVaultFilter");
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(mgr);
    return ok ? 1 : 0;
}

// ---- verbs --------------------------------------------------------

// Register the minifilter's altitude in the service registry key, the
// way a driver INF normally would. Without an altitude the filter
// manager can load the driver but will never attach it to any volume.
static int RegSetStr(HKEY key, const wchar_t* name, const wchar_t* value)
{
    return RegSetValueExW(key, name, 0, REG_SZ, (const BYTE*)value,
        (DWORD)((wcslen(value) + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

static int RegisterFilterAltitude(const wchar_t* service,
                                  const wchar_t* instance,
                                  const wchar_t* altitude)
{
    wchar_t path[512];
    HKEY hk;
    int ok = 1;
    wsprintfW(path, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances", service);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_SET_VALUE,
                        NULL, &hk, NULL) == ERROR_SUCCESS)
    {
        ok = RegSetStr(hk, L"DefaultInstance", instance) && ok;
        RegCloseKey(hk);
    }
    else ok = 0;
    wsprintfW(path, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances\\%s",
              service, instance);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_SET_VALUE,
                        NULL, &hk, NULL) == ERROR_SUCCESS)
    {
        ok = RegSetStr(hk, L"Altitude", altitude) && ok;
        DWORD flags = 0;
        ok = (RegSetValueExW(hk, L"Flags", 0, REG_DWORD,
            (const BYTE*)&flags, sizeof(flags)) == ERROR_SUCCESS) && ok;
        RegCloseKey(hk);
    }
    else ok = 0;
    return ok;
}

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

    // Demote any service left by an older build before checking whether it
    // is running.  A stale boot-start setting must never survive this tool.
    int serviceInstalled = 0;
    if (!SetExistingServiceDemandStart(&serviceInstalled))
    {
        wprintf(L"ERROR: could not change the existing driver service to\n"
                L"demand-start. Run as administrator. The driver was NOT loaded.\n");
        return 1;
    }

    if (serviceInstalled)
    {
        int installed = 0, running = 0;
        if (!QueryDriverService(&installed, &running))
        {
            wprintf(L"ERROR: could not query the existing driver service.\n");
            return 1;
        }
        if (running)
        {
            wprintf(L"OK: the driver is already loaded. Its service is now\n"
                    L"demand-start and will not load automatically at boot.\n");
            return 0;
        }
    }

    if (GetFileAttributesW(sysPath) == INVALID_FILE_ATTRIBUTES)
    {
    wprintf(L"ERROR: '%ls' not found. Build the driver first (see\n"
            L"driver/BUILD-TEST-RUNBOOK.md), then pass its path:\n"
            L"    filterctl load <path-to-EchoVaultFilter.sys>\n", sysPath);
        return 1;
    }

    // Copy the driver to the canonical drivers directory. Kernel driver
    // loads fail with "file not found" when the service ImagePath
    // contains spaces, and this is the location the INF uses anyway.
    wchar_t windir[MAX_PATH];
    if (!GetWindowsDirectoryW(windir, MAX_PATH))
        wcscpy(windir, L"C:\\Windows");
    wchar_t destPath[MAX_PATH];
    wsprintfW(destPath, L"%s\\System32\\drivers\\EchoVaultFilter.sys", windir);
    if (!CopyFileW(sysPath, destPath, FALSE))
    {
        wprintf(L"ERROR: could not copy the driver to\n  %ls\n"
                L"(error %lu). Run as administrator and make sure the\n"
                L"source .sys is on a local drive.\n", destPath, GetLastError());
        return 1;
    }

    if (!EnsureDemandStartService(destPath))
    {
        wprintf(L"ERROR: could not create/update the demand-start driver service.\n"
                L"The driver was NOT loaded. Run as administrator.\n");
        return 1;
    }

    // Register the altitude (the INF normally does this).
    if (!RegisterFilterAltitude(L"EchoVaultFilter",
            L"EchoVaultFilter Instance", L"360000"))
    {
        wprintf(L"ERROR: could not register the minifilter altitude.\n"
                L"The service remains demand-start and was NOT loaded.\n");
        return 1;
    }

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
    if (!EvFsSetLoaded(((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime))
    {
        EvFsSetDisabled(1);
        int unloadRc = RunCmd(L"fltmc unload EchoVaultFilter");
        wprintf(L"ERROR: the load-safety marker could not be saved. The\n"
                L"off-switch was set and emergency unload returned %d.\n"
                L"The service remains demand-start.\n", unloadRc);
        return 1;
    }
    wprintf(L"OK: driver loaded on demand (installed at %ls).\n"
            L"It will NOT load automatically at boot.\n"
            L"Off-switch: 'filterctl disable'.\n", destPath);
    return 0;
}

static int CmdDisable(void)
{
    // Persist both safety barriers BEFORE asking the kernel to unload.  If
    // unload hangs and the machine is reset, the service is already
    // demand-start and filterctl will still refuse a later manual load.
    if (!EvFsSetDisabled(1))
    {
        wprintf(L"ERROR: could not set the persistent off-switch.\n"
                L"The unload was not attempted.\n");
        return 1;
    }

    int serviceInstalled = 0;
    if (!SetExistingServiceDemandStart(&serviceInstalled))
    {
        wprintf(L"ERROR: the off-switch is set, but the service could not be\n"
                L"changed to demand-start. Do NOT reboot until this is fixed.\n");
        return 1;
    }

    int installed = 0, running = 0;
    if (!QueryDriverService(&installed, &running))
    {
        wprintf(L"ERROR: the off-switch is set and the service is demand-start,\n"
                L"but its current state could not be queried.\n");
        return 1;
    }

    if (running)
    {
        int rc = RunCmd(L"fltmc unload EchoVaultFilter");
        int installedAfter = 0, runningAfter = 1;
        int queried = QueryDriverService(&installedAfter, &runningAfter);
        if (rc != 0 || !queried || runningAfter)
        {
            wprintf(L"ERROR: the driver did not unload cleanly (exit %d).\n"
                    L"The persistent off-switch IS set and the service IS\n"
                    L"demand-start, so it will not load on the next boot.\n", rc);
            return 1;
        }
    }

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    if (!EvFsSetUnloaded(((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime))
    {
        wprintf(L"ERROR: the driver is unloaded and demand-start, but the clean\n"
                L"unload marker could not be saved. The off-switch remains set.\n");
        return 1;
    }
    wprintf(L"OK: driver unloaded, service set to demand-start, and the\n"
            L"persistent off-switch is set. It will stay off across reboots.\n");
    return 0;
}

static int CmdEnable(void)
{
    // Enabling only permits a future explicit load.  It never opts the
    // machine back into boot-start.
    if (!EvFsSetDisabled(0))
    {
        wprintf(L"ERROR: could not clear the off-switch.\n");
        return 1;
    }
    int installed = 0;
    if (!SetExistingServiceDemandStart(&installed))
    {
        EvFsSetDisabled(1);
        wprintf(L"ERROR: could not verify demand-start; the off-switch was\n"
                L"restored for safety.\n");
        return 1;
    }
    wprintf(L"OK: off-switch cleared. The service remains demand-start.\n"
            L"To start the driver explicitly, run as administrator:\n"
            L"    filterctl load\n");
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
    if (!pConnect || !pSend)
    {
        wprintf(L"fltlib.dll is missing required exports\n");
        return 1;
    }

    // ---- status: full report, driver reachability is best-effort ----
    if (wcscmp(verb, L"status") == 0)
    {
        HANDLE hProbe = INVALID_HANDLE_VALUE;
        int loaded = 0;
        HRESULT hr = ConnectControl(pConnect, &hProbe);
        if (SUCCEEDED(hr) && hProbe != INVALID_HANDLE_VALUE && hProbe != NULL)
        {
            loaded = 1;
            CloseHandle(hProbe);
        }
        wchar_t report[4096];
        EvFsBuildReport(report, 4096, loaded);
        wprintf(L"%ls", report);
        LocalFree(wargv);
        return 0;
    }

    // ---- Connect to the driver for the port operations ----
    HANDLE hPort = INVALID_HANDLE_VALUE;
    HRESULT hr = ConnectControl(pConnect, &hPort);
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
            CloseHandle(hPort);
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
            CloseHandle(hPort);
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
        CloseHandle(hPort);
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

    CloseHandle(hPort);
    LocalFree(wargv);
    return 0;
}
