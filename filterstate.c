//------------------------------------------------------------
// filterstate.c — implementation of the crash-safety state module
// (see filterstate.h for the design).
//
// Marker storage: HKCU\Software\EchoVault\Filter
//   LoadedAt   REG_SZ  decimal ULONGLONG FILETIME of the last load
//   UnloadedAt REG_SZ  decimal ULONGLONG FILETIME of the last clean
//                      unload (absent until a clean unload happens)
//   Disabled   REG_SZ  "1" = user off-switch, absent/"0" = enabled
//
// Unexpected-shutdown detection: the System event log's Event 6008
// ("The previous system shutdown ... was unexpected") is the ground
// truth for "did the machine crash or lose power". We query it with
// `wevtutil qe System /q:"*[System[(EventID=6008)]]" /c:1 /rd:true
// /f:xml` (standard on Windows 7+) and read the newest event's
// TimeCreated. Event times are wall-clock UTC; our markers are
// FILETIME (also UTC), so the comparison is direct.
//------------------------------------------------------------

#include <windows.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>

#include "filterstate.h"

#define EVFS_REG_KEY  L"Software\\EchoVault\\Filter"
#define EVFS_VAL_LOADED   L"LoadedAt"
#define EVFS_VAL_UNLOADED L"UnloadedAt"
#define EVFS_VAL_DISABLED L"Disabled"

// ---- helpers --------------------------------------------------

static ULONGLONG FileTimeToU64(const FILETIME* ft)
{
    return (((ULONGLONG)ft->dwHighDateTime) << 32) | ft->dwLowDateTime;
}

static void U64ToFileTime(ULONGLONG t, FILETIME* ft)
{
    ft->dwLowDateTime  = (DWORD)(t & 0xFFFFFFFFULL);
    ft->dwHighDateTime = (DWORD)(t >> 32);
}

// Read a REG_SZ value as a 64-bit number. Returns 0 if absent/unreadable
// (an absent marker is the "never happened" state, so 0 is correct).
static ULONGLONG ReadU64(HKEY hk, const wchar_t* name)
{
    wchar_t buf[32];
    DWORD size = (DWORD)sizeof(buf);
    DWORD type = 0;
    LONG rc = RegQueryValueExW(hk, name, NULL, &type, (LPBYTE)buf, &size);
    if (rc != ERROR_SUCCESS || type != REG_SZ)
        return 0;
    buf[(size / sizeof(wchar_t)) - 1] = L'\0';
    return _wcstoui64(buf, NULL, 10);
}

static void WriteU64(HKEY hk, const wchar_t* name, ULONGLONG v)
{
    wchar_t buf[32];
    wsprintfW(buf, L"%I64u", v);
    RegSetValueExW(hk, name, 0, REG_SZ, (const BYTE*)buf,
                   (DWORD)((wcslen(buf) + 1) * sizeof(wchar_t)));
}

static void DeleteValue(HKEY hk, const wchar_t* name)
{
    RegDeleteValueW(hk, name);
}

// ---- public API ------------------------------------------------

int EvFsGetState(EVFS_STATE* st)
{
    if (!st)
        return 0;
    memset(st, 0, sizeof(*st));

    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, EVFS_REG_KEY, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return 1;   // no key yet = fresh state

    st->LoadedAt   = ReadU64(hk, EVFS_VAL_LOADED);
    st->UnloadedAt = ReadU64(hk, EVFS_VAL_UNLOADED);

    wchar_t dbuf[8];
    DWORD dsize = (DWORD)sizeof(dbuf);
    DWORD dtype = 0;
    if (RegQueryValueExW(hk, EVFS_VAL_DISABLED, NULL, &dtype, (LPBYTE)dbuf, &dsize) == ERROR_SUCCESS
        && dtype == REG_SZ && _wtoi(dbuf) == 1)
        st->Flags |= EVFS_OPTS_DISABLED;

    if (st->LoadedAt)
        st->Flags |= EVFS_OPTS_LOADED;
    if (st->UnloadedAt)
        st->Flags |= EVFS_OPTS_UNLOADED;

    RegCloseKey(hk);
    return 1;
}

static int OpenWriteKey(HKEY* out)
{
    return RegCreateKeyExW(HKEY_CURRENT_USER, EVFS_REG_KEY, 0, NULL, 0,
                           KEY_SET_VALUE, NULL, out, NULL) == ERROR_SUCCESS;
}

int EvFsSetLoaded(ULONGLONG t)
{
    HKEY hk = NULL;
    if (!OpenWriteKey(&hk))
        return 0;
    WriteU64(hk, EVFS_VAL_LOADED, t);
    DeleteValue(hk, EVFS_VAL_UNLOADED);   // new epoch: no unload record yet
    RegCloseKey(hk);
    return 1;
}

int EvFsSetUnloaded(ULONGLONG t)
{
    HKEY hk = NULL;
    if (!OpenWriteKey(&hk))
        return 0;
    WriteU64(hk, EVFS_VAL_UNLOADED, t);
    RegCloseKey(hk);
    return 1;
}

int EvFsSetDisabled(int disabled)
{
    HKEY hk = NULL;
    if (!OpenWriteKey(&hk))
        return 0;
    wchar_t buf[4] = L"0";
    if (disabled)
        wcscpy(buf, L"1");
    RegSetValueExW(hk, EVFS_VAL_DISABLED, 0, REG_SZ, (const BYTE*)buf,
                   (DWORD)((wcslen(buf) + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    return 1;
}

int EvFsIsDisabled(void)
{
    EVFS_STATE st;
    if (!EvFsGetState(&st))
        return -1;
    return (st.Flags & EVFS_OPTS_DISABLED) ? 1 : 0;
}

int EvFsWasLoadedAtLastShutdown(const EVFS_STATE* st)
{
    if (!st || !(st->Flags & EVFS_OPTS_LOADED))
        return 0;
    if (!(st->Flags & EVFS_OPTS_UNLOADED))
        return 1;                     // loaded, never cleanly unloaded
    return st->UnloadedAt < st->LoadedAt ? 1 : 0;
}

// ---- wevtutil: unexpected-shutdown (Event 6008) detection -------

// Runs a command, captures stdout, returns the exit code (-1 = spawn
// failure). No console window is created.
static int RunCaptured(const wchar_t* cmdline, wchar_t* out, DWORD outChars)
{
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return -1;

    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    wchar_t* cmd = _wcsdup(cmdline);
    BOOL ok = cmd && CreateProcessW(NULL, cmd, NULL, NULL, TRUE,
                                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmd);
    CloseHandle(hWrite);

    int rc = -1;
    if (ok)
    {
        DWORD total = 0;
        char buf[4096];
        for (;;)
        {
            DWORD n = 0;
            if (!ReadFile(hRead, buf, sizeof(buf) - 1, &n, NULL) || n == 0)
                break;
            buf[n] = 0;
            if (out && total < outChars)
            {
                DWORD room = outChars - total;
                int conv = MultiByteToWideChar(CP_UTF8, 0, buf, (int)n, out + total, (int)room);
                if (conv > 0)
                    total += (DWORD)conv;
            }
        }
        if (out)
            out[total] = L'\0';

        WaitForSingleObject(pi.hProcess, 30000);
        DWORD code = 0;
        if (!GetExitCodeProcess(pi.hProcess, &code))
            code = 0xFFFFFFFF;
        rc = (int)code;

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    CloseHandle(hRead);
    return rc;
}

// Parses "yyyy-mm-ddThh:mm:ss[.fffffff]Z" (UTC, wevtutil emits up to
// 7 fractional digits) into a FILETIME value.
static int ParseIsoZ(const wchar_t* s, ULONGLONG* ftOut)
{
    int y, mo, d, h, mi, se;
    int n = swscanf(s, L"%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &se);
    if (n != 6)
        return 0;

    int ms = 0;
    const wchar_t* p = wcschr(s, L'.');
    if (p)
    {
        p++;
        for (int i = 0; i < 3 && *p >= L'0' && *p <= L'9'; i++)
            ms = ms * 10 + (*p - L'0');
    }

    SYSTEMTIME st;
    memset(&st, 0, sizeof(st));
    st.wYear = (WORD)y;
    st.wMonth = (WORD)mo;
    st.wDay = (WORD)d;
    st.wHour = (WORD)h;
    st.wMinute = (WORD)mi;
    st.wSecond = (WORD)se;
    st.wMilliseconds = (WORD)ms;

    FILETIME ft;
    if (!SystemTimeToFileTime(&st, &ft))
        return 0;
    *ftOut = FileTimeToU64(&ft);
    return 1;
}

int EvFsUnexpectedShutdownSince(ULONGLONG since, ULONGLONG* whenOut)
{
    // Resolve wevtutil explicitly from System32 — never a random copy
    // from the current directory. EVFILTER_WEVTUTIL overrides the path
    // (used by the logic tests to inject a fake event log).
    wchar_t exe[MAX_PATH];
    const wchar_t* env = _wgetenv(L"EVFILTER_WEVTUTIL");
    if (env && env[0])
    {
        wcsncpy(exe, env, MAX_PATH - 1);
        exe[MAX_PATH - 1] = L'\0';
    }
    else
    {
        if (!GetSystemDirectoryW(exe, MAX_PATH))
            return -1;
        wcscat(exe, L"\\wevtutil.exe");
    }

    wchar_t cmd[2100];
    wsprintfW(cmd,
        L"\"%s\" qe System /q:\"*[System[(EventID=6008)]]\" /c:1 /rd:true /f:xml",
        exe);

    wchar_t out[16384];
    int rc = RunCaptured(cmd, out, 16384);
    if (rc != 0)
        return -1;   // wevtutil failed (missing / no access) — unknown

    if (wcslen(out) == 0)
        return 0;    // no 6008 event at all

    const wchar_t* marker = wcsstr(out, L"SystemTime=\"");
    if (!marker)
        return 0;
    marker += wcslen(L"SystemTime=\"");
    const wchar_t* end = wcschr(marker, L'"');
    if (!end)
        return 0;

    wchar_t iso[64];
    size_t len = (size_t)(end - marker);
    if (len >= 64)
        len = 63;
    wcsncpy(iso, marker, len);
    iso[len] = L'\0';

    ULONGLONG evt = 0;
    if (!ParseIsoZ(iso, &evt))
        return 0;
    if (evt < since)
        return 0;
    if (whenOut)
        *whenOut = evt;
    return 1;
}

// ---- report -----------------------------------------------------

static void Append(wchar_t* buf, size_t cap, size_t* off, const wchar_t* line)
{
    size_t len = wcslen(line);
    if (*off + len + 2 >= cap)
        return;
    wcscpy(buf + *off, line);
    *off += len;
}

static void FtToStr(ULONGLONG t, wchar_t* out, size_t cap)
{
    (void)cap;
    if (t == 0)
    {
        wcscpy(out, L"never");
        return;
    }
    FILETIME ft;
    U64ToFileTime(t, &ft);
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    wsprintfW(out, L"%04d-%02d-%02d %02d:%02d:%02d UTC",
              (int)st.wYear, (int)st.wMonth, (int)st.wDay,
              (int)st.wHour, (int)st.wMinute, (int)st.wSecond);
}

int EvFsBuildReport(wchar_t* buf, size_t cap, int driverLoaded)
{
    if (!buf || cap < 128)
        return 0;
    buf[0] = L'\0';
    size_t off = 0;

    EVFS_STATE st;
    EvFsGetState(&st);

    wchar_t loadedStr[64], unloadedStr[64];
    FtToStr(st.LoadedAt, loadedStr, 64);
    FtToStr(st.UnloadedAt, unloadedStr, 64);

    wchar_t line[1024];   // room for the longest verdict (the crash warning)
    wsprintfW(line, L"EchoVault filter driver - state report\r\n");
    Append(buf, cap, &off, line);
    wsprintfW(line, L"  Driver loaded now:       %s\r\n", driverLoaded ? L"Yes" : L"No");
    Append(buf, cap, &off, line);
    wsprintfW(line, L"  User off-switch:         %s\r\n",
              (st.Flags & EVFS_OPTS_DISABLED) ? L"SET (driver kept unloaded)" : L"not set");
    Append(buf, cap, &off, line);
    wsprintfW(line, L"  Last loaded:             %s\r\n", loadedStr);
    Append(buf, cap, &off, line);
    wsprintfW(line, L"  Last clean unload:       %s\r\n", unloadedStr);
    Append(buf, cap, &off, line);

    // ---- verdict -------------------------------------------------
    if (st.Flags & EVFS_OPTS_DISABLED)
    {
        wsprintfW(line, L"  Verdict: off-switch is set. The driver stays unloaded until you run\r\n"
                        L"           'filterctl enable' and then 'filterctl load' (as admin).\r\n");
        Append(buf, cap, &off, line);
    }
    else if (driverLoaded)
    {
        wsprintfW(line, L"  Verdict: driver is RUNNING. Panic off-switch: 'filterctl disable'.\r\n");
        Append(buf, cap, &off, line);
    }
    else if (EvFsWasLoadedAtLastShutdown(&st))
    {
        ULONGLONG when = 0;
        int res = EvFsUnexpectedShutdownSince(st.LoadedAt, &when);
        if (res == 1)
        {
            wchar_t whenStr[64];
            FtToStr(when, whenStr, 64);
            wsprintfW(line,
                L"  Verdict: WARNING - your machine shut down abnormally (crash or power\r\n"
                L"           loss) at %s while the driver was loaded and never cleanly\r\n"
                L"           unloaded. The driver is NOT running now and will stay off.\r\n"
                L"           Only reload it if you choose: 'filterctl load' (admin).\r\n", whenStr);
        }
        else if (res == 0)
        {
            wsprintfW(line,
                L"  Verdict: the driver was loaded when the machine last shut down, but\r\n"
                L"           that shutdown was clean. It is not running now (it never\r\n"
                L"           auto-starts after a reboot). Reload: 'filterctl load' (admin).\r\n");
        }
        else
        {
            wsprintfW(line,
                L"  Verdict: the driver was loaded at the last shutdown, but the crash\r\n"
                L"           check could not run (event log inaccessible). Keep it\r\n"
                L"           unloaded until you can verify the last shutdown was clean.\r\n");
        }
        Append(buf, cap, &off, line);
    }
    else if (st.Flags & EVFS_OPTS_LOADED)
    {
        wsprintfW(line, L"  Verdict: the driver was loaded before and was cleanly unloaded.\r\n"
                        L"           It is not running now (it never auto-starts). Reload it:\r\n"
                        L"           'filterctl load' (admin).\r\n");
        Append(buf, cap, &off, line);
    }
    else
    {
        wsprintfW(line, L"  Verdict: no driver history on this machine. It is not running.\r\n"
                        L"           To start it (after building + VM-testing it):\r\n"
                        L"           'filterctl load' as administrator.\r\n");
        Append(buf, cap, &off, line);
    }

    return 1;
}
