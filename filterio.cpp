//------------------------------------------------------------
// filterio.cpp — user-mode access to the EchoVault minifilter
//
// Uses fltlib.dll loaded dynamically so this builds with any
// toolchain (no import library needed). Everything is best-
// effort: with the driver absent, all calls fail silently.
//------------------------------------------------------------

#include <windows.h>

#include "filterio.h"
#include "shared/evfilter.h"

// fltUserStructures.h may not ship with MinGW — the two structs
// below are its exact layouts, so the ABI matches fltlib.dll.
typedef struct _EV_FILTER_MESSAGE_HEADER {
    ULONG ReplyLength;
    ULONGLONG MessageId;
} EV_FILTER_MESSAGE_HEADER;

static_assert(FIELD_OFFSET(EV_FILTER_MESSAGE_HEADER, MessageId) == 8,
    "FILTER_MESSAGE_HEADER ABI mismatch");
static_assert(sizeof(EV_FILTER_MESSAGE_HEADER) == 16,
    "FILTER_MESSAGE_HEADER size mismatch");

typedef HRESULT(WINAPI* FnConnect)(LPCWSTR, DWORD, LPCVOID, WORD, LPVOID, HANDLE*);
typedef HRESULT(WINAPI* FnSend)(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD);
typedef HRESULT(WINAPI* FnGetMessage)(HANDLE, LPVOID, DWORD, LPOVERLAPPED);

static HMODULE     g_hFltlib = NULL;
static FnConnect   g_pConnect    = NULL;
static FnSend      g_pSend       = NULL;
static FnGetMessage g_pGetMessage = NULL;
static HANDLE      g_hPort       = INVALID_HANDLE_VALUE;
static unsigned long g_portRole  = 0;

static bool EvLoadApi()
{
    if (g_hFltlib)
        return true;

    HMODULE h = LoadLibraryW(L"fltlib.dll");
    if (!h)
        return false;

    FnConnect    c  = (FnConnect)(void*)GetProcAddress(h, "FilterConnectCommunicationPort");
    FnSend       s  = (FnSend)(void*)GetProcAddress(h, "FilterSendMessage");
    FnGetMessage gm = (FnGetMessage)(void*)GetProcAddress(h, "FilterGetMessage");
    if (!c || !s || !gm)
    {
        FreeLibrary(h);
        return false;
    }

    g_hFltlib = h;
    g_pConnect = c;
    g_pSend = s;
    g_pGetMessage = gm;
    return true;
}

static bool EvConnect(unsigned long role)
{
    if (g_hPort != INVALID_HANDLE_VALUE && g_hPort != NULL)
    {
        if (g_portRole == role)
            return true;
        CloseHandle(g_hPort);
        g_hPort = INVALID_HANDLE_VALUE;
        g_portRole = 0;
    }
    if (!EvLoadApi())
        return false;

    HANDLE h = INVALID_HANDLE_VALUE;
    EVFILTER_CONNECT_CONTEXT context = {};
    context.Magic = EVFILTER_CONNECT_MAGIC;
    context.Role = role;
    HRESULT hr = g_pConnect(EVFILTER_PORT_NAME, 0, &context,
        sizeof(context), NULL, &h);
    if (FAILED(hr) || h == INVALID_HANDLE_VALUE || h == NULL)
        return false;

    g_hPort = h;
    g_portRole = role;
    return true;
}

bool EvFilterAvailable()
{
    return EvConnect(EVFILTER_ROLE_CONTROL);
}

bool EvPortSend(unsigned long op, const std::wstring& path)
{
    if (!EvConnect(EVFILTER_ROLE_CONTROL))
        return false;

    EVFILTER_MSG msg = {};
    msg.OpCode = op;
    size_t n = path.size();
    if (n >= EVFILTER_MAX_PATH)
        n = EVFILTER_MAX_PATH - 1;
    for (size_t i = 0; i < n; i++)
        msg.Path[i] = path[i];
    msg.Path[n] = L'\0';

    DWORD msgSize = (DWORD)(FIELD_OFFSET(EVFILTER_MSG, Path) + (n + 1) * sizeof(WCHAR));
    DWORD returned = 0;
    HRESULT hr = g_pSend(g_hPort, &msg, msgSize, NULL, 0, &returned);
    if (FAILED(hr))
    {
        // A handle becomes permanently stale after driver unload/reload.
        // Drop it so the next operation reconnects to the new instance.
        CloseHandle(g_hPort);
        g_hPort = INVALID_HANDLE_VALUE;
        g_portRole = 0;
    }
    return SUCCEEDED(hr);
}

// Directories get a trailing backslash so the driver registers them as
// prefix entries (the folder itself + everything under it).
static std::wstring EvDirPath(const std::wstring& p)
{
    if (p.empty() || p.back() == L'\\')
        return p;
    DWORD attrs = GetFileAttributesW(p.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
        return p + L"\\";
    return p;
}

void EvAllowFor(const std::wstring& path)
{
    EvPortSend(EVFILTER_MSG_ALLOW, EvDirPath(path));
}

void EvDenyFor(const std::wstring& path)
{
    EvPortSend(EVFILTER_MSG_DISALLOW, EvDirPath(path));
}

void EvRegister(const std::wstring& path)
{
    EvPortSend(EVFILTER_MSG_ADD, EvDirPath(path));
}

void EvUnregister(const std::wstring& path)
{
    EvPortSend(EVFILTER_MSG_REMOVE, EvDirPath(path));
}

// Normalized minifilter names use NT device paths.  Convert them back to a
// Win32 path before the guard hands them to std::filesystem or ShellExecute.
static std::wstring EvToUserPath(const std::wstring& path)
{
    const std::wstring mup = L"\\Device\\Mup\\";
    if (path.size() >= mup.size() &&
        _wcsnicmp(path.c_str(), mup.c_str(), mup.size()) == 0)
        return L"\\\\" + path.substr(mup.size());

    DWORD drives = GetLogicalDrives();
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
    {
        if ((drives & (1UL << (letter - L'A'))) == 0)
            continue;
        wchar_t drive[3] = { letter, L':', L'\0' };
        wchar_t device[1024] = L"";
        if (!QueryDosDeviceW(drive, device, 1024))
            continue;
        size_t n = wcslen(device);
        if (path.size() >= n && _wcsnicmp(path.c_str(), device, n) == 0 &&
            (path.size() == n || path[n] == L'\\'))
            return std::wstring(drive) + path.substr(n);
    }
    return path; // best-effort; never invent a path when mapping is unknown
}

int EvGuardLoop(const std::function<void(const std::wstring&, const std::wstring&)>& onDenied)
{
    if (!EvConnect(EVFILTER_ROLE_GUARD))
        return 0;   // driver not loaded — exit quietly

    struct GuardBuf {
        EV_FILTER_MESSAGE_HEADER hdr;
        EVFILTER_NOTIFY notify;
    };

    for (;;)
    {
        GuardBuf buf = {};
        // Synchronous receive: FilterGetMessage's fourth parameter is an
        // optional OVERLAPPED pointer, not a byte-count pointer.
        HRESULT hr = g_pGetMessage(g_hPort, &buf, sizeof(buf), NULL);
        if (FAILED(hr))
            break;   // port closed (driver unloaded / service replaced)

        if (buf.notify.OpCode == EVFILTER_NOTIFY_DENIED)
        {
            std::wstring app;
            if (buf.notify.RequesterApp[0])
                app = std::wstring(buf.notify.RequesterApp);
            onDenied(EvToUserPath(std::wstring(buf.notify.Path)), app);
        }
    }
    CloseHandle(g_hPort);
    g_hPort = INVALID_HANDLE_VALUE;
    g_portRole = 0;
    return 0;
}
