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
    ULONG MessageId;
} EV_FILTER_MESSAGE_HEADER;

typedef struct _EV_FILTER_REPLY_HEADER {
    ULONG Status;
    ULONG MessageId;
} EV_FILTER_REPLY_HEADER;

typedef HRESULT(WINAPI* FnConnect)(LPCWSTR, DWORD, LPCVOID, DWORD, LPVOID, HANDLE*);
typedef HRESULT(WINAPI* FnSend)(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD);
typedef HRESULT(WINAPI* FnGetMessage)(HANDLE, LPVOID, DWORD, LPDWORD);
typedef HRESULT(WINAPI* FnReplyMessage)(HANDLE, LPVOID, DWORD);
typedef BOOL(WINAPI* FnClose)(HANDLE);

static HMODULE     g_hFltlib = NULL;
static FnConnect   g_pConnect    = NULL;
static FnSend      g_pSend       = NULL;
static FnGetMessage g_pGetMessage = NULL;
static FnReplyMessage g_pReply   = NULL;
static FnClose     g_pClose      = NULL;
static HANDLE      g_hPort       = INVALID_HANDLE_VALUE;

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
    FnReplyMessage r = (FnReplyMessage)(void*)GetProcAddress(h, "FilterReplyMessage");
    FnClose      cl = (FnClose)(void*)GetProcAddress(h, "FilterClose");
    if (!c || !s || !gm || !r || !cl)
    {
        FreeLibrary(h);
        return false;
    }

    g_hFltlib = h;
    g_pConnect = c;
    g_pSend = s;
    g_pGetMessage = gm;
    g_pReply = r;
    g_pClose = cl;
    return true;
}

static bool EvConnect()
{
    if (g_hPort != INVALID_HANDLE_VALUE && g_hPort != NULL)
        return true;
    if (!EvLoadApi())
        return false;

    HANDLE h = INVALID_HANDLE_VALUE;
    HRESULT hr = g_pConnect(EVFILTER_PORT_NAME, 0, NULL, 0, NULL, &h);
    if (FAILED(hr) || h == INVALID_HANDLE_VALUE || h == NULL)
        return false;

    g_hPort = h;
    return true;
}

bool EvFilterAvailable()
{
    return EvConnect();
}

bool EvPortSend(unsigned long op, const std::wstring& path)
{
    if (!EvConnect())
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

int EvGuardLoop(const std::function<void(const std::wstring&, const std::wstring&)>& onDenied)
{
    if (!EvConnect())
        return 0;   // driver not loaded — exit quietly

    struct GuardBuf {
        EV_FILTER_MESSAGE_HEADER hdr;
        EVFILTER_NOTIFY notify;
    };

    for (;;)
    {
        GuardBuf buf = {};
        DWORD bytes = 0;
        HRESULT hr = g_pGetMessage(g_hPort, &buf, sizeof(buf), &bytes);
        if (FAILED(hr))
            break;   // port closed (driver unloaded / service replaced)

        // Reply immediately so the kernel work item is never blocked on
        // our (potentially long) password dialog.
        EV_FILTER_REPLY_HEADER reply = {};
        reply.MessageId = buf.hdr.MessageId;
        g_pReply(g_hPort, &reply, sizeof(reply));

        if (buf.notify.OpCode == EVFILTER_NOTIFY_DENIED)
        {
            std::wstring app;
            if (buf.notify.RequesterApp[0])
                app = std::wstring(buf.notify.RequesterApp);
            onDenied(std::wstring(buf.notify.Path), app);
        }
    }
    return 0;
}
