//------------------------------------------------------------
// ui.cpp  —  Win32 dialogs for EchoVault
//------------------------------------------------------------

// Define the Task Scheduler GUIDs (CLSID_TaskScheduler, IID_ITaskService)
// in this translation unit. Must come before <windows.h> so guiddef.h
// sees INITGUID on first parse.
#define INITGUID

#include "ui.h"
#include "vault.h"

#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <taskschd.h>

#include <fstream>
#include <vector>

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// ---- Control IDs -------------------------------------------------

#define IDC_PW_EDIT     101
#define IDC_PW_SHOW     102
#define IDC_PW_OK       103
#define IDC_PW_CANCEL   104
#define IDC_PW_FORGOT   105

#define IDC_MENU_ADD          201
#define IDC_MENU_REMOVE       202
#define IDC_MENU_CHANGE_FILE  203
#define IDC_MENU_CHANGE_MASTER 204
#define IDC_MENU_EXIT         206
#define IDC_MENU_SETUP        207
#define IDC_MENU_OPEN         208

#define IDC_SEL_FILE          301
#define IDC_SEL_FOLDER        302
#define IDC_SEL_CANCEL        303

// ---- Shared helpers ---------------------------------------------

static HFONT GetUIFont()
{
    static HFONT hFont = nullptr;
    if (!hFont)
        hFont = CreateFontW(
            -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    return hFont;
}

static HFONT GetTitleFont()
{
    static HFONT hFont = nullptr;
    if (!hFont)
        hFont = CreateFontW(
            -20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    return hFont;
}

static void CenterWindow(HWND hwnd)
{
    RECT rc;
    GetWindowRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

static HWND MakeChild(HWND parent, const wchar_t* cls, const wchar_t* text,
                      DWORD style, DWORD exStyle,
                      int x, int y, int w, int h, int id)
{
    HWND hw = CreateWindowExW(exStyle, cls, text,
        WS_CHILD | WS_VISIBLE | style,
        x, y, w, h,
        parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandle(nullptr), nullptr);
    SendMessageW(hw, WM_SETFONT, (WPARAM)GetUIFont(), TRUE);
    return hw;
}

// ------------------------------------------------------------------
// Robust modal message pump for the custom dialogs.
//
// We never post WM_QUIT (a lingering WM_QUIT breaks the *next* dialog's
// message loop and MessageBoxes, which shows up as dialogs that pop up
// and vanish or never appear). Each loop just runs until its window is
// destroyed. Enter/Escape are handled at the pump level so they always
// work no matter which control has focus; when a button has focus, Enter
// is left to IsDialogMessage so it clicks that button (standard dialog
// behaviour).
// ------------------------------------------------------------------
static void RunDialogLoop(HWND hwnd, WORD defaultId, WORD cancelId)
{
    MSG msg;
    while (IsWindow(hwnd))
    {
        BOOL r = GetMessageW(&msg, nullptr, 0, 0);
        if (r <= 0)
            break;   // WM_QUIT or error

        if (msg.message == WM_KEYDOWN)
        {
            if (msg.wParam == VK_ESCAPE)
            {
                SendMessageW(hwnd, WM_COMMAND, cancelId, 0);
                continue;
            }
            if (msg.wParam == VK_RETURN)
            {
                // Let Enter click a focused button normally.
                HWND f = GetFocus();
                wchar_t cls[16] = L"";
                bool btn = (f != nullptr &&
                            GetClassNameW(f, cls, 16) > 0 &&
                            lstrcmpiW(cls, L"Button") == 0);
                if (!btn)
                {
                    SendMessageW(hwnd, WM_COMMAND, defaultId, 0);
                    continue;
                }
            }
        }

        if (IsDialogMessageW(hwnd, &msg))
            continue;

        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

//====================================================================
// Password dialog
//====================================================================

struct PwDlgData {
    std::wstring title;
    std::wstring message;
    bool         showForgot;
    std::wstring forgotText;
    PasswordAnswer answer;
    HWND hEdit;
    HWND hCheck;
};

static LRESULT CALLBACK PwDlgProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* d = reinterpret_cast<PwDlgData*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        d = reinterpret_cast<PwDlgData*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(d));

        int y = 15;
        MakeChild(hwnd, L"STATIC", d->message.c_str(),
                  SS_LEFT, 0,  15, y, 340, 20,  0);
        y += 28;

        d->hEdit = MakeChild(hwnd, L"EDIT", L"",
                  ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP,
                  WS_EX_CLIENTEDGE,
                  15, y, 340, 26,  IDC_PW_EDIT);
        SendMessageW(d->hEdit, EM_SETPASSWORDCHAR, 0x25CF, 0); // ●
        y += 34;

        d->hCheck = MakeChild(hwnd, L"BUTTON", L"Show password",
                  BS_AUTOCHECKBOX | WS_TABSTOP, 0,
                  15, y, 150, 20,  IDC_PW_SHOW);
        y += 30;

        if (d->showForgot) {
            MakeChild(hwnd, L"BUTTON", d->forgotText.c_str(),
                      BS_FLAT | WS_TABSTOP, 0,
                      15, y, 160, 26,  IDC_PW_FORGOT);
            y += 36;
        }

        MakeChild(hwnd, L"BUTTON", L"OK",
                  BS_DEFPUSHBUTTON | WS_TABSTOP, 0,
                  180, y, 85, 30,  IDC_PW_OK);
        MakeChild(hwnd, L"BUTTON", L"Cancel",
                  WS_TABSTOP, 0,
                  270, y, 85, 30,  IDC_PW_CANCEL);

        SetFocus(d->hEdit);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_PW_OK:
        {
            int len = GetWindowTextLengthW(d->hEdit);
            if (len > 0) {
                d->answer.password.resize(len + 1);
                GetWindowTextW(d->hEdit, &d->answer.password[0], len + 1);
                d->answer.password.resize(len);
            } else {
                d->answer.password.clear();
            }
            d->answer.result = PasswordResult::OK;
            DestroyWindow(hwnd);
            break;
        }
        case IDC_PW_CANCEL:
            d->answer.result = PasswordResult::Cancel;
            DestroyWindow(hwnd);
            break;

        case IDC_PW_FORGOT:
            d->answer.result = PasswordResult::ForgotPassword;
            DestroyWindow(hwnd);
            break;

        case IDC_PW_SHOW:
        {
            bool show = (SendMessageW(d->hCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageW(d->hEdit, EM_SETPASSWORDCHAR,
                         show ? 0 : 0x25CF, 0);
            InvalidateRect(d->hEdit, nullptr, TRUE);
            break;
        }
        }
        return 0;

    case DM_GETDEFID:
        return MAKELRESULT(IDC_PW_OK, DC_HASDEFID);

    case WM_CLOSE:
        d->answer.result = PasswordResult::Cancel;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

PasswordAnswer PromptPassword(
    const std::wstring& title,
    const std::wstring& message,
    bool showForgot,
    const std::wstring& forgotText)
{
    static bool reg = false;
    if (!reg) {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = PwDlgProc;
        wc.hInstance      = GetModuleHandle(nullptr);
        wc.lpszClassName  = L"EchoVault_PwDlg";
        wc.hbrBackground  = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.hCursor        = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
        RegisterClassExW(&wc);
        reg = true;
    }

    PwDlgData data;
    data.title      = title;
    data.message    = message;
    data.showForgot = showForgot;
    data.forgotText = forgotText;

    int clientH = showForgot ? 200 : 170;
    RECT rc = { 0, 0, 375, clientH };
    AdjustWindowRectEx(&rc, WS_POPUP | WS_CAPTION | WS_SYSMENU,
                       FALSE, WS_EX_DLGMODALFRAME);

    HWND hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"EchoVault_PwDlg", title.c_str(),
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, GetModuleHandle(nullptr), &data);
    if (!hwnd)
        return PasswordAnswer{};

    CenterWindow(hwnd);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetFocus(data.hEdit);

    RunDialogLoop(hwnd, IDC_PW_OK, IDC_PW_CANCEL);

    return data.answer;
}

//====================================================================
// Recovery-key input dialog
//====================================================================

struct RkDlgData {
    std::wstring result;
    bool accepted = false;
    HWND hEdit;
};

static LRESULT CALLBACK RkDlgProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* d = reinterpret_cast<RkDlgData*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        d = reinterpret_cast<RkDlgData*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(d));

        MakeChild(hwnd, L"STATIC",
                  L"Enter your 64-character recovery key:",
                  SS_LEFT, 0,  15, 15, 370, 20,  0);

        d->hEdit = MakeChild(hwnd, L"EDIT", L"",
                  ES_AUTOHSCROLL | WS_TABSTOP,
                  WS_EX_CLIENTEDGE,
                  15, 42, 370, 26,  IDC_PW_EDIT);

        MakeChild(hwnd, L"BUTTON", L"OK",
                  BS_DEFPUSHBUTTON | WS_TABSTOP, 0,
                  210, 85, 85, 30,  IDC_PW_OK);
        MakeChild(hwnd, L"BUTTON", L"Cancel",
                  WS_TABSTOP, 0,
                  300, 85, 85, 30,  IDC_PW_CANCEL);

        SetFocus(d->hEdit);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_PW_OK:
        {
            int len = GetWindowTextLengthW(d->hEdit);
            if (len > 0) {
                d->result.resize(len + 1);
                GetWindowTextW(d->hEdit, &d->result[0], len + 1);
                d->result.resize(len);
            }
            d->accepted = true;
            DestroyWindow(hwnd);
            break;
        }
        case IDC_PW_CANCEL:
            d->accepted = false;
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    case DM_GETDEFID:
        return MAKELRESULT(IDC_PW_OK, DC_HASDEFID);

    case WM_CLOSE:
        d->accepted = false;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

std::wstring PromptRecoveryKey()
{
    static bool reg = false;
    if (!reg) {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = RkDlgProc;
        wc.hInstance      = GetModuleHandle(nullptr);
        wc.lpszClassName  = L"EchoVault_RkDlg";
        wc.hbrBackground  = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.hCursor        = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
        RegisterClassExW(&wc);
        reg = true;
    }

    RkDlgData data;

    RECT rc = { 0, 0, 400, 130 };
    AdjustWindowRectEx(&rc, WS_POPUP | WS_CAPTION | WS_SYSMENU,
                       FALSE, WS_EX_DLGMODALFRAME);

    HWND hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"EchoVault_RkDlg", L"EchoVault \u2014 Recovery Key",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, GetModuleHandle(nullptr), &data);
    if (!hwnd)
        return L"";

    CenterWindow(hwnd);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetFocus(data.hEdit);

    RunDialogLoop(hwnd, IDC_PW_OK, IDC_PW_CANCEL);

    return data.accepted ? data.result : L"";
}

void ShowRecoveryKey(const std::wstring& recoveryKeyHex)
{
    std::wstring formatted;
    for (size_t i = 0; i < recoveryKeyHex.size(); i++) {
        if (i > 0 && i % 32 == 0) formatted += L'\n';
        else if (i > 0 && i % 4 == 0) formatted += L' ';
        formatted += recoveryKeyHex[i];
    }

    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        size_t bytes = (recoveryKeyHex.size() + 1) * sizeof(wchar_t);
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (hMem) {
            auto* mem = static_cast<wchar_t*>(GlobalLock(hMem));
            if (mem) {
                memcpy(mem, recoveryKeyHex.c_str(), bytes);
                GlobalUnlock(hMem);
                SetClipboardData(CF_UNICODETEXT, hMem);
            }
        }
        CloseClipboard();
    }

    std::wstring msg =
        L"IMPORTANT \u2014 Save this recovery key!\n\n"
        L"If you forget your master password, this is the\n"
        L"ONLY way to recover your encrypted data.\n\n"
        L"Recovery Key (also copied to clipboard):\n\n" +
        formatted + L"\n\n"
        L"Store it somewhere safe. You will NOT see it again.";

    MessageBoxW(nullptr, msg.c_str(),
                L"EchoVault \u2014 Recovery Key",
                MB_OK | MB_ICONWARNING);
}

//====================================================================
// Main menu
//====================================================================

struct MenuDlgData {
    MenuAction action = MenuAction::Exit;
};

static LRESULT CALLBACK MenuDlgProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* d = reinterpret_cast<MenuDlgData*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        d = reinterpret_cast<MenuDlgData*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(d));

        HWND hTitle = MakeChild(hwnd, L"STATIC", L"EchoVault",
                  SS_CENTER, 0,  0, 12, 320, 28,  0);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)GetTitleFont(), TRUE);

        MakeChild(hwnd, L"BUTTON", L"\U0001F512  Add to Vault (Encrypt)",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  60, 55, 200, 35,  IDC_MENU_ADD);

        MakeChild(hwnd, L"BUTTON", L"\U0001F513  Remove from Vault (Decrypt)",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  60, 95, 200, 35,  IDC_MENU_REMOVE);

        MakeChild(hwnd, L"BUTTON", L"Change a File's Password",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  60, 140, 200, 32,  IDC_MENU_CHANGE_FILE);

        MakeChild(hwnd, L"BUTTON", L"Change Master Password",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  60, 177, 200, 32,  IDC_MENU_CHANGE_MASTER);

        MakeChild(hwnd, L"BUTTON", L"&Open encrypted file",
                  BS_PUSHBUTTON | WS_TABSTOP, 0, 60, 214, 200, 32, IDC_MENU_OPEN);
        MakeChild(hwnd, L"BUTTON", L"Explorer &setup and status",
                  BS_PUSHBUTTON | WS_TABSTOP, 0, 60, 251, 200, 32, IDC_MENU_SETUP);
        MakeChild(hwnd, L"BUTTON", L"Exit",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  60, 288, 200, 32,  IDC_MENU_EXIT);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_MENU_ADD:
            d->action = MenuAction::Add;
            DestroyWindow(hwnd);
            break;
        case IDC_MENU_REMOVE:
            d->action = MenuAction::Remove;
            DestroyWindow(hwnd);
            break;
        case IDC_MENU_CHANGE_FILE:
            d->action = MenuAction::ChangeFilePw;
            DestroyWindow(hwnd);
            break;
        case IDC_MENU_CHANGE_MASTER:
            d->action = MenuAction::ChangeMasterPw;
            DestroyWindow(hwnd);
            break;
        case IDC_MENU_SETUP:
            d->action = MenuAction::Setup; DestroyWindow(hwnd); break;
        case IDC_MENU_OPEN:
            d->action = MenuAction::Open; DestroyWindow(hwnd); break;
        case IDC_MENU_EXIT:
            d->action = MenuAction::Exit;
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    case WM_CLOSE:
        d->action = MenuAction::Exit;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

MenuAction ShowMainMenu()
{
    static bool reg = false;
    if (!reg) {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = MenuDlgProc;
        wc.hInstance      = GetModuleHandle(nullptr);
        wc.lpszClassName  = L"EchoVault_MenuDlg";
        wc.hbrBackground  = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.hCursor        = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
        RegisterClassExW(&wc);
        reg = true;
    }

    MenuDlgData data;
    RECT rc = { 0, 0, 320, 345 };
    AdjustWindowRectEx(&rc, WS_POPUP | WS_CAPTION | WS_SYSMENU,
                       FALSE, WS_EX_DLGMODALFRAME);

    HWND hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"EchoVault_MenuDlg", L"EchoVault",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, GetModuleHandle(nullptr), &data);
    if (!hwnd)
        return MenuAction::Exit;

    CenterWindow(hwnd);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    RunDialogLoop(hwnd, IDC_MENU_ADD, IDC_MENU_EXIT);

    return data.action;
}

//====================================================================
// File / folder selection dialog
//====================================================================

struct SelDlgData {
    int choice = 0; // 1 = file, 2 = folder, 0 = cancel
};

static LRESULT CALLBACK SelDlgProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* d = reinterpret_cast<SelDlgData*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        d = reinterpret_cast<SelDlgData*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(d));

        MakeChild(hwnd, L"STATIC", L"What would you like to select?",
                  SS_CENTER, 0,  15, 20, 270, 20,  0);

        MakeChild(hwnd, L"BUTTON", L"Select a File",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  30, 50, 240, 35,  IDC_SEL_FILE);

        MakeChild(hwnd, L"BUTTON", L"Select a Folder",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  30, 95, 240, 35,  IDC_SEL_FOLDER);

        MakeChild(hwnd, L"BUTTON", L"Cancel",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  30, 150, 240, 30,  IDC_SEL_CANCEL);
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_SEL_FILE:
            d->choice = 1;
            DestroyWindow(hwnd);
            break;
        case IDC_SEL_FOLDER:
            d->choice = 2;
            DestroyWindow(hwnd);
            break;
        case IDC_SEL_CANCEL:
            d->choice = 0;
            DestroyWindow(hwnd);
            break;
        }
        return 0;
    case WM_CLOSE:
        d->choice = 0;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

std::filesystem::path SelectTarget()
{
    static bool reg = false;
    if (!reg) {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = SelDlgProc;
        wc.hInstance      = GetModuleHandle(nullptr);
        wc.lpszClassName  = L"EchoVault_SelDlg";
        wc.hbrBackground  = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.hCursor        = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
        RegisterClassExW(&wc);
        reg = true;
    }

    SelDlgData data;
    RECT rc = { 0, 0, 300, 200 };
    AdjustWindowRectEx(&rc, WS_POPUP | WS_CAPTION | WS_SYSMENU,
                       FALSE, WS_EX_DLGMODALFRAME);

    HWND hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"EchoVault_SelDlg", L"EchoVault \u2014 Select Target",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, GetModuleHandle(nullptr), &data);
    if (!hwnd)
        return {};

    CenterWindow(hwnd);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    RunDialogLoop(hwnd, IDC_SEL_FILE, IDC_SEL_CANCEL);

    if (data.choice == 0) return {};

    if (data.choice == 1) // File
    {
        wchar_t filename[MAX_PATH] = L"";
        OPENFILENAMEW ofn = {};
        ofn.lStructSize  = sizeof(ofn);
        ofn.lpstrFile    = filename;
        ofn.nMaxFile     = MAX_PATH;
        ofn.lpstrFilter  = L"All Files\0*.*\0";
        ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

        if (GetOpenFileNameW(&ofn))
            return filename;
        return {};
    }
    else // Folder
    {
        BROWSEINFOW bi = {};
        bi.lpszTitle = L"Choose Folder";
        PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
        if (!pidl) return {};

        wchar_t path[MAX_PATH];
        SHGetPathFromIDListW(pidl, path);
        CoTaskMemFree(pidl);
        return path;
    }
}

//====================================================================
// Windows Explorer Registry Hooks
//====================================================================

bool InstallRegistryHooks()
{
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return false;

    std::wstring commandStr = L"\"";
    commandStr += exePath;
    commandStr += L"\" \"%1\"";

    auto writeReg = [&](const wchar_t* subKey, const wchar_t* valName, const std::wstring& valData) {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, subKey, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
        {
            LONG status = RegSetValueExW(hKey, valName, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(valData.c_str()),
                static_cast<DWORD>((valData.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);
            return status == ERROR_SUCCESS;
        }
        return false;
    };

    // Add for all files (*)
    bool ok = writeReg(L"Software\\Classes\\*\\shell\\EchoVault", nullptr, L"EchoVault (Lock/Unlock)");
    ok = writeReg(L"Software\\Classes\\*\\shell\\EchoVault\\command", nullptr, commandStr) && ok;

    // Add for directories
    ok = writeReg(L"Software\\Classes\\Directory\\shell\\EchoVault", nullptr, L"EchoVault (Lock/Unlock)") && ok;
    ok = writeReg(L"Software\\Classes\\Directory\\shell\\EchoVault\\command", nullptr, commandStr) && ok;
    std::wstring openCommand = L"\"" + std::wstring(exePath) + L"\" --open \"%1\"";
    ok = writeReg(L"Software\\Classes\\*\\shell\\EchoVaultOpen", nullptr, L"Open with EchoVault") && ok;
    ok = writeReg(L"Software\\Classes\\*\\shell\\EchoVaultOpen\\command", nullptr, openCommand) && ok;
    if (!ok) return false;

    ShowInfo(L"EchoVault", L"Windows Explorer integration installed successfully!\n\nYou can now right-click any file or folder and select 'EchoVault (Lock/Unlock)'.");
    return true;
}

//====================================================================
// Simple message boxes
//====================================================================

void ShowError(const std::wstring& title, const std::wstring& message)
{
    MessageBoxW(nullptr, message.c_str(), title.c_str(),
                MB_OK | MB_ICONERROR);
}

void ShowInfo(const std::wstring& title, const std::wstring& message)
{
    MessageBoxW(nullptr, message.c_str(), title.c_str(),
                MB_OK | MB_ICONINFORMATION);
}

//====================================================================
// User-controlled Explorer integration. Never writes or deletes UserChoice.
// A default app is chosen in Windows Settings, not enforced by a watcher.

static std::wstring ToLowerW(std::wstring s)
{
    for (auto& c : s) if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
    return s;
}
static std::wstring GetExePath()
{
    wchar_t path[32768] = {};
    DWORD n = GetModuleFileNameW(nullptr, path, 32768);
    return n && n < 32768 ? std::wstring(path, n) : L"";
}
static std::wstring ReadReg(HKEY root, const std::wstring& path, const wchar_t* name = nullptr)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return {};
    wchar_t value[32768] = {};
    DWORD size = sizeof(value), type = 0;
    LONG rc = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(value), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || size >= sizeof(value)) return {};
    return value;
}
static bool WriteReg(const std::wstring& path, const wchar_t* name, const std::wstring& value)
{
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE,
                       nullptr, &key, nullptr) != ERROR_SUCCESS) return false;
    LONG rc = RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                            static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}
static void DeleteRegValue(const std::wstring& path, const wchar_t* name)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegDeleteValueW(key, name);
        RegCloseKey(key);
    }
}
static const std::wstring kIntegration = L"Software\\EchoVault\\OpenInterception";
static const std::wstring kCapabilities = L"Software\\EchoVault\\Capabilities";
static const wchar_t* kCommonExtensions[] = {
    L".txt", L".md", L".log", L".ini", L".cfg", L".conf", L".csv", L".tsv",
    L".json", L".xml", L".yaml", L".yml", L".rtf", L".doc", L".docx", L".xls",
    L".xlsx", L".ppt", L".pptx", L".pdf", L".cpp", L".c",
    L".h", L".hpp", L".cs", L".java", L".go", L".rs",
    L".ts", L".html", L".htm", L".css", L".sql", L".bgt",
    L".nvgt", L".sbl", L".png", L".jpg", L".jpeg", L".gif", L".bmp", L".tiff",
    L".svg", L".webp", L".mp3", L".wav", L".m4a", L".ogg", L".flac", L".mp4",
    L".mkv", L".avi", L".mov", L".wmv", L".webm"
};
static std::vector<std::wstring> RegisteredExtensions()
{
    std::vector<std::wstring> exts;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kIntegration.c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &key) != ERROR_SUCCESS) return exts;
    for (DWORD i = 0;; ++i) {
        wchar_t name[256] = {}; DWORD n = 256;
        LONG rc = RegEnumKeyExW(key, i, name, &n, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_SUCCESS && name[0] == L'.') exts.emplace_back(name, n);
    }
    RegCloseKey(key);
    return exts;
}
static std::wstring CurrentHandler(const std::wstring& ext)
{
    auto chosen = ReadReg(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\" + ext + L"\\UserChoice", L"ProgId");
    if (!chosen.empty()) return chosen;
    return ReadReg(HKEY_CLASSES_ROOT, ext);
}
bool RepairScriptAssociations()
{
    struct ScriptType { const wchar_t* extension; const wchar_t* fallback; };
    static const ScriptType scripts[] = {
        { L".bat", L"batfile" }, { L".cmd", L"cmdfile" },
        { L".ps1", L"" }, { L".vbs", L"VBSFile" }, { L".js", L"JSFile" },
        { L".mjs", L"" }, { L".cjs", L"" }, { L".py", L"" },
        { L".pyw", L"" }, { L".rb", L"" }, { L".php", L"" },
        { L".lua", L"" }, { L".sh", L"" }, { L".ahk", L"" }
    };
    bool success = true;
    bool changed = false;
    for (const auto& script : scripts) {
        std::wstring ext = script.extension;
        std::wstring backupPath = kIntegration + L"\\" + ext;
        std::wstring backup = ReadReg(HKEY_CURRENT_USER, backupPath, L"ProgID");
        std::wstring replacement = backup.empty() ? script.fallback : backup;
        std::wstring userChoicePath =
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\" +
            ext + L"\\UserChoice";
        std::wstring chosen = ReadReg(HKEY_CURRENT_USER, userChoicePath, L"ProgId");
        if (ToLowerW(chosen) == L"echovaultopen") {
            LONG rc = RegDeleteTreeW(HKEY_CURRENT_USER, userChoicePath.c_str());
            if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND && rc != ERROR_PATH_NOT_FOUND)
                success = false;
            else
                changed = true;
        }
        std::wstring classPath = L"Software\\Classes\\" + ext;
        if (ToLowerW(ReadReg(HKEY_CURRENT_USER, classPath)) == L"echovaultopen") {
            if (replacement.empty())
                DeleteRegValue(classPath, nullptr);
            else if (!WriteReg(classPath, nullptr, replacement))
                success = false;
            changed = true;
        }
        DeleteRegValue(classPath + L"\\OpenWithProgids", L"EchoVaultOpen");
        DeleteRegValue(kCapabilities + L"\\FileAssociations", ext.c_str());
        RegDeleteTreeW(HKEY_CURRENT_USER, backupPath.c_str());
    }
    if (changed)
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    return success;
}
static bool FindOriginalHandler(const std::wstring& ext, std::wstring& prog, std::wstring& command)
{
    prog = CurrentHandler(ext);
    if (ToLowerW(prog) == L"echovaultopen") {
        prog = ReadReg(HKEY_CURRENT_USER, kIntegration + L"\\" + ext, L"ProgID");
        command = ReadReg(HKEY_CURRENT_USER, kIntegration + L"\\" + ext, L"Command");
    } else command = ReadReg(HKEY_CLASSES_ROOT, prog + L"\\shell\\open\\command");
    return !prog.empty() && !command.empty() && ToLowerW(prog) != L"echovaultopen";
}
bool IsOpenInterceptionInstalled()
{
    return ReadReg(HKEY_CURRENT_USER, kIntegration, L"Mode") == L"UserChoice";
}
static bool RegisterExtension(std::wstring ext)
{
    ext = ToLowerW(ext);
    if (ext.empty() || ext[0] != L'.' || ext.size() > 64 ||
        ext.find_first_of(L"\\/\" :*?") != std::wstring::npos) return false;
    static const wchar_t* executableScripts[] = {
        L".bat", L".cmd", L".ps1", L".vbs", L".js", L".mjs", L".cjs",
        L".py", L".pyw", L".rb", L".php", L".lua", L".sh", L".ahk"
    };
    for (const auto* script : executableScripts)
        if (ext == script) return false;
    std::wstring prog, command;
    FindOriginalHandler(ext, prog, command);
    auto backup = kIntegration + L"\\" + ext;
    if (!prog.empty() && ReadReg(HKEY_CURRENT_USER, backup, L"ProgID").empty()) {
        if (!WriteReg(backup, L"ProgID", prog) || !WriteReg(backup, L"Command", command)) return false;
    }
    return WriteReg(backup, L"Registered", L"1") &&
        WriteReg(L"Software\\Classes\\" + ext + L"\\OpenWithProgids", L"EchoVaultOpen", L"") &&
        WriteReg(kCapabilities + L"\\FileAssociations", ext.c_str(), L"EchoVaultOpen");
}
void EnsureExtensionIntercepted(const std::wstring& ext)
{
    // Encryption itself does not install startup tasks or change defaults.
    if (!IsOpenInterceptionInstalled() || !RegisterExtension(ext)) return;
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    if (ReadReg(HKEY_CURRENT_USER, kIntegration, L"SettingsOffered") != L"1" &&
        ToLowerW(CurrentHandler(ToLowerW(ext))) != L"echovaultopen") {
        // Persist this choice so right-click launches (each a new process) do
        // not repeat the same reminder for every encrypted file.
        WriteReg(kIntegration, L"SettingsOffered", L"1");
        if (MessageBoxW(nullptr,
            (L"EchoVault is now available for " + ToLowerW(ext) +
             L" files, but Windows is still sending double-clicks to another app. "
             L"Until you choose EchoVault for this type, use 'Open with EchoVault' or the app menu.\n\n"
             L"Open Windows Default Apps now?").c_str(),
            L"EchoVault - Enable double-click prompt", MB_YESNO | MB_ICONINFORMATION | MB_DEFBUTTON2) == IDYES)
            ShellExecuteW(nullptr, L"open", L"ms-settings:defaultapps?registeredAppUser=EchoVault",
                          nullptr, nullptr, SW_SHOWNORMAL);
    }
}
bool AddOpenInterceptionExt(const std::wstring& ext)
{
    return IsOpenInterceptionInstalled() && RegisterExtension(ext.empty() || ext[0] == L'.' ? ext : L"." + ext);
}
bool RemoveOpenInterceptionExt(const std::wstring& extIn)
{
    std::wstring ext = ToLowerW(extIn);
    if (ext.empty()) return false;
    if (ext[0] != L'.') ext = L"." + ext;
    if (ext.find_first_of(L"\\/\" :*?") != std::wstring::npos) return false;
    DeleteRegValue(L"Software\\Classes\\" + ext + L"\\OpenWithProgids", L"EchoVaultOpen");
    DeleteRegValue(kCapabilities + L"\\FileAssociations", ext.c_str());
    // Keep the original handler backup: Windows may still have EchoVault
    // selected for this type until the user chooses something else in Settings.
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    return true;
}
static std::wstring AssociationStatus()
{
    if (!IsOpenInterceptionInstalled()) return L"Explorer setup has not been enabled.";
    int active = 0, other = 0;
    std::wstring names;
    for (const auto& ext : RegisteredExtensions()) {
        if (ToLowerW(CurrentHandler(ext)) == L"echovaultopen") ++active;
        else { ++other; if (other <= 15) names += ext + L" "; }
    }
    return L"File types set to open with EchoVault: " + std::to_wstring(active) +
        L"\nFile types using another app or not yet selected: " + std::to_wstring(other) +
        L"\n" + names + L"\n\nAnother app may show encrypted bytes instead of a password prompt. "
        L"Encryption remains in place. Use EchoVault's Decrypt button or right-click menu, "
        L"or choose EchoVault for that file type in Windows Settings. This affects all files of that type.";
}
void ReassertInterception()
{
    // Compatibility entry point: report only. Do not fight the user's choice.
    static std::wstring last;
    std::wstring status = AssociationStatus();
    if (status == last) return;
    auto path = GetVaultDirectory() / L"association-status.txt";
    std::wofstream out(path);
    if (out) { out << status; last = status; }
}
static const wchar_t* kWatcherStopEvent = L"EchoVaultAssocWatcherStop";
void StopAssocWatcher()
{
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, kWatcherStopEvent);
    if (event) { SetEvent(event); CloseHandle(event); }
}
bool StartAssocWatcher()
{
    if (!IsOpenInterceptionInstalled()) return false;
    HANDLE existing = OpenMutexW(SYNCHRONIZE, FALSE, L"EchoVaultAssocWatcher");
    if (existing) { CloseHandle(existing); return true; }
    auto exe = GetExePath();
    std::wstring command = L"\"" + exe + L"\" --watch";
    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) return false;
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return true;
}
int RunAssocWatcher()
{
    HANDLE mutex = CreateMutexW(nullptr, FALSE, L"EchoVaultAssocWatcher");
    if (!mutex) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(mutex); return 0; }
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, kWatcherStopEvent);
    if (!stop) { CloseHandle(mutex); return 1; }
    ResetEvent(stop);
    while (IsOpenInterceptionInstalled()) {
        ReassertInterception();
        if (WaitForSingleObject(stop, 30000) != WAIT_TIMEOUT) break;
    }
    CloseHandle(stop); CloseHandle(mutex); return 0;
}
static void RemoveTaskByName(const wchar_t* taskName)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE)
    {
        ITaskService* pSvc = nullptr;
        if (SUCCEEDED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                IID_ITaskService, reinterpret_cast<void**>(&pSvc))))
        {
            if (SUCCEEDED(pSvc->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT())))
            {
                ITaskFolder* pRoot = nullptr;
                BSTR rootPath = SysAllocString(L"\\");
                if (rootPath && SUCCEEDED(pSvc->GetFolder(rootPath, &pRoot)))
                {
                    BSTR name = SysAllocString(taskName);
                    if (name)
                    {
                        pRoot->DeleteTask(name, 0);
                        SysFreeString(name);
                    }
                    pRoot->Release();
                }
                if (rootPath) SysFreeString(rootPath);
            }
            pSvc->Release();
        }
    }
    if (SUCCEEDED(hr)) CoUninitialize();
}


// Only reverse the legacy values EchoVault itself owned. Keep other values,
// OpenWith lists, and Windows UserChoice intact.
static void RestoreLegacyDefaults()
{
    for (const auto& ext : RegisteredExtensions()) {
        auto path = L"Software\\Classes\\" + ext;
        if (ToLowerW(ReadReg(HKEY_CURRENT_USER, path)) == L"echovaultopen") {
            auto backup = ReadReg(HKEY_CURRENT_USER, kIntegration + L"\\" + ext, L"ProgID");
            if (backup.empty()) DeleteRegValue(path, nullptr);
            else WriteReg(path, nullptr, backup);
        }
    }
    const std::wstring path = L"Software\\Classes\\*\\shell\\open\\command";
    auto cmd = ToLowerW(ReadReg(HKEY_CURRENT_USER, path));
    if (cmd.find(L"echovault.exe") != std::wstring::npos && cmd.find(L"--open") != std::wstring::npos) {
        auto backup = ReadReg(HKEY_CURRENT_USER, kIntegration + L"\\*", L"Command");
        if (backup.empty()) DeleteRegValue(path, nullptr);
        else WriteReg(path, nullptr, backup);
    }
    RemoveTaskByName(L"EchoVaultWatcher");
    RemoveTaskByName(L"EchoVaultGuard");
    DeleteRegValue(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"EchoVaultAssocWatcher");
    StopAssocWatcher();
}
bool InstallOpenInterception()
{
    RepairScriptAssociations();
    RestoreLegacyDefaults();
    std::wstring cmd = L"\"" + GetExePath() + L"\" --open \"%1\"";
    bool ok = WriteReg(L"Software\\Classes\\EchoVaultOpen", nullptr, L"EchoVault protected file") &&
        WriteReg(L"Software\\Classes\\EchoVaultOpen\\shell\\open\\command", nullptr, cmd) &&
        WriteReg(kCapabilities, L"ApplicationName", L"EchoVault") &&
        WriteReg(kCapabilities, L"ApplicationDescription", L"Password-protected files; no kernel driver") &&
        WriteReg(L"Software\\RegisteredApplications", L"EchoVault", kCapabilities) &&
        WriteReg(kIntegration, L"Mode", L"UserChoice");
    for (const auto* ext : kCommonExtensions) ok = RegisterExtension(ext) && ok;
    for (const auto& ext : RegisteredExtensions()) ok = RegisterExtension(ext) && ok;
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    return ok;
}
bool UninstallOpenInterception()
{
    RepairScriptAssociations();
    RestoreLegacyDefaults();
    for (const auto& ext : RegisteredExtensions())
        DeleteRegValue(L"Software\\Classes\\" + ext + L"\\OpenWithProgids", L"EchoVaultOpen");
    DeleteRegValue(L"Software\\RegisteredApplications", L"EchoVault");
    RegDeleteTreeW(HKEY_CURRENT_USER, kCapabilities.c_str());
    RegDeleteTreeW(HKEY_CURRENT_USER, kIntegration.c_str());
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\EchoVaultOpen");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\*\\shell\\EchoVault");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\Directory\\shell\\EchoVault");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\*\\shell\\EchoVaultOpen");
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    return true;
}
void ManageOpenInterception()
{
    bool firstSetup = !IsOpenInterceptionInstalled();
    if (firstSetup) {
        if (MessageBoxW(nullptr,
            L"Enable EchoVault's right-click actions and make it available in Windows Default Apps?\n\n"
            L"This does not load a driver or change your current default apps. "
            L"You choose the types that open with EchoVault in Windows Settings.",
            L"EchoVault - Explorer setup", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
    }
    // Refresh an existing beta installation as well. Earlier builds registered
    // only .txt, so merely opening this screen must add the complete list.
    if (!InstallOpenInterception() || (firstSetup && !InstallRegistryHooks())) {
        ShowError(L"EchoVault", L"Explorer setup could not be completed."); return;
    }
    ReassertInterception();
    auto text = AssociationStatus() + L"\n\nOpen Windows Default Apps now?";
    WriteReg(kIntegration, L"SettingsOffered", L"1");
    if (MessageBoxW(nullptr, text.c_str(), L"EchoVault - Explorer status",
            MB_YESNO | MB_ICONINFORMATION | MB_DEFBUTTON2) == IDYES)
        ShellExecuteW(nullptr, L"open", L"ms-settings:defaultapps?registeredAppUser=EchoVault",
                      nullptr, nullptr, SW_SHOWNORMAL);
}

// Substitute %1/%L with the quoted file path, expand env vars, and drop
// the other %2..%9 parameters. Appends the path if there was no placeholder.
static std::wstring SubstituteArgs(
    const std::wstring& command,
    const std::wstring& filePath)
{
    DWORD n = ExpandEnvironmentStringsW(command.c_str(), nullptr, 0);
    std::wstring exp;
    if (n > 1)
    {
        exp.resize(n);
        ExpandEnvironmentStringsW(command.c_str(), &exp[0], n);
        exp.resize(n - 1);
    }
    else
    {
        exp = command;
    }

    std::wstring out;
    bool appended = false;
    for (size_t i = 0; i < exp.size(); i++)
    {
        if (exp[i] == L'%' && i + 1 < exp.size())
        {
            wchar_t c = exp[i + 1];
            if (c == L'1' || c == L'L')
            {
                // Windows command templates differ: some already carry their
                // own quotes ("%1" %* — .bat/.cmd), some don't
                // (NOTEPAD.EXE %1 — .txt). Quote the path only when the
                // template does not, to avoid both double-quoting and
                // unquoted paths with spaces.
                bool quotedInTemplate =
                    (i > 0 && exp[i - 1] == L'"') &&
                    (i + 2 < exp.size() && exp[i + 2] == L'"');
                if (quotedInTemplate)
                    out += filePath;
                else
                    out += L"\"" + filePath + L"\"";
                appended = true;
                i++;
                continue;
            }
            if (c >= L'2' && c <= L'9')
            {
                i++;
                continue;
            }
        }
        out += exp[i];
    }

    if (!appended)
        out += L" \"" + filePath + L"\"";

    return out;
}

// Opens a file with the program that was associated with it BEFORE
// EchoVault installed its open-interception handler.
// Returns the launched process id, or 0 if nothing was launched.
unsigned long OpenWithOriginalApp(const std::filesystem::path& filePath,
                                  const std::wstring& appOverride)
{
    // Fail-safe: never hand an encrypted file to another program. If a
    // file still starts with EVF2, something went wrong upstream — refuse
    // rather than show protected content as garbage.
    if (IsEncrypted(filePath))
    {
        ShowError(L"EchoVault",
            L"This file is still encrypted and could not be unlocked.\n"
            L"It was NOT opened, to avoid exposing its protected contents.\n"
            L"\nTry unlocking it from the right-click menu.");
        return 0;
    }

    // Phase 3: the driver told us which app tried to open this file
    // ("Open with" fidelity). Launch THAT app with the file. ShellExecuteEx
    // resolves the base name via App Paths and the standard search, so
    // this works for any normally-installed program. Never use EchoVault
    // itself, and fall through to the default program if it fails.
    if (!appOverride.empty() &&
        ToLowerW(appOverride).find(L"echovault") == std::wstring::npos)
    {
        std::wstring params = L"\"" + filePath.wstring() + L"\"";
        SHELLEXECUTEINFOW sei = {};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"open";
        sei.lpFile = appOverride.c_str();
        sei.lpParameters = params.c_str();
        sei.nShow = SW_SHOWNORMAL;
        if (ShellExecuteExW(&sei))
        {
            unsigned long pid = 0;
            if (sei.hProcess)
            {
                pid = GetProcessId(sei.hProcess);
                CloseHandle(sei.hProcess);
            }
            return pid;
        }
        // Chosen app is gone (moved / uninstalled): fall through to the
        // default program, which is better than showing an error.
    }

    std::wstring ext = ToLowerW(filePath.extension().wstring());

    std::wstring command, progId;

    // 1) Prefer the backup made at install time.
    HKEY hK = nullptr;
    std::wstring key = L"Software\\EchoVault\\OpenInterception\\" + ext;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &hK) == ERROR_SUCCESS)
    {
        wchar_t buf[4096] = L"";
        DWORD sz = sizeof(buf);
        if (RegQueryValueExW(hK, L"Command", nullptr, nullptr,
                reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS)
            command = buf;
        sz = sizeof(buf);
        if (RegQueryValueExW(hK, L"ProgID", nullptr, nullptr,
                reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS)
            progId = buf;
        RegCloseKey(hK);
    }

    // 2) Fall back to whatever is registered (never EchoVaultOpen).
    if (command.empty())
    {
        if (!FindOriginalHandler(ext, progId, command) || command.empty())
        {
            // SHOpenWithDialog is modal. OAIF_EXEC waits for the user's
            // selection before starting that app, so EchoVault's later
            // "save, close, then lock" dialog cannot race ahead of it.
            OPENASINFO info = {};
            info.pcszFile = filePath.c_str();
            info.pcszClass = nullptr;
            info.oaifInFlags = OAIF_EXEC;
            if (SUCCEEDED(SHOpenWithDialog(nullptr, &info)))
                return 1; // launched, but Windows does not expose a useful PID
            ShowError(L"EchoVault",
                L"No application was selected. The file remains unlocked until "
                L"you confirm re-locking.");
            return 0;
        }
    }

    // Guard: never let EchoVault launch itself.
    std::wstring lowerCmd = ToLowerW(command);
    if (lowerCmd.find(L"echovaultopen") != std::wstring::npos ||
        lowerCmd.find(L"echovault.exe") != std::wstring::npos)
    {
        ShowError(L"EchoVault",
            L"Could not resolve the original program for this file.");
        return 0;
    }

    std::wstring cmdLine = SubstituteArgs(command, filePath.wstring());

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    std::wstring workDir = filePath.parent_path().wstring();
    std::wstring finalCmd = cmdLine;

    if (!CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, FALSE, 0,
            nullptr, workDir.empty() ? nullptr : workDir.c_str(), &si, &pi))
    {
        // CreateProcessW cannot start batch files at all (the shell runs
        // them via the command interpreter). If the stored handler is the
        // file itself ("%1" %* — the normal .bat/.cmd command), retry the
        // way Explorer does: cmd.exe /c ""file"".
        std::wstring extL = ToLowerW(filePath.extension().wstring());
        if (extL == L".bat" || extL == L".cmd")
        {
            finalCmd = L"cmd.exe /c \"\"" + filePath.wstring() + L"\"\"";
            if (!CreateProcessW(nullptr, &finalCmd[0], nullptr, nullptr, FALSE, 0,
                    nullptr, workDir.empty() ? nullptr : workDir.c_str(), &si, &pi))
            {
                ShowError(L"EchoVault",
                    (L"Failed to start this batch file:\n" +
                     filePath.wstring() + L"\n\nCommand:\n" + finalCmd).c_str());
                return 0;
            }
        }
        else
        {
            ShowError(L"EchoVault",
                (L"Failed to start the default program for:\n" +
                 filePath.wstring() + L"\n\nCommand:\n" + cmdLine).c_str());
            return 0;
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pi.dwProcessId;
}
