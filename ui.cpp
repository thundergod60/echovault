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

        MakeChild(hwnd, L"BUTTON", L"Exit",
                  BS_PUSHBUTTON | WS_TABSTOP, 0,
                  60, 214, 200, 32,  IDC_MENU_EXIT);
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
    RECT rc = { 0, 0, 320, 280 };
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
            RegSetValueExW(hKey, valName, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(valData.c_str()),
                static_cast<DWORD>((valData.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);
            return true;
        }
        return false;
    };

    // Add for all files (*)
    writeReg(L"Software\\Classes\\*\\shell\\EchoVault", nullptr, L"EchoVault (Lock/Unlock)");
    writeReg(L"Software\\Classes\\*\\shell\\EchoVault\\command", nullptr, commandStr);

    // Add for directories
    writeReg(L"Software\\Classes\\Directory\\shell\\EchoVault", nullptr, L"EchoVault (Lock/Unlock)");
    writeReg(L"Software\\Classes\\Directory\\shell\\EchoVault\\command", nullptr, commandStr);

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
// Open interception \u2014 auto-unlock on double-click
//
// Encrypted files keep their original extension, so double-clicking one
// would normally open the raw ciphertext in the associated program. To
// make EchoVault intercept that open, we register EchoVault as the
// default handler for a set of common extensions and remember what the
// original handler was. When EchoVault is then invoked with
// "--open <file>" it either unlocks the file (password prompt, decrypt
// in place, open) or passes plain files straight through to the original
// program. This gives the end-user behaviour of a minifilter driver
// without needing a signed kernel driver.
//====================================================================

static const wchar_t* kInterceptExts[] = {
    // Documents & text
    L".txt", L".md", L".log", L".ini", L".cfg", L".conf",
    L".csv", L".tsv", L".json", L".xml", L".yaml", L".yml", L".rtf",
    L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx", L".pdf",
    // Code & scripts
    L".py", L".pyw", L".ipynb", L".cpp", L".c", L".h", L".hpp", L".cc",
    L".cs", L".java", L".kt", L".swift", L".go", L".rs", L".rb", L".php",
    L".js", L".mjs", L".cjs", L".jsx", L".ts", L".tsx", L".html", L".htm",
    L".css", L".scss", L".sql", L".lua", L".pl", L".r", L".sh", L".bat",
    L".cmd", L".ps1", L".vbs", L".ahk",
    // Accessibility / audio-game scripting
    L".bgt", L".nvgt", L".sbl",
    // Images
    L".png", L".jpg", L".jpeg", L".gif", L".bmp", L".tiff", L".svg", L".webp",
    // Audio / video
    L".mp3", L".wav", L".m4a", L".ogg", L".flac",
    L".mp4", L".mkv", L".avi", L".mov", L".wmv", L".webm",
};
static const size_t kInterceptExtCount =
    sizeof(kInterceptExts) / sizeof(kInterceptExts[0]);

static std::wstring ToLowerW(std::wstring s)
{
    for (auto& c : s)
        if (c >= L'A' && c <= L'Z')
            c += (L'a' - L'A');
    return s;
}

static std::wstring GetExePath()
{
    wchar_t buf[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, buf, MAX_PATH)) return L"";
    return buf;
}

// ------------------------------------------------------------------
// The interception list is user-extensible: any extra extensions listed
// in %LOCALAPPDATA%\EchoVault\intercept-extensions.txt (one per line,
// "#" for comments) are added to the built-in list. Use the CLI verbs
// --add-ext <ext> / --remove-ext <ext> to manage it.
// ------------------------------------------------------------------

static std::filesystem::path GetInterceptExtsFile()
{
    wchar_t buf[MAX_PATH];
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH) == 0)
        return {};
    std::filesystem::path dir = std::filesystem::path(buf) / L"EchoVault";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir / L"intercept-extensions.txt";
}

static std::vector<std::wstring> LoadUserExts()
{
    std::vector<std::wstring> out;
    std::ifstream f(GetInterceptExtsFile());
    if (!f) return out;
    std::string line;
    while (std::getline(f, line))
    {
        size_t b = line.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) continue;
        size_t e = line.find_last_not_of(" \t\r\n");
        std::string s = line.substr(b, e - b + 1);
        if (s.empty() || s[0] == '#') continue;
        std::wstring w;
        for (char c : s) w += (wchar_t)(unsigned char)c;
        if (w.empty()) continue;
        if (w[0] != L'.') w = L"." + w;
        w = ToLowerW(w);
        bool dup = false;
        for (auto& x : out) if (x == w) { dup = true; break; }
        if (!dup) out.push_back(w);
    }
    return out;
}

static std::vector<std::wstring> AllInterceptExts()
{
    std::vector<std::wstring> v;
    for (size_t i = 0; i < kInterceptExtCount; i++)
        v.push_back(ToLowerW(kInterceptExts[i]));
    auto user = LoadUserExts();
    for (auto& u : user)
    {
        bool dup = false;
        for (auto& x : v) if (x == u) { dup = true; break; }
        if (!dup) v.push_back(u);
    }
    return v;
}

bool AddOpenInterceptionExt(const std::wstring& extIn)
{
    std::wstring ext = extIn;
    if (ext.empty()) return false;
    if (ext[0] != L'.') ext = L"." + ext;
    ext = ToLowerW(ext);

    auto exts = LoadUserExts();
    bool found = false;
    for (auto& x : exts) if (x == ext) { found = true; break; }
    if (!found) exts.push_back(ext);

    std::ofstream f(GetInterceptExtsFile(), std::ios::trunc);
    if (!f) return false;
    for (auto& x : exts)
        f << std::string(x.begin(), x.end()) << "\n";
    f.close();

    // Re-apply so the new extension is intercepted immediately.
    return InstallOpenInterception();
}

bool RemoveOpenInterceptionExt(const std::wstring& extIn)
{
    std::wstring ext = extIn;
    if (ext.empty()) return false;
    if (ext[0] != L'.') ext = L"." + ext;
    ext = ToLowerW(ext);

    auto exts = LoadUserExts();
    auto it = exts.begin();
    while (it != exts.end())
    {
        if (*it == ext) it = exts.erase(it);
        else ++it;
    }

    std::ofstream f(GetInterceptExtsFile(), std::ios::trunc);
    if (!f) return false;
    for (auto& x : exts)
        f << std::string(x.begin(), x.end()) << "\n";
    f.close();

    return InstallOpenInterception();
}

// Windows' "UserChoice" key (set when a user picks an app via
// Open With / Settings) OVERRIDES the extension's default ProgID.
// Delete it so our mapping actually wins for double-clicks.
// Returns true only if a UserChoice key was actually removed — callers
// rely on this to avoid notifying the shell about changes that didn't
// happen (which would otherwise loop back into this watcher).
//
// A RegDeleteTreeW on a NONEXISTENT key is surprisingly expensive
// (~1 ms each), and this is called for every registered extension every
// second — so probe existence first and only delete when something is
// actually there. That makes the steady-state sweep (no UserChoice
// present) nearly free.
static bool DeleteUserChoiceForExt(const std::wstring& ext)
{
    std::wstring ucKey =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\" +
        ext + L"\\UserChoice";

    HKEY hProbe = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, ucKey.c_str(), 0, KEY_READ, &hProbe) != ERROR_SUCCESS)
        return false;   // no UserChoice — fast path, nothing to do
    RegCloseKey(hProbe);

    return RegDeleteTreeW(HKEY_CURRENT_USER, ucKey.c_str()) == ERROR_SUCCESS;
}

// ------------------------------------------------------------------
// Background association watcher
// ------------------------------------------------------------------
// When the user picks another program via "Open with", Windows writes a
// UserChoice key that OVERRIDES the extension's default handler — so the
// next double-click would go straight to that program, past EchoVault.
// This watcher runs as a hidden-window process (no polling loop burning
// CPU: it blocks on a message queue and wakes only on shell
// association-change notifications, plus a low-frequency safety sweep)
// and re-deletes those overrides for every extension we have taken over.
// ------------------------------------------------------------------

#define WM_ASSOC_CHANGED (WM_APP + 1)

static const wchar_t* kWatcherMutexName = L"EchoVaultAssocWatcher";
static const wchar_t* kWatcherStopEvent = L"EchoVaultAssocWatcherStop";
static const wchar_t* kWatcherRunValue  = L"EchoVaultAssocWatcher";
static const UINT_PTR kSweepTimerId     = 1;
// 30 s: the real triggers are event-driven (a shell notification when an
// association changes + a registry notification when FileExts changes), so
// this timer is only a rare safety net for events we miss. It must NOT be
// short: every sweep touches a UserChoice path per registered extension,
// and those accesses are expensive (~0.5 ms each) because Windows
// Defender's tamper protection hooks them.
static const UINT      kSweepIntervalMs = 30000;

static std::wstring GetWatcherRunCommand()
{
    std::wstring cmd;
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_READ, &h) == ERROR_SUCCESS)
    {
        wchar_t buf[1024] = L"";
        DWORD sz = sizeof(buf), type = 0;
        if (RegQueryValueExW(h, kWatcherRunValue, nullptr, &type,
                reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS && sz > sizeof(wchar_t))
            cmd = buf;
        RegCloseKey(h);
    }
    return cmd;
}

// Re-asserts EchoVault's ownership of every intercepted extension by
// deleting Windows' UserChoice override (the key "Open with" writes,
// which would otherwise send the next double-click straight to the
// chosen app, past EchoVault). Also called on every --open so the
// mapping self-heals even if the watcher is not running. Returns true
// if any override was removed.
void ReassertInterception()
{
    HKEY hBase = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\EchoVault\\OpenInterception",
            0, KEY_READ, &hBase) != ERROR_SUCCESS)
        return;

    bool changed = false;
    wchar_t name[128];
    DWORD nsz = 128;
    for (DWORD i = 0;
         RegEnumKeyExW(hBase, i, name, &nsz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
         i++)
    {
        std::wstring ext = name;
        if (!ext.empty() && ext[0] == L'.')
        {
            if (DeleteUserChoiceForExt(ext))
                changed = true;
        }
        nsz = 128;
    }
    RegCloseKey(hBase);

    if (changed)
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
}

// Re-asserts and reports whether the watcher should keep running.
// Returns false when the watcher should exit (interception uninstalled,
// or the exe was moved/reinstalled).
static bool SweepAssociationOverrides()
{
    if (!IsOpenInterceptionInstalled())
        return false;

    // Stale watcher (exe moved / reinstalled elsewhere): the new install
    // starts its own. Exit quietly.
    std::wstring runCmd = GetWatcherRunCommand();
    if (!runCmd.empty() && runCmd.find(GetExePath()) == std::wstring::npos)
        return false;

    ReassertInterception();
    return true;
}

// Coalesces the event-driven sweeps: the shell notification, the registry
// notification and our own "fixed it" notification can fire within the same
// second, and the sweep is not cheap, so run it at most once per second.
static ULONGLONG g_LastSweepMs = 0;

static LRESULT CALLBACK WatcherWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_ASSOC_CHANGED || msg == WM_TIMER)
    {
        ULONGLONG now = GetTickCount64();
        if (now - g_LastSweepMs >= 1000)
        {
            g_LastSweepMs = now;
            if (!SweepAssociationOverrides())
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        return 0;
    }
    if (msg == WM_CLOSE) { DestroyWindow(hwnd); return 0; }
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int RunAssocWatcher()
{
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, kWatcherMutexName);
    if (!hMutex) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(hMutex);
        return 0;   // another watcher is already running
    }

    HANDLE hStop = CreateEventW(nullptr, TRUE, FALSE, kWatcherStopEvent);
    if (!hStop) { ReleaseMutex(hMutex); CloseHandle(hMutex); return 1; }
    ResetEvent(hStop);   // clear a stale signal from a previous uninstall

    HINSTANCE hInst = GetModuleHandle(nullptr);
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WatcherWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"EchoVaultAssocWatcherWnd";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"", 0,
        0, 0, 0, 0, HWND_MESSAGE, nullptr, hInst, nullptr);

    ULONG notifyReg = 0;
    if (hwnd)
    {
        SHChangeNotifyEntry ent = { nullptr, TRUE };
        notifyReg = SHChangeNotifyRegister(hwnd, SHCNRF_ShellLevel,
            SHCNE_ASSOCCHANGED, WM_ASSOC_CHANGED, 1, &ent);
    }

    if (!hwnd)
    {
        // Hidden window failed (extremely unlikely): fall back to polling.
        for (;;)
        {
            if (WaitForSingleObject(hStop, kSweepIntervalMs) == WAIT_OBJECT_0)
                break;
            if (!SweepAssociationOverrides())
                break;
        }
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        CloseHandle(hStop);
        return 0;
    }

    // Direct registry trigger: wake the moment anything under FileExts
    // changes (e.g. Explorer writes a UserChoice for "Open with"). This is
    // the primary signal; the shell notification above is a second one;
    // the (now rare) timer below is only a safety net. Keeping the process
    // event-driven instead of polling every second matters: a full sweep
    // touches every registered extension's UserChoice path, and those
    // accesses are slow because Defender's tamper protection hooks them.
    HANDLE hNotifyEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    HKEY hFileExts = nullptr;
    RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts",
        0, KEY_NOTIFY, &hFileExts);

    auto ArmRegNotify = [&]() {
        if (hFileExts && hNotifyEvent)
            RegNotifyChangeKeyValue(hFileExts, TRUE,
                REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
                hNotifyEvent, TRUE);
    };

    // Fix any override created while the watcher was down, then wait.
    if (!SweepAssociationOverrides())
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    ArmRegNotify();
    SetTimer(hwnd, kSweepTimerId, kSweepIntervalMs, nullptr);

    HANDLE waitObjs[2] = { hStop, hNotifyEvent ? hNotifyEvent : hStop };
    MSG msg;
    for (;;)
    {
        DWORD r = MsgWaitForMultipleObjectsEx(2, waitObjs, INFINITE,
            QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        if (r == WAIT_OBJECT_0)
            break;   // stop event signalled (uninstall)
        if (r == WAIT_OBJECT_0 + 1)
        {
            // FileExts changed — re-arm and run a (throttled) sweep.
            ArmRegNotify();
            PostMessageW(hwnd, WM_ASSOC_CHANGED, 0, 0);
            continue;
        }
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT)
            {
                ReleaseMutex(hMutex);
                CloseHandle(hMutex);
                CloseHandle(hStop);
                if (hNotifyEvent) CloseHandle(hNotifyEvent);
                if (hFileExts) RegCloseKey(hFileExts);
                return 0;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if (notifyReg)
        SHChangeNotifyDeregister(notifyReg);
    KillTimer(hwnd, kSweepTimerId);
    DestroyWindow(hwnd);
    if (hNotifyEvent) CloseHandle(hNotifyEvent);
    if (hFileExts) RegCloseKey(hFileExts);
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    CloseHandle(hStop);
    return 0;
}

void StopAssocWatcher()
{
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, kWatcherStopEvent);
    if (h)
    {
        SetEvent(h);
        CloseHandle(h);
    }
}

bool StartAssocWatcher()
{
    // Already running?
    HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, kWatcherMutexName);
    if (hMutex)
    {
        CloseHandle(hMutex);
        return true;
    }

    std::wstring exe = GetExePath();
    if (exe.empty()) return false;
    std::wstring cmd = L"\"" + exe + L"\" --watch";
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
    return false;
}

// ------------------------------------------------------------------
// Task Scheduler self-heal for the watcher.
//
// The watcher reverts "Open with" overrides. It starts at logon via the
// Run key, but if it is ever killed or crashes, nothing would restart
// it until the next logon — and in the meantime double-clicks could
// bypass EchoVault. So we also register a scheduled task that (a) fires
// at logon, (b) repeats every 5 minutes for the whole session (reviving
// the watcher within minutes if it ever dies) and (c) restarts it on
// failure. The watcher's own mutex makes relaunches free: a second
// instance exits instantly when one is already running.
// ------------------------------------------------------------------

static std::wstring XmlEscape(const std::wstring& s)
{
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s)
    {
        switch (c)
        {
            case L'&':  out += L"&amp;";  break;
            case L'<':  out += L"&lt;";   break;
            case L'>':  out += L"&gt;";   break;
            case L'"':  out += L"&quot;"; break;
            default:    out += c;          break;
        }
    }
    return out;
}

static std::wstring BuildTaskXml(const wchar_t* taskName,
                                 const wchar_t* description,
                                 const wchar_t* args)
{
    std::wstring userId;
    {
        wchar_t dom[256] = L"", usr[256] = L"";
        DWORD dn = 256, un = 256;
        if (GetEnvironmentVariableW(L"USERDOMAIN", dom, dn) &&
            GetEnvironmentVariableW(L"USERNAME", usr, un) && usr[0])
        {
            userId = dom;
            userId += L"\\";
            userId += usr;
        }
    }

    (void)taskName;   // the task name is the registration path

    std::wstring xml;
    xml += L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n";
    xml += L"<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n";
    xml += L"  <RegistrationInfo>\n";
    xml += L"    <Author>EchoVault</Author>\n";
    xml += L"    <Description>";
    xml += description;
    xml += L"</Description>\n";
    xml += L"  </RegistrationInfo>\n";
    xml += L"  <Triggers>\n";
    xml += L"    <LogonTrigger>\n";
    xml += L"      <Enabled>true</Enabled>\n";
    if (!userId.empty())
        xml += L"      <UserId>" + XmlEscape(userId) + L"</UserId>\n";
    xml += L"    </LogonTrigger>\n";
    xml += L"    <TimeTrigger>\n";
    xml += L"      <StartBoundary>2020-01-01T00:00:00</StartBoundary>\n";
    xml += L"      <Enabled>true</Enabled>\n";
    xml += L"      <Repetition>\n";
    // 1-minute refire: the task is the recovery net for a killed
    // watcher/guard (user-mode processes can be killed; the kernel
    // driver cannot). Each firing exits instantly when the process is
    // already running (mutex), so this costs almost nothing and bounds
    // the dead window to about a minute.
    xml += L"        <Interval>PT1M</Interval>\n";
    xml += L"        <Duration>P3650D</Duration>\n";
    xml += L"        <StopAtDurationEnd>false</StopAtDurationEnd>\n";
    xml += L"      </Repetition>\n";
    xml += L"    </TimeTrigger>\n";
    xml += L"  </Triggers>\n";
    xml += L"  <Principals>\n";
    xml += L"    <Principal id=\"Author\">\n";
    xml += L"      <LogonType>InteractiveToken</LogonType>\n";
    xml += L"      <RunLevel>LeastPrivilege</RunLevel>\n";
    xml += L"    </Principal>\n";
    xml += L"  </Principals>\n";
    xml += L"  <Settings>\n";
    xml += L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n";
    xml += L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n";
    xml += L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n";
    xml += L"    <AllowHardTerminate>true</AllowHardTerminate>\n";
    xml += L"    <StartWhenAvailable>true</StartWhenAvailable>\n";
    xml += L"    <AllowStartOnDemand>true</AllowStartOnDemand>\n";
    xml += L"    <Enabled>true</Enabled>\n";
    xml += L"    <Hidden>true</Hidden>\n";
    xml += L"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n";
    xml += L"    <WakeToRun>false</WakeToRun>\n";
    xml += L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n";
    xml += L"    <Priority>7</Priority>\n";
    xml += L"    <RestartOnFailure>\n";
    xml += L"      <Interval>PT1M</Interval>\n";
    xml += L"      <Count>3</Count>\n";
    xml += L"    </RestartOnFailure>\n";
    xml += L"  </Settings>\n";
    xml += L"  <Actions Context=\"Author\">\n";
    xml += L"    <Exec>\n";
    xml += L"      <Command>\"" + XmlEscape(GetExePath()) + L"\"</Command>\n";
    xml += L"      <Arguments>";
    xml += args;
    xml += L"</Arguments>\n";
    xml += L"    </Exec>\n";
    xml += L"  </Actions>\n";
    xml += L"</Task>\n";
    return xml;
}

static bool RegisterTaskByName(const wchar_t* taskName,
                               const wchar_t* description,
                               const wchar_t* args);

static bool RegisterWatcherTask()
{
    // The watcher task revives the association watcher; the guard task
    // revives the password-prompt service when the minifilter is loaded.
    bool ok = RegisterTaskByName(L"EchoVaultWatcher",
        L"Keeps EchoVault's open interception active: runs the association watcher and revives it if it ever stops.",
        L"--watch");
    RegisterTaskByName(L"EchoVaultGuard",
        L"EchoVault password-prompt service: listens for denied opens of encrypted files (requires the EchoVault minifilter) and revives itself if it ever stops.",
        L"--guard");
    return ok;
}

static bool RegisterTaskByName(const wchar_t* taskName,
                               const wchar_t* description,
                               const wchar_t* args)
{
    std::wstring xml = BuildTaskXml(taskName, description, args);
    bool ok = false;
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
                    BSTR xmlB = SysAllocString(xml.c_str());
                    ITaskDefinition* pDef = nullptr;
                    IRegisteredTask* pTask = nullptr;
                    if (name && xmlB &&
                        SUCCEEDED(pSvc->NewTask(0, &pDef)) &&
                        SUCCEEDED(pDef->put_XmlText(xmlB)) &&
                        SUCCEEDED(pRoot->RegisterTaskDefinition(name, pDef,
                            TASK_CREATE_OR_UPDATE, VARIANT(), VARIANT(),
                            TASK_LOGON_INTERACTIVE_TOKEN, VARIANT(), &pTask)))
                    {
                        ok = true;
                    }
                    if (pTask) pTask->Release();
                    if (pDef) pDef->Release();
                    if (name) SysFreeString(name);
                    if (xmlB) SysFreeString(xmlB);
                    pRoot->Release();
                }
                if (rootPath) SysFreeString(rootPath);
            }
            pSvc->Release();
        }
    }
    if (SUCCEEDED(hr)) CoUninitialize();
    return ok;
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

static void RemoveWatcherTask()
{
    RemoveTaskByName(L"EchoVaultWatcher");
    RemoveTaskByName(L"EchoVaultGuard");
}

// Installs / removes the logon auto-start entry for the watcher, plus
// the self-healing scheduled task (see above).
static void SetWatcherAutoStart(bool enable)
{
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &h) == ERROR_SUCCESS)
    {
        if (enable)
        {
            std::wstring cmd = L"\"" + GetExePath() + L"\" --watch";
            RegSetValueExW(h, kWatcherRunValue, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(cmd.c_str()),
                static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t)));
        }
        else
        {
            RegDeleteValueW(h, kWatcherRunValue);
        }
        RegCloseKey(h);
    }

    if (enable)
        RegisterWatcherTask();
    else
        RemoveWatcherTask();
}

// Takes over interception for a single extension, backing up whatever
// was there before. Used when a file is encrypted so ANY file type is
// covered immediately (even ones not in the static list).
static bool FindOriginalHandler(
    const std::wstring& ext, std::wstring& outProgId, std::wstring& outCommand);

void EnsureExtensionIntercepted(const std::wstring& extIn)
{
    std::wstring ext = extIn;
    if (ext.empty() || ext[0] != L'.') return;
    ext = ToLowerW(ext);

    // First encryption anywhere: install the full interception set.
    if (!IsOpenInterceptionInstalled())
        InstallOpenInterception();

    // Already covered (installed list or a previous per-file takeover)?
    std::wstring bkKey = L"Software\\EchoVault\\OpenInterception\\" + ext;
    HKEY hBk = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, bkKey.c_str(), 0, KEY_READ, &hBk) == ERROR_SUCCESS)
    {
        RegCloseKey(hBk);
        return;
    }

    // Take over this specific extension now.
    std::wstring progId, command;
    FindOriginalHandler(ext, progId, command);

    HKEY hExt = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, bkKey.c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hExt, nullptr) == ERROR_SUCCESS)
    {
        if (!progId.empty())
            RegSetValueExW(hExt, L"ProgID", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(progId.c_str()),
                static_cast<DWORD>((progId.size() + 1) * sizeof(wchar_t)));
        if (!command.empty())
            RegSetValueExW(hExt, L"Command", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(command.c_str()),
                static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hExt);
    }

    std::wstring clsKey = L"Software\\Classes\\" + ext;
    HKEY hCls = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, clsKey.c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hCls, nullptr) == ERROR_SUCCESS)
    {
        RegSetValueExW(hCls, nullptr, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(L"EchoVaultOpen"),
            static_cast<DWORD>((wcslen(L"EchoVaultOpen") + 1) * sizeof(wchar_t)));
        RegCloseKey(hCls);
    }

    std::wstring owpKey = clsKey + L"\\OpenWithProgids";
    HKEY hOwp = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, owpKey.c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hOwp, nullptr) == ERROR_SUCCESS)
    {
        RegSetValueExW(hOwp, L"EchoVaultOpen", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(L""), 2);
        RegCloseKey(hOwp);
    }

    DeleteUserChoiceForExt(ext);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);

    // Make sure the background watcher is defending this (and every)
    // extension against future "Open with" overrides.
    StartAssocWatcher();
}

// Returns the ProgID and shell\open\command registered for an extension,
// skipping EchoVault's own ProgID so we always find the "real" handler.
static bool FindOriginalHandler(
    const std::wstring& ext,
    std::wstring& outProgId,
    std::wstring& outCommand)
{
    outProgId.clear();
    outCommand.clear();

    // 1) Default ProgID of the extension
    HKEY hK = nullptr;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, ext.c_str(), 0, KEY_READ, &hK) == ERROR_SUCCESS)
    {
        wchar_t buf[1024] = L"";
        DWORD sz = sizeof(buf), type = 0;
        if (RegQueryValueExW(hK, nullptr, nullptr, &type,
                reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS && sz > sizeof(wchar_t))
            outProgId = buf;
        RegCloseKey(hK);
    }

    // 2) Fall back to the first OpenWithProgids entry
    if (outProgId.empty())
    {
        std::wstring sub = ext + L"\\OpenWithProgids";
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, sub.c_str(), 0, KEY_READ, &hK) == ERROR_SUCCESS)
        {
            wchar_t name[256];
            DWORD nsz = 256;
            for (DWORD i = 0;
                 RegEnumValueW(hK, i, name, &nsz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
                 i++)
            {
                if (lstrcmpiW(name, L"EchoVaultOpen") != 0) { outProgId = name; break; }
                nsz = 256;
            }
            RegCloseKey(hK);
        }
    }

    // 2b) Fall back to the user's explicit "Open with" choice, if any.
    //     (Extensions that were only ever opened via "Open with" have no
    //     HKCR default at all - only a UserChoice entry.)
    if (outProgId.empty())
    {
        std::wstring sub = L"Software\\Microsoft\\Windows\\CurrentVersion\\"
                           L"Explorer\\FileExts\\" + ext + L"\\UserChoice";
        if (RegOpenKeyExW(HKEY_CURRENT_USER, sub.c_str(), 0, KEY_READ, &hK) == ERROR_SUCCESS)
        {
            wchar_t buf[1024] = L"";
            DWORD sz = sizeof(buf), type = 0;
            if (RegQueryValueExW(hK, L"ProgId", nullptr, &type,
                    reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS && sz > sizeof(wchar_t))
                outProgId = buf;
            RegCloseKey(hK);
        }
    }

    if (lstrcmpiW(outProgId.c_str(), L"EchoVaultOpen") == 0)
        outProgId.clear();
    if (outProgId.empty())
        return false;

    // 3) shell\open\command of the ProgID
    // (Paths here are relative to HKEY_CLASSES_ROOT, which is the
    // merged Software\Classes view - NOT prefixed with Software\Classes.)
    std::wstring cmdKey = outProgId + L"\\shell\\open\\command";
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, cmdKey.c_str(), 0, KEY_READ, &hK) == ERROR_SUCCESS)
    {
        wchar_t buf[4096] = L"";
        DWORD sz = sizeof(buf), type = 0;
        if (RegQueryValueExW(hK, nullptr, nullptr, &type,
                reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS && sz > sizeof(wchar_t))
            outCommand = buf;
        RegCloseKey(hK);
    }

    return !outCommand.empty();
}

bool IsOpenInterceptionInstalled()
{
    HKEY hK = nullptr;
    LONG r = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\EchoVault\\OpenInterception", 0, KEY_READ, &hK);
    if (r == ERROR_SUCCESS) RegCloseKey(hK);
    return r == ERROR_SUCCESS;
}

bool UninstallOpenInterception()
{
    // Delete our ProgID entirely
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\EchoVaultOpen");

    // --- Special case: the "*" (All Files) handler. ---
    // (The generic loop below skips it because we never set a default
    // value on the "*" key itself.)
    {
        std::wstring backupCmd;
        HKEY hExt = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                L"Software\\EchoVault\\OpenInterception\\*",
                0, KEY_READ, &hExt) == ERROR_SUCCESS)
        {
            wchar_t buf[4096] = L"";
            DWORD sz = sizeof(buf), type = 0;
            if (RegQueryValueExW(hExt, L"Command", nullptr, &type,
                    reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS)
                backupCmd = buf;
            RegCloseKey(hExt);
        }

        // Only remove the override if it is still ours.
        std::wstring cur;
        HKEY hCur = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                L"Software\\Classes\\*\\shell\\open\\command",
                0, KEY_READ, &hCur) == ERROR_SUCCESS)
        {
            wchar_t buf[4096] = L"";
            DWORD sz = sizeof(buf), type = 0;
            if (RegQueryValueExW(hCur, nullptr, nullptr, &type,
                    reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS)
                cur = buf;
            RegCloseKey(hCur);
        }

        if (cur.find(L"--open") != std::wstring::npos)
        {
            RegDeleteTreeW(HKEY_CURRENT_USER,
                L"Software\\Classes\\*\\shell\\open");
            if (!backupCmd.empty())
            {
                HKEY hCmd = nullptr;
                if (RegCreateKeyExW(HKEY_CURRENT_USER,
                        L"Software\\Classes\\*\\shell\\open\\command",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE,
                        nullptr, &hCmd, nullptr) == ERROR_SUCCESS)
                {
                    RegSetValueExW(hCmd, nullptr, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(backupCmd.c_str()),
                        static_cast<DWORD>((backupCmd.size() + 1) * sizeof(wchar_t)));
                    RegCloseKey(hCmd);
                }
            }
        }
    }

    // Restore every extension we took over
    HKEY hBase = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\EchoVault\\OpenInterception",
            0, KEY_READ, &hBase) == ERROR_SUCCESS)
    {
        wchar_t name[128];
        DWORD nsz = 128;
        for (DWORD i = 0;
             RegEnumKeyExW(hBase, i, name, &nsz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
             i++)
        {
            std::wstring ext = name;

            // Backup ProgID we saved at install time
            std::wstring backupProgId;
            HKEY hExt = nullptr;
            std::wstring key = std::wstring(L"Software\\EchoVault\\OpenInterception\\") + ext;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &hExt) == ERROR_SUCCESS)
            {
                wchar_t buf[1024] = L"";
                DWORD sz = sizeof(buf), type = 0;
                if (RegQueryValueExW(hExt, L"ProgID", nullptr, &type,
                        reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS)
                    backupProgId = buf;
                RegCloseKey(hExt);
            }

            // Only touch the extension if we still own it
            std::wstring clsKey = L"Software\\Classes\\" + ext;
            std::wstring curDefault;
            HKEY hCur = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, clsKey.c_str(), 0, KEY_READ, &hCur) == ERROR_SUCCESS)
            {
                wchar_t buf[128] = L"";
                DWORD sz = sizeof(buf), type = 0;
                if (RegQueryValueExW(hCur, nullptr, nullptr, &type,
                        reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS)
                    curDefault = buf;
                RegCloseKey(hCur);
            }

            if (lstrcmpiW(curDefault.c_str(), L"EchoVaultOpen") == 0)
            {
                RegDeleteTreeW(HKEY_CURRENT_USER, clsKey.c_str());
                if (!backupProgId.empty())
                {
                    HKEY hCls = nullptr;
                    if (RegCreateKeyExW(HKEY_CURRENT_USER, clsKey.c_str(), 0, nullptr,
                            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hCls, nullptr) == ERROR_SUCCESS)
                    {
                        RegSetValueExW(hCls, nullptr, 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(backupProgId.c_str()),
                            static_cast<DWORD>((backupProgId.size() + 1) * sizeof(wchar_t)));
                        RegCloseKey(hCls);
                    }
                }
            }
            // else: the user changed the association themselves after install
            //       \u2014 leave their choice alone.

            nsz = 128;
        }
        RegCloseKey(hBase);
    }

    // Remove all of our bookkeeping
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\EchoVault\\OpenInterception");

    // Stop the background watcher and its logon auto-start entry.
    SetWatcherAutoStart(false);
    StopAssocWatcher();

    // Tell the shell to re-read associations right away.
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);

    return true;
}

bool InstallOpenInterception()
{
    std::wstring exe = GetExePath();
    if (exe.empty()) return false;

    // Start from a clean slate so the backups stay consistent
    UninstallOpenInterception();

    std::wstring handlerCmd = L"\"" + exe + L"\" --open \"%1\"";

    HKEY hBase = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\EchoVault\\OpenInterception",
            0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE,
            nullptr, &hBase, nullptr) != ERROR_SUCCESS)
        return false;

    int done = 0;

    auto exts = AllInterceptExts();
    for (auto& ext : exts)
    {
        std::wstring progId, command;
        if (!FindOriginalHandler(ext, progId, command))
            continue;

        // --- Back up the original handler ---
        HKEY hExt = nullptr;
        std::wstring key = L"Software\\EchoVault\\OpenInterception\\" + ext;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hExt, nullptr) != ERROR_SUCCESS)
            continue;
        RegSetValueExW(hExt, L"ProgID", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(progId.c_str()),
            static_cast<DWORD>((progId.size() + 1) * sizeof(wchar_t)));
        RegSetValueExW(hExt, L"Command", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(command.c_str()),
            static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));

        // Also remember the user's explicit "Open with" choice so uninstall
        // can put things back as close as possible.
        {
            std::wstring ucPath =
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
                L"FileExts\\" + ext + L"\\UserChoice";
            std::wstring ucProgId;
            HKEY hUc = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, ucPath.c_str(), 0, KEY_READ, &hUc) == ERROR_SUCCESS)
            {
                wchar_t buf[1024] = L"";
                DWORD sz = sizeof(buf), type = 0;
                if (RegQueryValueExW(hUc, L"ProgId", nullptr, &type,
                        reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS && sz > sizeof(wchar_t))
                    ucProgId = buf;
                RegCloseKey(hUc);
            }
            if (!ucProgId.empty())
                RegSetValueExW(hExt, L"UserChoice", 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(ucProgId.c_str()),
                    static_cast<DWORD>((ucProgId.size() + 1) * sizeof(wchar_t)));
        }
        RegCloseKey(hExt);

        // --- Make EchoVault the default handler ---
        std::wstring clsKey = L"Software\\Classes\\" + ext;
        HKEY hCls = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, clsKey.c_str(), 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hCls, nullptr) == ERROR_SUCCESS)
        {
            std::wstring prog = L"EchoVaultOpen";
            RegSetValueExW(hCls, nullptr, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(prog.c_str()),
                static_cast<DWORD>((prog.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hCls);
        }

        std::wstring owpKey = clsKey + L"\\OpenWithProgids";
        HKEY hOwp = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, owpKey.c_str(), 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hOwp, nullptr) == ERROR_SUCCESS)
        {
            std::wstring prog = L"EchoVaultOpen";
            RegSetValueExW(hOwp, prog.c_str(), 0, REG_SZ,
                reinterpret_cast<const BYTE*>(L""), 2);
            RegCloseKey(hOwp);
        }

        // UserChoice overrides the default ProgID above - remove it so our
        // mapping is authoritative and double-clicks actually reach us.
        DeleteUserChoiceForExt(ext);

        done++;
    }

    // --- All Files (*) fallback: catches every extension that has no
    // specific registered handler (e.g. many code files) so "any file"
    // is intercepted. ---
    {
        std::wstring starCmd;
        HKEY hK = nullptr;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"*\\shell\\open\\command",
                0, KEY_READ, &hK) == ERROR_SUCCESS)
        {
            wchar_t buf[4096] = L"";
            DWORD sz = sizeof(buf), type = 0;
            if (RegQueryValueExW(hK, nullptr, nullptr, &type,
                    reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS)
                starCmd = buf;
            RegCloseKey(hK);
        }

        // Back up whatever was there before us.
        HKEY hExt = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\EchoVault\\OpenInterception\\*",
                0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE,
                nullptr, &hExt, nullptr) == ERROR_SUCCESS)
        {
            if (!starCmd.empty())
                RegSetValueExW(hExt, L"Command", 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(starCmd.c_str()),
                    static_cast<DWORD>((starCmd.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hExt);
        }

        // Make EchoVault the open command for all files.
        HKEY hCmd = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER,
                L"Software\\Classes\\*\\shell\\open\\command",
                0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE,
                nullptr, &hCmd, nullptr) == ERROR_SUCCESS)
        {
            RegSetValueExW(hCmd, nullptr, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(handlerCmd.c_str()),
                static_cast<DWORD>((handlerCmd.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hCmd);
        }
        done++;
    }

    // --- The EchoVaultOpen ProgID + its open command ---
    HKEY hProg = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
            L"Software\\Classes\\EchoVaultOpen\\shell\\open\\command",
            0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE,
            nullptr, &hProg, nullptr) == ERROR_SUCCESS)
    {
        RegSetValueExW(hProg, nullptr, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(handlerCmd.c_str()),
            static_cast<DWORD>((handlerCmd.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hProg);
    }

    RegCloseKey(hBase);

    // Tell the shell to re-read associations right away (no logoff needed).
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);

    if (done == 0)
        return false;

    // Start the background watcher (re-asserts our mapping against
    // future "Open with" overrides) and autostart it at logon.
    SetWatcherAutoStart(true);
    StartAssocWatcher();

    return true;
}

void ManageOpenInterception()
{
    if (IsOpenInterceptionInstalled())
    {
        int r = MessageBoxW(nullptr,
            L"Open interception is currently installed.\n\n"
            L"When you double-click an encrypted file, EchoVault asks for its\n"
            L"password, unlocks it and opens it in the normal program.\n"
            L"Plain files still open directly.\n\n"
            L"Uninstall it now?",
            L"EchoVault \u2014 Open Interception",
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
        if (r == IDYES)
        {
            if (UninstallOpenInterception())
                ShowInfo(L"EchoVault",
                    L"Open interception removed. Original file associations restored.");
            else
                ShowError(L"EchoVault",
                    L"Failed to fully remove open interception.");
        }
        return;
    }

    auto allExts = AllInterceptExts();
    std::wstring exts;
    size_t shown = 0;
    for (auto& e : allExts)
    {
        if (shown >= 24)
        {
            exts += L"... and " + std::to_wstring(allExts.size() - shown) + L" more";
            break;
        }
        if (shown > 0 && shown % 8 == 0) exts += L"\n";
        exts += e;
        exts += L" ";
        shown++;
    }

    std::wstring msg =
        L"Install open interception (auto-unlock)?\n\n"
        L"EchoVault will intercept opening of these types (plus ANY file\n"
        L"type that has no other registered program):\n\n" +
        exts + L"\n\n"
        L"Double-clicking an encrypted file will prompt for its password,\n"
        L"unlock it, and open it normally. Plain files are unaffected.\n"
        L"Add more types later with: EchoVault.exe --add-ext .xyz\n"
        L"Original associations are backed up and restored on uninstall.";
    int r = MessageBoxW(nullptr, msg.c_str(),
        L"EchoVault \u2014 Open Interception",
        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
    if (r != IDYES)
        return;

    if (InstallOpenInterception())
        ShowInfo(L"EchoVault", L"Open interception installed successfully!");
    else
        ShowError(L"EchoVault", L"Open interception could not be installed.");
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
        exp.resize(n - 1);
        ExpandEnvironmentStringsW(command.c_str(), &exp[0], n);
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
            // No registered program for this file type: show the standard
            // Windows "How do you want to open this file?" picker, exactly
            // as a normal double-click would.
            SHELLEXECUTEINFOW sei = {};
            sei.cbSize = sizeof(sei);
            sei.lpVerb = L"openas";
            sei.lpFile = filePath.c_str();
            sei.nShow  = SW_SHOWNORMAL;
            ShellExecuteExW(&sei);
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