//------------------------------------------------------------
// test-evtable.c — user-mode logic test for the EchoVault gate
//
// Compiles and runs on any machine (no kernel, no VM, no WDK):
//   g++ -O2 -o test-evtable test-evtable.c
//
// It exercises the EXACT same code the kernel driver runs
// (shared/evtable.h) — fail-open behavior, add/allow/disallow,
// per-boot epoch, folder/prefix gating, file-overrides-folder,
// case-insensitivity, trailing backslashes, removal, overflow.
//------------------------------------------------------------

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

// MinGW lacks winternl.h; the NT string struct the gate logic uses.
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

#include "..\shared\evtable.h"

static EVT_ENTRY* gEntries[256];
static EVT_TABLE  gTable;
static int        gPass = 0;
static int        gFail = 0;

static void* t_alloc(SIZE_T s) { return malloc(s); }
static void  t_free(void* p)   { free(p); }

static UNICODE_STRING U(const wchar_t* s)
{
    UNICODE_STRING u;
    u.Buffer = (PWSTR)s;
    u.Length = (USHORT)(wcslen(s) * sizeof(wchar_t));
    u.MaximumLength = u.Length + (USHORT)sizeof(wchar_t);
    return u;
}

// Thin wrappers so calls take plain strings (no temp-address issues).
static BOOLEAN T_allowed(const wchar_t* s)  { UNICODE_STRING u = U(s); return evtIsAllowed(&gTable, &u); }
static int     T_add(const wchar_t* s)      { UNICODE_STRING u = U(s); return evtAdd(&gTable, &u); }
static int     T_allow(const wchar_t* s)    { UNICODE_STRING u = U(s); return evtAllow(&gTable, &u); }
static int     T_disallow(const wchar_t* s) { UNICODE_STRING u = U(s); return evtDisallow(&gTable, &u); }
static int     T_remove(const wchar_t* s)   { UNICODE_STRING u = U(s); return evtRemove(&gTable, &u); }

static void check(BOOLEAN ok, const wchar_t* what)
{
    wprintf(L"%ls %ls\n", ok ? L"PASS" : L"FAIL", what);
    if (ok) gPass++; else gFail++;
}

static void reset_table(void)
{
    evtClear(&gTable);
    gTable.count = 0;
    gTable.epoch = 1;
}

int main(void)
{
    gTable.entries = gEntries;
    gTable.max = 256;
    gTable.alloc = t_alloc;
    gTable.free = t_free;
    reset_table();

    const wchar_t* f1 = L"C:\\secret\\file.txt";
    const wchar_t* f3 = L"c:\\SECRET\\File.TXT";          // different case
    const wchar_t* f4 = L"C:\\secret\\other.txt";         // sibling
    const wchar_t* dir = L"C:\\secret\\";

    // 1. Fail-open: nothing registered → everything allowed
    check(T_allowed(f1) == TRUE, L"unregistered file is allowed (fail-open)");

    // 2. Add a file → denied; allow → allowed; disallow → denied
    check(T_add(f1) == EVT_OK, L"add registers the file");
    check(T_allowed(f1) == FALSE, L"registered file is denied");
    check(T_allowed(f3) == FALSE, L"denied case-insensitively");
    check(T_allow(f1) == EVT_OK, L"allow succeeds");
    check(T_allowed(f1) == TRUE, L"allow-listed file is allowed");
    check(T_allowed(L"C:\\secret\\file.txt") == TRUE, L"allowed (exact)");
    check(T_disallow(f1) == EVT_OK, L"disallow succeeds");
    check(T_allowed(f1) == FALSE, L"disallowed file is denied again");
    check(T_allowed(f4) == TRUE, L"sibling (unregistered) still allowed");

    // 3. Reboot = new epoch → allow-lists expire
    T_allow(f1);
    check(T_allowed(f1) == TRUE, L"allowed before 'reboot'");
    gTable.epoch++;                       // simulate driver reload / boot
    check(T_allowed(f1) == FALSE, L"stale allow-list expires on reboot");

    // 4. Folder prefix: gates the folder AND everything under it
    reset_table();
    check(T_add(dir) == EVT_OK, L"add folder (prefix) entry");
    check(T_allowed(L"C:\\secret\\") == FALSE, L"folder open denied");
    check(T_allowed(L"C:\\secret") == FALSE, L"folder open without trailing \\ denied");
    check(T_allowed(L"C:\\secret\\file.txt") == FALSE, L"file inside folder denied");
    check(T_allowed(L"C:\\secret\\sub\\deep\\x.txt") == FALSE, L"deep file denied");
    check(T_allowed(L"C:\\other\\file.txt") == TRUE, L"outside folder allowed");
    check(T_allow(dir) == EVT_OK, L"allow the folder");
    check(T_allowed(L"C:\\secret\\file.txt") == TRUE, L"folder allow-list covers contents");

    // 5. File entry overrides folder prefix
    check(T_disallow(L"C:\\secret\\file.txt") == EVT_OK, L"disallow one file under the folder");
    check(T_allowed(L"C:\\secret\\file.txt") == FALSE, L"file denied while folder allowed");
    check(T_allowed(L"C:\\secret\\other.txt") == TRUE, L"sibling still allowed via folder");

    // 6. Re-adding an existing path re-locks it
    reset_table();
    T_add(f1);
    T_allow(f1);
    check(T_allowed(f1) == TRUE, L"unlocked before re-encrypt");
    T_add(f1);
    check(T_allowed(f1) == FALSE, L"re-encrypt (re-add) locks again");

    // 7. Remove unregisters (permanent decrypt)
    T_remove(f1);
    check(T_allowed(f1) == TRUE, L"removed file is allowed (permanent decrypt)");
    check(T_remove(f1) == EVT_ERR_NOTFOUND, L"remove of unknown path reports not-found");

    // 8. File paths with trailing backslashes still match exact files
    reset_table();
    T_add(f1);
    check(T_allowed(L"C:\\secret\\file.txt\\") == FALSE, L"trailing-\\ open still denied (exact)");

    // 9. Overflow is graceful (no crash, error returned)
    {
        gTable.max = 3;
        int over = 0;
        for (int i = 0; i < 10; i++)
        {
            wchar_t buf[64];
            wsprintfW(buf, L"C:\\file%d.txt", i);
            if (T_add(buf) == EVT_ERR_FULL) { over = 1; break; }
        }
        check(over == 1, L"table overflow returns an error, does not crash");
        gTable.max = 256;
    }

    // 10. Empty/bad paths are rejected, not stored
    reset_table();
    check(T_add(L"") == EVT_ERR_BADPATH, L"empty path rejected");

    // 11. clear wipes everything
    reset_table();
    T_add(f1);
    T_add(dir);
    evtClear(&gTable);
    check(T_allowed(f1) == TRUE, L"clear un-gates everything");

    // 12. allow on an unregistered path is a harmless no-op
    reset_table();
    check(T_allow(f1) == EVT_ERR_NOTFOUND, L"allow on unknown path is a no-op");

    // 13. App-exclusion list (backup/indexer tools)
    {
        EVT_EXCL_TABLE ex;
        ex.count = 0;

        check(evtExclCheck(&ex, L"backup.exe") == FALSE, L"no exclusions initially");
        check(evtExclAdd(&ex, L"backup.exe") == EVT_OK, L"exclude adds an app");
        check(evtExclAdd(&ex, L"BACKUP.EXE") == EVT_OK, L"re-adding is idempotent");
        check(evtExclCheck(&ex, L"backup.exe") == TRUE, L"excluded app matches");
        check(evtExclCheck(&ex, L"Backup.Exe") == TRUE, L"match is case-insensitive");
        check(evtExclCheck(&ex, L"backup2.exe") == FALSE, L"similar name does NOT match (exact)");
        check(evtExclCheck(&ex, L"NOTEPAD.EXE") == FALSE, L"unrelated app not excluded");
        check(evtExclAdd(&ex, L"indexer.exe") == EVT_OK, L"second app added");
        check(evtExclCheck(&ex, L"INDEXER.EXE") == TRUE, L"second app matches");
        check(evtExclRemove(&ex, L"Backup.EXE") == EVT_OK, L"remove works case-insensitively");
        check(evtExclCheck(&ex, L"backup.exe") == FALSE, L"removed app no longer excluded");
        check(evtExclCheck(&ex, L"indexer.exe") == TRUE, L"other app unaffected by remove");
        check(evtExclRemove(&ex, L"nope.exe") == EVT_ERR_NOTFOUND, L"remove of unknown app reports not-found");
        check(evtExclAdd(&ex, L"") == EVT_ERR_BADPATH, L"empty app name rejected");
        {
            wchar_t longName[EVT_MAX_EXCL_NAME + 8];
            for (int i = 0; i < EVT_MAX_EXCL_NAME + 7; i++) longName[i] = L'x';
            longName[EVT_MAX_EXCL_NAME + 7] = L'\0';
            check(evtExclAdd(&ex, longName) == EVT_ERR_BADPATH, L"over-long app name rejected");
        }
        evtExclClear(&ex);
        check(evtExclCheck(&ex, L"indexer.exe") == FALSE, L"clear wipes exclusions");
    }

    wprintf(L"\n%d passed, %d failed\n", gPass, gFail);
    evtClear(&gTable);
    return gFail == 0 ? 0 : 1;
}
