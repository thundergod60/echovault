//------------------------------------------------------------
// evtable.h — EchoVault minifilter GATE LOGIC (pure, shared)
//
// The deny/allow decision logic of the driver, as a small
// dependency-free table so the SAME code runs in the kernel
// driver AND in a user-mode logic test (driver/test-evtable.c).
//
// NO #include here. The including TU must provide the base types
// via <windows.h> (user mode) or <fltKernel.h> (kernel): ULONG,
// BOOLEAN, WCHAR, UNICODE_STRING, SIZE_T, NULL, TRUE/FALSE.
//
// Behavior contract (identical in kernel and test):
//   * FAIL-OPEN: unknown/unregistered paths are always allowed.
//   * A registered-encrypted path is DENIED unless allow-listed
//     with the CURRENT epoch (epoch changes at every driver load,
//     so nothing stays unlocked across a reboot).
//   * Entries whose path ends in '\' are folder/prefix entries:
//     they gate the folder itself AND everything under it.
//   * The MOST SPECIFIC match wins (a file entry overrides a
//     folder prefix).
//   * The caller serializes access (the driver holds its lock).
//------------------------------------------------------------

#ifndef EVTABLE_H
#define EVTABLE_H

#ifdef __cplusplus
extern "C" {
#endif

#define EVT_MAX_PATH 1024
#define EVT_MAX_EXCL      32      // max entries in the app-exclusion list
#define EVT_MAX_EXCL_NAME 64      // WCHARs incl. NUL (image base names)

typedef struct _EVT_ENTRY {
    ULONG   Epoch;          // epoch at which this entry was allow-listed
    BOOLEAN Encrypted;      // registered as an EchoVault-encrypted path
    BOOLEAN Allowed;        // currently in the allow-list
    USHORT  PathChars;      // count of WCHARs in Path (excluding NUL)
    WCHAR   Path[1];        // variable length
} EVT_ENTRY;

typedef struct _EVT_TABLE {
    EVT_ENTRY** entries;
    ULONG       count;
    ULONG       max;
    ULONG       epoch;
    void*       (*alloc)(SIZE_T);
    void        (*free)(void*);
} EVT_TABLE;

// Status codes
#define EVT_OK            0
#define EVT_ERR_NOTFOUND -1
#define EVT_ERR_FULL     -2
#define EVT_ERR_BADPATH  -3

// ---- Case-insensitive string compare ---------------------------
// Kernel: full Unicode folding via the system's Rtl routine.
// User test: ASCII fold (a-z/A-Z) — identical for the common
// (ASCII) path cases; any exotic mismatch fails OPEN, never denies.
#ifdef _FLT_KERNEL_MODE
#define EVT_STRICMP(a, b)  RtlEqualUnicodeString((a), (b), TRUE)
#else
static BOOLEAN evtStriCmp(const UNICODE_STRING* a, const UNICODE_STRING* b)
{
    if (a->Length != b->Length)
        return FALSE;
    ULONG n = a->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < n; i++)
    {
        WCHAR ca = a->Buffer[i];
        WCHAR cb = b->Buffer[i];
        if (ca >= L'a' && ca <= L'z') ca = (WCHAR)(ca - L'a' + L'A');
        if (cb >= L'a' && cb <= L'z') cb = (WCHAR)(cb - L'a' + L'A');
        if (ca != cb)
            return FALSE;
    }
    return TRUE;
}
#define EVT_STRICMP(a, b)  evtStriCmp((a), (b))
#endif

static ULONG evtPathChars(const WCHAR* s, ULONG maxChars)
{
    ULONG n = 0;
    while (n < maxChars && s[n] != L'\0')
        n++;
    return n;
}

// Exact-file compare, ignoring trailing backslashes.
static BOOLEAN evtPathsEqual(const EVT_ENTRY* e, const UNICODE_STRING* name)
{
    UNICODE_STRING a, b;
    a.Buffer = (PWCH)e->Path;
    a.Length = (USHORT)(e->PathChars * sizeof(WCHAR));
    a.MaximumLength = (USHORT)((e->PathChars + 1) * sizeof(WCHAR));

    b.Buffer = name->Buffer;
    b.Length = name->Length;
    b.MaximumLength = name->MaximumLength;

    while (a.Length >= 2 && a.Buffer[a.Length / 2 - 1] == L'\\')
        a.Length -= 2;
    while (b.Length >= 2 && b.Buffer[b.Length / 2 - 1] == L'\\')
        b.Length -= 2;

    return EVT_STRICMP(&a, &b);
}

// Folder/prefix entry (Path ends with '\'): matches the folder and
// everything under it.
static BOOLEAN evtDirMatches(const EVT_ENTRY* e, const UNICODE_STRING* name)
{
    ULONG prefixChars = e->PathChars - 1;   // drop the trailing '\'
    ULONG nameChars = name->Length / sizeof(WCHAR);
    if (nameChars < prefixChars)
        return FALSE;

    UNICODE_STRING p, n;
    p.Buffer = (PWCH)e->Path;
    p.Length = (USHORT)(prefixChars * sizeof(WCHAR));
    p.MaximumLength = (USHORT)((prefixChars + 1) * sizeof(WCHAR));
    n.Buffer = name->Buffer;
    n.Length = (USHORT)(prefixChars * sizeof(WCHAR));
    n.MaximumLength = (USHORT)(prefixChars * sizeof(WCHAR));

    if (!EVT_STRICMP(&p, &n))
        return FALSE;
    if (nameChars == prefixChars)
        return TRUE;                    // the directory itself
    return name->Buffer[prefixChars] == L'\\';   // something under it
}

// Most specific matching entry (longest path) — file entries override
// folder prefixes. Returns NULL if nothing matches.
static EVT_ENTRY* evtFindBest(EVT_TABLE* t, const UNICODE_STRING* name)
{
    EVT_ENTRY* best = NULL;
    ULONG bestLen = 0;
    for (ULONG i = 0; i < t->count; i++)
    {
        EVT_ENTRY* e = t->entries[i];
        BOOLEAN match;
        if (e->PathChars > 1 && e->Path[e->PathChars - 1] == L'\\')
            match = evtDirMatches(e, name);
        else
            match = evtPathsEqual(e, name);
        if (match && e->PathChars > bestLen)
        {
            best = e;
            bestLen = e->PathChars;
        }
    }
    return best;
}

// THE decision: TRUE = allow the open. FAIL-OPEN.
static BOOLEAN evtIsAllowed(EVT_TABLE* t, const UNICODE_STRING* name)
{
    EVT_ENTRY* e = evtFindBest(t, name);
    if (e && e->Encrypted)
        return (e->Allowed && e->Epoch == t->epoch);
    return TRUE;
}

// ---- Intent: a trailing '\' means folder (prefix) semantics. -----
// File paths (no trailing '\') act on the EXACT file entry only; if
// only a folder prefix matches, a precise file entry is created so a
// single file can be allowed/denied without touching the folder.

static BOOLEAN evtIsDirEntry(const EVT_ENTRY* e)
{
    return e->PathChars > 1 && e->Path[e->PathChars - 1] == L'\\';
}

static BOOLEAN evtPathIsDir(const UNICODE_STRING* p)
{
    return p->Length >= 2 && p->Buffer[p->Length / 2 - 1] == L'\\';
}

// Ensures an EXACT (non-folder) entry exists for path; creates one if
// needed. Returns it, or NULL on failure. Does not change flags.
static EVT_ENTRY* evtEnsureEntry(EVT_TABLE* t, const UNICODE_STRING* path)
{
    for (ULONG i = 0; i < t->count; i++)
    {
        EVT_ENTRY* e = t->entries[i];
        if (!evtIsDirEntry(e) && evtPathsEqual(e, path))
            return e;
    }

    if (t->count >= t->max)
        return NULL;

    ULONG chars = path->Length / sizeof(WCHAR);
    if (chars == 0 || chars >= 0xFFFF)
        return NULL;

    SIZE_T size = sizeof(EVT_ENTRY) + (chars + 1) * sizeof(WCHAR);
    EVT_ENTRY* e = (EVT_ENTRY*)t->alloc(size);
    if (!e)
        return NULL;

    e->Epoch     = 0;
    e->Encrypted = FALSE;
    e->Allowed   = FALSE;
    e->PathChars = (USHORT)chars;
    RtlCopyMemory(e->Path, path->Buffer, chars * sizeof(WCHAR));
    e->Path[chars] = L'\0';

    t->entries[t->count++] = e;
    return e;
}

// Register a path as encrypted (locked until allow-listed).
static int evtAdd(EVT_TABLE* t, const UNICODE_STRING* path)
{
    BOOLEAN dir = evtPathIsDir(path);
    EVT_ENTRY* e = NULL;
    EVT_ENTRY* best = evtFindBest(t, path);
    if (best && ((dir && evtIsDirEntry(best)) || (!dir && !evtIsDirEntry(best))))
        e = best;                      // exact kind of entry already exists
    else
        e = evtEnsureEntry(t, path);   // folder matched a file path, etc.
    if (!e)
        return t->count >= t->max ? EVT_ERR_FULL : EVT_ERR_BADPATH;
    e->Encrypted = TRUE;
    e->Allowed   = FALSE;
    return EVT_OK;
}

static int evtAllow(EVT_TABLE* t, const UNICODE_STRING* path)
{
    EVT_ENTRY* e = evtFindBest(t, path);
    if (!e)
        return EVT_ERR_NOTFOUND;
    if (evtPathIsDir(path) || !evtIsDirEntry(e))
    {
        // folder intent, or an exact file entry: operate on it directly
        e->Allowed = TRUE;
        e->Epoch   = t->epoch;
        return EVT_OK;
    }
    // file intent, only a folder prefix matched: create a precise entry
    EVT_ENTRY* fe = evtEnsureEntry(t, path);
    if (!fe)
        return EVT_ERR_FULL;
    fe->Encrypted = TRUE;
    fe->Allowed   = TRUE;
    fe->Epoch     = t->epoch;
    return EVT_OK;
}

static int evtDisallow(EVT_TABLE* t, const UNICODE_STRING* path)
{
    EVT_ENTRY* e = evtFindBest(t, path);
    if (!e)
        return EVT_ERR_NOTFOUND;
    if (evtPathIsDir(path) || !evtIsDirEntry(e))
    {
        e->Allowed = FALSE;
        return EVT_OK;
    }
    // file intent, only a folder prefix matched: lock just this file
    EVT_ENTRY* fe = evtEnsureEntry(t, path);
    if (!fe)
        return EVT_ERR_FULL;
    fe->Encrypted = TRUE;
    fe->Allowed   = FALSE;
    return EVT_OK;
}

static int evtRemove(EVT_TABLE* t, const UNICODE_STRING* path)
{
    for (ULONG i = 0; i < t->count; i++)
    {
        EVT_ENTRY* e = t->entries[i];
        BOOLEAN match = evtIsDirEntry(e)
            ? (evtPathIsDir(path) && evtDirMatches(e, path))
            : (!evtPathIsDir(path) && evtPathsEqual(e, path));
        if (match)
        {
            t->free(e);
            for (ULONG j = i + 1; j < t->count; j++)
                t->entries[j - 1] = t->entries[j];
            t->count--;
            return EVT_OK;
        }
    }
    return EVT_ERR_NOTFOUND;
}

static void evtClear(EVT_TABLE* t)
{
    for (ULONG i = 0; i < t->count; i++)
        t->free(t->entries[i]);
    t->count = 0;
}

// ---- App exclusion list ------------------------------------------
// Base image names ("backup.exe") that may open locked files. This is
// SAFE by construction: without the master password they only ever see
// ciphertext — the point is letting backup/indexer tools copy locked
// files. Exclusions are global (apply to every registered path) and
// persist for the driver session. Case-insensitive, exact base-name
// match ("notepad.exe" matches "NOTEPAD.EXE" but not "notepad2.exe").

typedef struct _EVT_EXCL_ENTRY {
    USHORT NameChars;                 // WCHARs in Name (excluding NUL)
    WCHAR  Name[EVT_MAX_EXCL_NAME];   // NUL-terminated, stored as-is
} EVT_EXCL_ENTRY;

typedef struct _EVT_EXCL_TABLE {
    EVT_EXCL_ENTRY entries[EVT_MAX_EXCL];
    ULONG count;
} EVT_EXCL_TABLE;

// Case-insensitive compare of two NUL-terminated WCHAR strings.
static BOOLEAN evtStriCmpW(const WCHAR* a, const WCHAR* b)
{
    while (*a && *b)
    {
        WCHAR ca = *a, cb = *b;
        if (ca >= L'a' && ca <= L'z') ca = (WCHAR)(ca - L'a' + L'A');
        if (cb >= L'a' && cb <= L'z') cb = (WCHAR)(cb - L'a' + L'A');
        if (ca != cb)
            return FALSE;
        a++;
        b++;
    }
    return *a == *b;
}

static int evtExclAdd(EVT_EXCL_TABLE* t, const WCHAR* name)
{
    ULONG chars = evtPathChars(name, EVT_MAX_EXCL_NAME);
    if (chars == 0 || chars >= EVT_MAX_EXCL_NAME)
        return EVT_ERR_BADPATH;

    for (ULONG i = 0; i < t->count; i++)
        if (evtStriCmpW(t->entries[i].Name, name))
            return EVT_OK;   // already excluded — idempotent

    if (t->count >= EVT_MAX_EXCL)
        return EVT_ERR_FULL;

    EVT_EXCL_ENTRY* e = &t->entries[t->count++];
    e->NameChars = (USHORT)chars;
    RtlCopyMemory(e->Name, name, chars * sizeof(WCHAR));
    e->Name[chars] = L'\0';
    return EVT_OK;
}

static int evtExclRemove(EVT_EXCL_TABLE* t, const WCHAR* name)
{
    for (ULONG i = 0; i < t->count; i++)
    {
        if (evtStriCmpW(t->entries[i].Name, name))
        {
            for (ULONG j = i + 1; j < t->count; j++)
                t->entries[j - 1] = t->entries[j];
            t->count--;
            return EVT_OK;
        }
    }
    return EVT_ERR_NOTFOUND;
}

static BOOLEAN evtExclCheck(EVT_EXCL_TABLE* t, const WCHAR* name)
{
    for (ULONG i = 0; i < t->count; i++)
        if (evtStriCmpW(t->entries[i].Name, name))
            return TRUE;
    return FALSE;
}

static void evtExclClear(EVT_EXCL_TABLE* t)
{
    t->count = 0;
}

#ifdef __cplusplus
}
#endif

#endif // EVTABLE_H
