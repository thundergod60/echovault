//------------------------------------------------------------
// EchoVaultFilter.c — EchoVault minifilter (Phase 2)
//
// What it does: on EVERY file open (IRP_MJ_CREATE) it checks an
// in-memory table. If the path was registered as an EchoVault-
// encrypted file and is not in the current session's allow-list,
// the open is denied (STATUS_ACCESS_DENIED). Everything else is
// untouched and passes through at nearly zero cost.
//
// Phase 2 adds the auto-prompt: a denied open notifies the guard
// service (EchoVault.exe --guard) over a communication port, which
// pops the normal password dialog. Folder entries (trailing '\')
// gate the whole tree under them.
//
// Phase 3 adds the requesting app: the deny notification carries the
// requestor's image base name (e.g. "notepad.exe"), so after the
// password is entered the guard reopens the file with the SAME app
// the user chose ("Open with" stays faithful) instead of the default
// program.
//
// SAFETY DESIGN (see driver/README-DRIVER.md for the full write-up)
// ---------------------------------------------------------------
//  1. The filter NEVER touches file contents. No reads, no writes,
//     no buffers held across calls. It only does a path lookup.
//  2. FAIL-OPEN: any error, unknown path, or uncertain state means
//     the open is ALLOWED. Denial happens only for paths that were
//     explicitly registered as encrypted and are not allow-listed.
//  3. No I/O is performed while holding the table lock; the hot
//     path is a mutex + a case-insensitive string compare. Deny
//     notifications run on a system work item, never in the open.
//  4. The allow-list carries a random per-boot epoch, so nothing
//     stays unlocked across a reboot.
//  5. If the driver fails to load or is removed, the system boots
//     and runs normally with today's user-mode behavior.
//------------------------------------------------------------

// Use the kernel branch of the shared gate logic (evtable.h): the full
// Unicode case-insensitive compare (RtlEqualUnicodeString) instead of
// the ASCII-only fold used by the user-mode test harness. fltkernel.h
// does not define this flag itself.
#define _FLT_KERNEL_MODE 1

// IMPORTANT: fltKernel.h must come BEFORE ntddk.h. fltKernel.h pulls in
// ntifs.h, which defines _NTIFS_INCLUDED_ so wdm.h types PEPROCESS and
// PETHREAD consistently (as struct _KPROCESS*). Including ntddk.h first
// makes wdm.h use its default definitions (struct _EPROCESS*), and then
// ntifs.h redefines them with different types (MSVC error C2371).
// fltKernel.h includes ntddk.h transitively, so the explicit include
// below is just for clarity.
#include <fltKernel.h>
#include <ntddk.h>
#include "..\shared\evfilter.h"
#include "..\shared\evtable.h"

// ---- Globals ---------------------------------------------------

static PFLT_FILTER gFilter     = NULL;
static PFLT_PORT   gServerPort = NULL;

#define EV_MAX_ENTRIES 1024
#define EV_POOL_TAG    'tfvE'      // pool tag for EvEntry

// The gate table's alloc/free (kernel pool).
static void* EvtAllocKernel(SIZE_T sz)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, EV_POOL_TAG);
}
static void EvtFreeKernel(void* p)
{
    ExFreePoolWithTag(p, EV_POOL_TAG);
}

static FAST_MUTEX gLock;
static EVT_ENTRY* gEntries[EV_MAX_ENTRIES];
static EVT_TABLE  gTable;

// App-exclusion list: image base names that may open locked files
// (backup/indexer tools). Safe by construction — without the password
// they only ever see ciphertext.
static FAST_MUTEX      gExclLock;
static EVT_EXCL_TABLE  gExcl;

static ULONG      gRandSeed   = 0xE601;

// Maps the shared logic's status codes to NTSTATUS.
static NTSTATUS EvMapStatus(int rc)
{
    switch (rc)
    {
        case EVT_OK:            return STATUS_SUCCESS;
        case EVT_ERR_NOTFOUND:  return STATUS_NOT_FOUND;
        case EVT_ERR_FULL:      return STATUS_INSUFFICIENT_RESOURCES;
        case EVT_ERR_BADPATH:   return STATUS_INVALID_PARAMETER;
        default:                return STATUS_UNSUCCESSFUL;
    }
}

// ---- Deny notification (Phase 2) --------------------------------
// When an open is denied, a work item tells the guard service (via
// FltSendMessage on the client port) so it can pop the password
// dialog. Best-effort: if no client is connected the message is
// dropped and the open is still denied.

static KSPIN_LOCK gPortLock;

// Multiple user-mode clients are connected at the same time: the guard
// (long-lived listener for deny notifications) plus short-lived clients
// (EchoVault app operations, filterctl). Track them all so that one
// client disconnecting never cuts the others' notifications. The port
// is created with this many connection slots (FltCreateCommunicationPort
// below); with a single slot the guard would starve every other client
// (FilterConnectCommunicationPort fails with ACCESS_DENIED when the
// limit is reached).
#define EV_MAX_CLIENTS 16
static PFLT_PORT  gClients[EV_MAX_CLIENTS];

// Build tag, embedded in the .sys so CI artifacts can be told apart
// beyond doubt. Any .sys built before this tag does NOT contain the
// string. Verify a downloaded driver with:
//     findstr /c:"EVBUILD-PORTUSERS-20260818" EchoVaultFilter.sys
const char EvBuildTag[] = "EVBUILD-PORTUSERS-20260818";

// 2-second throttle: don't spam the guard with duplicate denies of
// the same path (Explorer can retry opens rapidly).
#define EV_NOTIFY_THROTTLE_TICKS 200   // ~2s at 10ms tick
static WCHAR  gLastNotifyPath[EVFILTER_MAX_PATH];
static ULONG  gLastNotifyTick = 0;

#define EV_NOTIFY_TAG 'tfvE'

typedef struct _EV_NOTIFY_CONTEXT {
    WORK_QUEUE_ITEM Wq;
    WCHAR Path[EVFILTER_MAX_PATH];
    WCHAR RequesterApp[EVFILTER_MAX_APP];
} EV_NOTIFY_CONTEXT;

// Captures the requestor's image base name (e.g. "notepad.exe") into a
// WCHAR buffer. Best-effort: on any failure the buffer stays empty, and
// the guard then falls back to the default program (harmless).
// Uses SeLocateProcessImageName (ntifs.h, pulled in by fltKernel.h) —
// the current documented API. It must run at PASSIVE_LEVEL, which holds
// for IRP_MJ_CREATE pre-operation callbacks.
static VOID EvCaptureRequesterApp(PEPROCESS proc, WCHAR* out, ULONG outChars)
{
    if (!proc || !out || outChars == 0)
        return;
    out[0] = L'\0';

    // SeLocateProcessImageName allocates a UNICODE_STRING holding the
    // FULL image path; the caller frees the structure with ExFreePool.
    PUNICODE_STRING imageName = NULL;
    if (!NT_SUCCESS(SeLocateProcessImageName(proc, &imageName)) || !imageName)
        return;

    // Extract the base name (the part after the last '\').
    ULONG chars = imageName->Length / sizeof(WCHAR);
    ULONG base = 0;
    for (ULONG i = chars; i > 0; i--)
    {
        if (imageName->Buffer[i - 1] == L'\\')
        {
            base = i;
            break;
        }
    }
    ULONG baseChars = chars - base;
    if (baseChars > 0 && baseChars < outChars)
    {
        RtlCopyMemory(out, imageName->Buffer + base, baseChars * sizeof(WCHAR));
        out[baseChars] = L'\0';
    }

    ExFreePool(imageName);
}

static VOID EvNotifyWorker(_In_ PVOID Context)
{
    EV_NOTIFY_CONTEXT* c = (EV_NOTIFY_CONTEXT*)Context;

    EVFILTER_NOTIFY notify;
    RtlZeroMemory(&notify, sizeof(notify));
    notify.OpCode = EVFILTER_NOTIFY_DENIED;
    RtlCopyMemory(notify.Path, c->Path,
        (evtPathChars(c->Path, EVFILTER_MAX_PATH) + 1) * sizeof(WCHAR));
    RtlCopyMemory(notify.RequesterApp, c->RequesterApp,
        EVFILTER_MAX_APP * sizeof(WCHAR));

    // Snapshot the connected clients under the lock, then send to each
    // outside it. Fire-and-forget: no reply is needed; a client that
    // disconnected meanwhile just fails immediately and is skipped.
    PFLT_PORT snapshot[EV_MAX_CLIENTS];
    KIRQL irql;
    ExAcquireSpinLock(&gPortLock, &irql);
    for (ULONG i = 0; i < EV_MAX_CLIENTS; i++)
        snapshot[i] = gClients[i];
    ExReleaseSpinLock(&gPortLock, irql);

    for (ULONG i = 0; i < EV_MAX_CLIENTS; i++)
    {
        if (snapshot[i])
            FltSendMessage(gFilter, &snapshot[i], &notify, sizeof(notify),
                NULL, NULL, NULL);
    }

    ExFreePoolWithTag(c, EV_NOTIFY_TAG);
}

// Queues the notification unless the same path was notified within
// the throttle window. Must NOT be called with gLock held (the worker
// takes gPortLock only). app is the requestor's image base name
// ("notepad.exe"), copied synchronously.
static VOID EvQueueDenyNotification(const UNICODE_STRING* name, const WCHAR* app)
{
    ULONG chars = name->Length / sizeof(WCHAR);
    if (chars == 0)
        return;
    if (chars >= EVFILTER_MAX_PATH)
        chars = EVFILTER_MAX_PATH - 1;

    KIRQL irql;
    ExAcquireSpinLock(&gPortLock, &irql);

    LARGE_INTEGER tickCount;
    KeQueryTickCount(&tickCount);
    ULONG tick = (ULONG)(tickCount.QuadPart & 0xFFFFFFFF);
    BOOLEAN throttled =
        (gLastNotifyTick != 0) &&
        (tick - gLastNotifyTick < EV_NOTIFY_THROTTLE_TICKS) &&
        (chars == evtPathChars(gLastNotifyPath, EVFILTER_MAX_PATH)) &&
        RtlEqualMemory(name->Buffer, gLastNotifyPath, chars * sizeof(WCHAR));

    BOOLEAN anyClient = FALSE;
    for (ULONG i = 0; i < EV_MAX_CLIENTS; i++)
    {
        if (gClients[i])
        {
            anyClient = TRUE;
            break;
        }
    }
    if (throttled || !anyClient)
    {
        ExReleaseSpinLock(&gPortLock, irql);
        return;
    }

    EV_NOTIFY_CONTEXT* c = (EV_NOTIFY_CONTEXT*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(EV_NOTIFY_CONTEXT), EV_NOTIFY_TAG);
    if (!c)
    {
        ExReleaseSpinLock(&gPortLock, irql);
        return;
    }

    RtlCopyMemory(c->Path, name->Buffer, chars * sizeof(WCHAR));
    c->Path[chars] = L'\0';
    c->RequesterApp[0] = L'\0';
    if (app)
        RtlCopyMemory(c->RequesterApp, app, EVFILTER_MAX_APP * sizeof(WCHAR));

    gLastNotifyTick = tick;
    RtlCopyMemory(gLastNotifyPath, c->Path, (chars + 1) * sizeof(WCHAR));
    ExReleaseSpinLock(&gPortLock, irql);

    ExInitializeWorkItem(&c->Wq, EvNotifyWorker, c);
    ExQueueWorkItem(&c->Wq, DelayedWorkQueue);
}

// ---- Path-form translation -------------------------------------
// The filter manager's normalized names are DEVICE paths
// (\Device\HarddiskVolume1\...), while user mode registers DRIVE
// LETTER / UNC paths (C:\..., \\server\share\...). The gate must
// compare like with like, so incoming registration paths are
// translated to device form. The logic lives in evdevpath.c so it can
// be unit-tested in user mode; the same code runs in the kernel.
#include "evdevpath.c"

// ---- Communication port security ------------------------------
// FltBuildDefaultSecurityDescriptor builds a DACL that grants access
// only to SYSTEM and Administrators. EchoVault.exe, the guard, and the
// watcher all run as the normal (non-elevated) logged-on user, so with
// that descriptor every one of their port connections is rejected with
// STATUS_ACCESS_DENIED and every path registration silently fails —
// encrypted files and folders would never actually be gated. Build a
// custom descriptor that ALSO grants Authenticated Users, so the app's
// own processes can connect while the gate still denies every other
// opener (the file opens themselves are gated separately, per-path).
#define EV_SD_TAG 'tfvE'

static NTSTATUS EvBuildPortSecurityDescriptor(PSECURITY_DESCRIPTOR* OutSd)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL acl = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    // SIDs are built on the stack with the kernel Rtl* APIs (the
    // user-mode RtlAllocateAndInitializeSid/RtlFreeSid are ntdll exports
    // and do not exist in ntoskrnl.lib). 40 bytes fits S-1-5-11 and
    // S-1-5-32-544 (16 bytes each, no subauthority nesting).
    UCHAR authUsersBuf[40];
    UCHAR adminsBuf[40];
    PSID authUsers = (PSID)authUsersBuf;
    PSID admins = (PSID)adminsBuf;

    // S-1-5-11: Authenticated Users — the logged-on user's processes
    // (EchoVault.exe, the guard, the watcher).
    RtlInitializeSid(authUsers, &ntAuth, 1);
    *RtlSubAuthoritySid(authUsers, 0) = SECURITY_AUTHENTICATED_USER_RID;

    // S-1-5-32-544: BUILTIN\Administrators — keeps elevated tools like
    // filterctl working.
    RtlInitializeSid(admins, &ntAuth, 2);
    *RtlSubAuthoritySid(admins, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(admins, 1) = DOMAIN_ALIAS_RID_ADMINS;

    ULONG aclSize = sizeof(ACL)
        + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)) + RtlLengthSid(authUsers)
        + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)) + RtlLengthSid(admins);

    acl = (PACL)ExAllocatePool2(POOL_FLAG_NON_PAGED, aclSize, EV_SD_TAG);
    sd = (PSECURITY_DESCRIPTOR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        SECURITY_DESCRIPTOR_MIN_LENGTH, EV_SD_TAG);
    if (!acl || !sd)
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    status = RtlCreateSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) goto done;
    status = RtlCreateAcl(acl, aclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) goto done;
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, FLT_PORT_ALL_ACCESS, authUsers);
    if (!NT_SUCCESS(status)) goto done;
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, FLT_PORT_ALL_ACCESS, admins);
    if (!NT_SUCCESS(status)) goto done;
    status = RtlSetDaclSecurityDescriptor(sd, TRUE, acl, FALSE);
    if (!NT_SUCCESS(status)) goto done;

    *OutSd = sd;
    sd = NULL;      // ownership transferred to the caller

 done:
    if (acl)       ExFreePoolWithTag(acl, EV_SD_TAG);
    if (sd)        ExFreePoolWithTag(sd, EV_SD_TAG);
    return status;
}

static VOID EvFreePortSecurityDescriptor(PSECURITY_DESCRIPTOR sd)
{
    if (!sd) return;

    // The DACL is a separately allocated block referenced by the SD.
    PACL dacl = NULL;
    BOOLEAN daclPresent = FALSE;
    BOOLEAN daclDefaulted = FALSE;
    if (NT_SUCCESS(RtlGetDaclSecurityDescriptor(sd, &daclPresent, &dacl, &daclDefaulted))
        && daclPresent && dacl)
    {
        ExFreePoolWithTag(dacl, EV_SD_TAG);
    }
    ExFreePoolWithTag(sd, EV_SD_TAG);
}

// ---- Communication port ---------------------------------------

static NTSTATUS EvConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    KIRQL irql;
    ExAcquireSpinLock(&gPortLock, &irql);
    for (ULONG i = 0; i < EV_MAX_CLIENTS; i++)
    {
        if (gClients[i] == NULL)
        {
            gClients[i] = ClientPort;
            break;
        }
    }
    ExReleaseSpinLock(&gPortLock, irql);

    *ConnectionPortCookie = (PVOID)ClientPort;
    return STATUS_SUCCESS;
}

static VOID EvDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    KIRQL irql;
    ExAcquireSpinLock(&gPortLock, &irql);
    PFLT_PORT who = (PFLT_PORT)ConnectionCookie;
    for (ULONG i = 0; i < EV_MAX_CLIENTS; i++)
    {
        if (who ? (gClients[i] == who) : (gClients[i] != NULL))
        {
            gClients[i] = NULL;
            break;
        }
    }
    gLastNotifyTick = 0;
    ExReleaseSpinLock(&gPortLock, irql);
}

static NTSTATUS EvMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (ReturnOutputBufferLength)
        *ReturnOutputBufferLength = 0;

    if (!InputBuffer ||
        InputBufferLength < FIELD_OFFSET(EVFILTER_MSG, Path) + sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    EVFILTER_MSG* m = (EVFILTER_MSG*)InputBuffer;

    // The path must be NUL-terminated inside the buffer.
    ULONG availChars =
        (InputBufferLength - FIELD_OFFSET(EVFILTER_MSG, Path)) / sizeof(WCHAR);
    ULONG len = evtPathChars(m->Path, availChars);
    if (len == availChars && m->Path[len - 1] != L'\0')
        return STATUS_INVALID_PARAMETER;

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, m->Path);   // safe: NUL found within bounds

    NTSTATUS status = STATUS_SUCCESS;

    // Translate the registration path to the device form the gate
    // compares against (normalized names are \Device\... paths).
    UNICODE_STRING devPath;
    EvToDevicePath(&path, &devPath);

    // Exclusions live in their own table/lock: they are config, not path
    // state, and they are accessed only when an open is about to be
    // denied, so keeping them out of the hot-path lock is right.
    if (m->OpCode == EVFILTER_MSG_EXCLUDE_ADD ||
        m->OpCode == EVFILTER_MSG_EXCLUDE_REMOVE ||
        m->OpCode == EVFILTER_MSG_EXCLUDE_CLEAR)
    {
        ExAcquireFastMutex(&gExclLock);
        switch (m->OpCode)
        {
            case EVFILTER_MSG_EXCLUDE_ADD:    status = EvMapStatus(evtExclAdd(&gExcl, m->Path));    break;
            case EVFILTER_MSG_EXCLUDE_REMOVE: status = EvMapStatus(evtExclRemove(&gExcl, m->Path)); break;
            case EVFILTER_MSG_EXCLUDE_CLEAR:  evtExclClear(&gExcl);                                  break;
        }
        ExReleaseFastMutex(&gExclLock);
        return status;
    }

    ExAcquireFastMutex(&gLock);
    switch (m->OpCode)
    {
        case EVFILTER_MSG_ADD:      status = EvMapStatus(evtAdd(&gTable, &devPath));      break;
        case EVFILTER_MSG_ALLOW:    status = EvMapStatus(evtAllow(&gTable, &devPath));    break;
        case EVFILTER_MSG_DISALLOW: status = EvMapStatus(evtDisallow(&gTable, &devPath)); break;
        case EVFILTER_MSG_REMOVE:   status = EvMapStatus(evtRemove(&gTable, &devPath));   break;
        case EVFILTER_MSG_CLEAR:    evtClear(&gTable);                                    break;
        case EVFILTER_MSG_STATUS:                                                         break;
        default:                    status = STATUS_INVALID_PARAMETER;                    break;
    }
    ExReleaseFastMutex(&gLock);

    if (devPath.Buffer != path.Buffer)
        ExFreePool(devPath.Buffer);

    return status;
}

// ---- Pre-op callback: the actual gate --------------------------

static FLT_PREOP_CALLBACK_STATUS EvPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!FltObjects || !FltObjects->FileObject)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;   // fail-open

    ExAcquireFastMutex(&gLock);
    BOOLEAN allowed = evtIsAllowed(&gTable, &nameInfo->Name);
    ExReleaseFastMutex(&gLock);

    if (!allowed)
    {
        // Who is asking? Used both for the exclusion check and (Phase 3)
        // for the deny notification, so the guard can reopen the file in
        // the SAME app after the password is entered.
        WCHAR requesterApp[EVFILTER_MAX_APP] = { 0 };
        EvCaptureRequesterApp(FltGetRequestorProcess(Data), requesterApp, EVFILTER_MAX_APP);

        // App-exclusion list (backup/indexer tools): these may open locked
        // files. This is safe by construction — without the master password
        // they only ever see ciphertext — and it lets backups of locked
        // files actually happen (otherwise the driver would block even a
        // backup tool from copying the encrypted file).
        if (requesterApp[0])
        {
            ExAcquireFastMutex(&gExclLock);
            BOOLEAN excluded = evtExclCheck(&gExcl, requesterApp);
            ExReleaseFastMutex(&gExclLock);
            if (excluded)
                allowed = TRUE;
        }

        if (!allowed)
        {
            // Tell the guard service (best-effort, async, throttled) so it
            // can pop the password dialog. The open itself is denied either
            // way: never expose the contents of a locked file. (Queued
            // while nameInfo is still valid — it copies synchronously.)
            EvQueueDenyNotification(&nameInfo->Name, requesterApp);
        }
    }

    FltReleaseFileNameInformation(nameInfo);

    if (!allowed)
    {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---- Registration / unload -------------------------------------

static NTSTATUS EvFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    ExAcquireFastMutex(&gLock);
    evtClear(&gTable);
    ExReleaseFastMutex(&gLock);

    ExAcquireFastMutex(&gExclLock);
    evtExclClear(&gExcl);
    ExReleaseFastMutex(&gExclLock);

    KIRQL irql;
    ExAcquireSpinLock(&gPortLock, &irql);
    PFLT_PORT toClose[EV_MAX_CLIENTS];
    for (ULONG i = 0; i < EV_MAX_CLIENTS; i++)
    {
        toClose[i] = gClients[i];
        gClients[i] = NULL;
    }
    gLastNotifyTick = 0;
    ExReleaseSpinLock(&gPortLock, irql);
    for (ULONG i = 0; i < EV_MAX_CLIENTS; i++)
    {
        if (toClose[i])
            FltCloseClientPort(gFilter, &toClose[i]);
    }

    if (gServerPort)
    {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
    if (gFilter)
    {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return STATUS_SUCCESS;
}

static FLT_PREOP_CALLBACK_STATUS EvPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

CONST FLT_OPERATION_REGISTRATION EvCallbacks[] = {
    { IRP_MJ_CREATE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      EvPreCreate, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION EvRegistration = {
    sizeof(FLT_REGISTRATION),   // Size
    FLT_REGISTRATION_VERSION,   // Version
    0,                          // Flags
    NULL,                       // ContextRegistration
    EvCallbacks,                // OperationRegistration
    EvFilterUnload,             // FilterUnloadCallback
    NULL,                       // InstanceSetup (attach to all volumes)
    NULL,                       // InstanceQueryTeardown
    NULL,                       // InstanceTeardownStart
    NULL,                       // InstanceTeardownComplete
    NULL,                       // GenerateFileName
    NULL,                       // NormalizeNameComponent
    NULL,                       // NormalizeContextCleanup
    NULL,                       // TransactionNotification
    NULL,                       // NormalizeNameComponentEx
    NULL                        // SectionNotification
};

// ---- Entry point -----------------------------------------------

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeFastMutex(&gLock);
    ExInitializeFastMutex(&gExclLock);
    gExcl.count = 0;
    KeInitializeSpinLock(&gPortLock);
    for (ULONG i = 0; i < EV_MAX_CLIENTS; i++)
        gClients[i] = NULL;
    gLastNotifyTick = 0;
    RtlZeroMemory(gLastNotifyPath, sizeof(gLastNotifyPath));

    gTable.entries = gEntries;
    gTable.count   = 0;
    gTable.max     = EV_MAX_ENTRIES;
    gTable.alloc   = EvtAllocKernel;
    gTable.free    = EvtFreeKernel;

    // Random per-boot epoch: every allow-list entry created now is
    // stale after the next boot, so locked files are locked again.
    gTable.epoch = RtlRandomEx(&gRandSeed);
    if (gTable.epoch == 0)
        gTable.epoch = 1;

    NTSTATUS status = FltRegisterFilter(DriverObject, &EvRegistration, &gFilter);
    if (!NT_SUCCESS(status))
        return status;

    PSECURITY_DESCRIPTOR sd = NULL;
    status = EvBuildPortSecurityDescriptor(&sd);
    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }

    UNICODE_STRING portName = RTL_CONSTANT_STRING(EVFILTER_PORT_NAME);
    OBJECT_ATTRIBUTES oa;
    // CRITICAL: the security descriptor MUST be attached to the object
    // attributes. FltCreateCommunicationPort has no SD parameter — the
    // ACL travels via InitializeObjectAttributes. With a NULL descriptor
    // the port grants access only to SYSTEM, so EVERY user-mode client
    // (guard, app, filterctl — even an elevated admin) is rejected with
    // STATUS_ACCESS_DENIED on FilterConnectCommunicationPort. And with
    // FltBuildDefaultSecurityDescriptor it grants access only to SYSTEM
    // and Administrators, which silently starves the non-elevated app
    // (see EvBuildPortSecurityDescriptor).
    InitializeObjectAttributes(&oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
        EvConnectNotify, EvDisconnectNotify, EvMessageNotify, EV_MAX_CLIENTS);

    EvFreePortSecurityDescriptor(sd);

    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status))
    {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }

    // Reference the build tag so the linker keeps it in the image.
    DbgPrint("EchoVaultFilter %s loaded\n", EvBuildTag);

    return STATUS_SUCCESS;
}
