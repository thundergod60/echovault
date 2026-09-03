//------------------------------------------------------------
// test-evdevpath.c — user-mode unit test for EvToDevicePath
// (driver/evdevpath.c), the minifilter's path-form translation.
//
// Build (plain gcc, no WDK):
//   gcc -o test-evdevpath test-evdevpath.c -I . -I ..\..\shared
//   test-evdevpath.exe
//------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntddk.h"
#include "fltKernel.h"
#include "../../shared/evfilter.h"   // EVFILTER_MAX_PATH

// ---- Kernel function implementations (test doubles) -------------

static void* gAllocations[64];
static int gOutstanding = 0;
static int gInvalidFree = 0;
static int gFreeCalls = 0;
static int gForceAllocFailure = 0;

void* ExAllocatePool2(ULONG Flags, SIZE_T NumberOfBytes, ULONG Tag)
{
    (void)Flags; (void)Tag;
    if (gForceAllocFailure || gOutstanding >= 64)
        return NULL;
    void* result = malloc(NumberOfBytes);
    if (result)
        gAllocations[gOutstanding++] = result;
    return result;
}

void ExFreePool(void* P)
{
    // C free(NULL) would hide a kernel bug. Reject NULL, borrowed pointers,
    // and double frees instead of delegating those invalid cases to libc.
    for (int i = 0; P && i < gOutstanding; i++)
    {
        if (gAllocations[i] == P)
        {
            gAllocations[i] = gAllocations[--gOutstanding];
            gFreeCalls++;
            free(P);
            return;
        }
    }
    gInvalidFree++;
    printf("FAIL  invalid kernel-pool free detected by test double\n");
}

// Fake symbolic-link resolution: any "\??\X:" maps to
// "\Device\HarddiskVolume1" (21 WCHARs).
NTSTATUS ZwOpenSymbolicLinkObject(PHANDLE LinkHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
    (void)DesiredAccess;
    if (!LinkHandle || !ObjectAttributes || !ObjectAttributes->ObjectName ||
        !ObjectAttributes->ObjectName->Buffer)
        return STATUS_INVALID_PARAMETER;

    const UNICODE_STRING* name = ObjectAttributes->ObjectName;
    if (name->Length < 6 * sizeof(WCHAR) ||
        name->Buffer[0] != L'\\' || name->Buffer[1] != L'?' ||
        name->Buffer[2] != L'?' || name->Buffer[3] != L'\\' ||
        name->Buffer[5] != L':')
        return STATUS_NOT_FOUND;

    *LinkHandle = (HANDLE)0x1234;
    return STATUS_SUCCESS;
}

NTSTATUS ZwQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength)
{
    (void)LinkHandle;
    if (ReturnedLength)
        *ReturnedLength = 0;
    if (!LinkTarget || !LinkTarget->Buffer)
        return STATUS_INVALID_PARAMETER;

    static const WCHAR dev[] = L"\\Device\\HarddiskVolume1";
    ULONG devChars = (ULONG)(wcslen(dev));
    if (LinkTarget->MaximumLength < (devChars + 1) * sizeof(WCHAR))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(LinkTarget->Buffer, dev, devChars * sizeof(WCHAR));
    LinkTarget->Buffer[devChars] = L'\0';
    LinkTarget->Length = (USHORT)(devChars * sizeof(WCHAR));
    if (ReturnedLength)
        *ReturnedLength = devChars * sizeof(WCHAR);
    return STATUS_SUCCESS;
}

NTSTATUS ZwClose(HANDLE Handle)
{
    (void)Handle;
    return STATUS_SUCCESS;
}

VOID RtlInitUnicodeString(PUNICODE_STRING Dest, PCWSTR Source)
{
    if (!Dest || !Source)
        return;
    Dest->Buffer = (PWSTR)Source;
    Dest->Length = (USHORT)(wcslen(Source) * sizeof(WCHAR));
    Dest->MaximumLength = (USHORT)((wcslen(Source) + 1) * sizeof(WCHAR));
}

// ---- Include the code under test --------------------------------

#include "../evdevpath.c"

// ---- Harness -----------------------------------------------------

static int gFail = 0;

static void Check(const WCHAR* in, const WCHAR* expected)
{
    UNICODE_STRING u;
    u.Buffer = (WCHAR*)in;
    u.Length = (USHORT)(wcslen(in) * sizeof(WCHAR));
    u.MaximumLength = u.Length;

    UNICODE_STRING out;
    EvToDevicePath(&u, &out);

    const WCHAR* got = out.Buffer ? out.Buffer : L"(null)";
    if (wcscmp(got, expected) != 0)
    {
        gFail++;
        printf("FAIL  in=%-38ls expected=%-38ls got=%ls\n", in, expected, got);
    }
    else
    {
        printf("ok    in=%-38ls -> %ls\n", in, got);
    }

    EvFreeDevicePath(&u, &out);
}

static void CheckNull(void)
{
    UNICODE_STRING out;
    EvToDevicePath(NULL, &out);
    if (out.Buffer != NULL || out.Length != 0)
    {
        gFail++;
        printf("FAIL  NULL input\n");
    }
    else
    {
        printf("ok    NULL input -> empty\n");
    }

    UNICODE_STRING empty;
    empty.Buffer = NULL;
    empty.Length = 0;
    empty.MaximumLength = 0;
    EvToDevicePath(&empty, &out);
    if (out.Buffer != NULL)
    {
        gFail++;
        printf("FAIL  empty input\n");
    }
    else
    {
        printf("ok    empty input -> empty\n");
    }
}

static void CheckCleanup(void)
{
    UNICODE_STRING input, output;
    int before = gFreeCalls;

    // Real CLEAR/STATUS messages contain a NON-NULL pointer to an empty
    // WCHAR string. This is distinct from the old empty.Buffer=NULL case.
    RtlInitUnicodeString(&input, L"");
    EvToDevicePath(&input, &output);
    EvFreeDevicePath(&input, &output);
    EvFreeDevicePath(&input, &output);
    if (gFreeCalls != before || gInvalidFree || output.Buffer || output.Length)
    {
        gFail++;
        printf("FAIL  non-NULL empty-string cleanup\n");
    }
    else printf("ok    non-NULL empty-string cleanup does not free NULL\n");

    EvToDevicePath(NULL, &output);
    EvFreeDevicePath(NULL, &output);
    EvFreeDevicePath(NULL, NULL);
    RtlInitUnicodeString(&input, L"relative.txt");
    EvToDevicePath(&input, &output);
    EvFreeDevicePath(&input, &output);
    if (gFreeCalls != before || gInvalidFree)
    {
        gFail++;
        printf("FAIL  NULL or borrowed-buffer cleanup\n");
    }
    else printf("ok    NULL and borrowed buffers are never freed\n");

    RtlInitUnicodeString(&input, L"C:\\allocated.txt");
    EvToDevicePath(&input, &output);
    if (!output.Buffer || output.Buffer == input.Buffer)
    {
        gFail++;
        printf("FAIL  expected allocated translation\n");
    }
    EvFreeDevicePath(&input, &output);
    EvFreeDevicePath(&input, &output);
    if (gFreeCalls != before + 1 || gOutstanding || gInvalidFree)
    {
        gFail++;
        printf("FAIL  owned translation cleanup\n");
    }
    else printf("ok    owned translation freed exactly once\n");

    before = gFreeCalls;
    gForceAllocFailure = 1;
    EvToDevicePath(&input, &output);
    gForceAllocFailure = 0;
    if (output.Buffer != input.Buffer)
    {
        gFail++;
        printf("FAIL  allocation failure must borrow input\n");
    }
    EvFreeDevicePath(&input, &output);
    if (gFreeCalls != before || gOutstanding || gInvalidFree)
    {
        gFail++;
        printf("FAIL  allocation-failure cleanup\n");
    }
    else printf("ok    allocation failure does not free the input\n");
}

int main(void)
{
    printf("EvToDevicePath tests\n");

    // Drive letter -> device form
    Check(L"C:\\Users\\Lenovo\\a.txt",  L"\\Device\\HarddiskVolume1\\Users\\Lenovo\\a.txt");
    Check(L"C:\\Vault\\",               L"\\Device\\HarddiskVolume1\\Vault\\");
    Check(L"C:\\",                      L"\\Device\\HarddiskVolume1\\");
    Check(L"C:\\a.txt",                 L"\\Device\\HarddiskVolume1\\a.txt");
    Check(L"c:\\Users\\A",              L"\\Device\\HarddiskVolume1\\Users\\A");

    // UNC -> \Device\Mup
    Check(L"\\\\srv\\share\\f.txt",     L"\\Device\\Mup\\srv\\share\\f.txt");
    Check(L"\\\\srv\\share\\",          L"\\Device\\Mup\\srv\\share\\");
    Check(L"\\\\srv\\share\\dir\\",     L"\\Device\\Mup\\srv\\share\\dir\\");

    // Already-device / unrecognized -> unchanged (fail-open)
    Check(L"\\Device\\HarddiskVolume1\\x\\y", L"\\Device\\HarddiskVolume1\\x\\y");
    Check(L"relative.txt",              L"relative.txt");
    Check(L"C:relative",                L"C:relative");
    Check(L"\\\\.\\pipe\\name",         L"\\\\.\\pipe\\name");

    CheckNull();
    CheckCleanup();
    if (gOutstanding || gInvalidFree)
        gFail++;

    if (gFail == 0)
    {
        printf("\nAll EvToDevicePath tests passed.\n");
        return 0;
    }
    printf("\n%d EvToDevicePath test(s) FAILED.\n", gFail);
    return 1;
}
