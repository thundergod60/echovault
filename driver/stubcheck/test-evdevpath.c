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

void* ExAllocatePool2(ULONG Flags, SIZE_T NumberOfBytes, ULONG Tag)
{
    (void)Flags; (void)Tag;
    return malloc(NumberOfBytes);
}

void ExFreePool(void* P) { free(P); }

// Fake symbolic-link resolution: any "\??\X:" maps to
// "\Device\HarddiskVolume1" (21 WCHARs).
NTSTATUS ZwQuerySymbolicLink(PUNICODE_STRING LinkName, PUNICODE_STRING TargetName)
{
    if (!LinkName || !LinkName->Buffer || !TargetName || !TargetName->Buffer)
        return STATUS_INVALID_PARAMETER;
    if (LinkName->Length < 6 * sizeof(WCHAR) ||
        LinkName->Buffer[0] != L'\\' || LinkName->Buffer[1] != L'?' ||
        LinkName->Buffer[2] != L'?' || LinkName->Buffer[3] != L'\\' ||
        LinkName->Buffer[5] != L':')
        return STATUS_NOT_FOUND;

    static const WCHAR dev[] = L"\\Device\\HarddiskVolume1";
    ULONG devChars = (ULONG)(wcslen(dev));
    if (TargetName->MaximumLength < (devChars + 1) * sizeof(WCHAR))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(TargetName->Buffer, dev, devChars * sizeof(WCHAR));
    TargetName->Buffer[devChars] = L'\0';
    TargetName->Length = (USHORT)(devChars * sizeof(WCHAR));
    return STATUS_SUCCESS;
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

    if (out.Buffer != u.Buffer && out.Buffer)
        ExFreePool(out.Buffer);
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

    if (gFail == 0)
    {
        printf("\nAll EvToDevicePath tests passed.\n");
        return 0;
    }
    printf("\n%d EvToDevicePath test(s) FAILED.\n", gFail);
    return 1;
}
