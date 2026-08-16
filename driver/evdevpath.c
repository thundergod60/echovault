//------------------------------------------------------------
// evdevpath.c — user-path -> device-path translation for the
// minifilter gate (see EvToDevicePath below).
//
// This file is #included by the driver (EchoVaultFilter.c) and by
// the user-mode unit test (stubcheck/test-evdevpath.c), so the SAME
// code is verified in both. It relies on the including TU providing
// the kernel base types (UNICODE_STRING, ULONG, ...) and the
// allocator/query functions used below.
//------------------------------------------------------------

#define EV_DEVICE_TAG 'tfvE'

// Converts a user-mode path (drive letter or UNC form) to the device
// form the filter manager uses for normalized names, so the gate
// compares like with like. Examples (note: comment lines must not end
// in a backslash, which would splice lines in C):
//   C:\Users\a\f.txt maps to \Device\HarddiskVolume1\Users\a\f.txt
//   C:\ maps to \Device\HarddiskVolume1\ (folder entry kept)
//   \\srv\sh\f.txt maps to \Device\Mup\srv\sh\f.txt
// On ANY failure the path is used as-is (fail-open: an untranslated
// path simply never matches). The result may point at 'in' (no free
// needed) or at a buffer the caller must free with ExFreePool when it
// differs from 'in'.
static VOID EvToDevicePath(const UNICODE_STRING* in, UNICODE_STRING* out)
{
    out->Buffer = NULL;
    out->Length = 0;
    out->MaximumLength = 0;

    if (!in || !in->Buffer || in->Length == 0)
        return;

    ULONG chars = in->Length / sizeof(WCHAR);

    // UNC: \\server\share\... -> \Device\Mup\server\share\...
    // "\Device\Mup" is 11 WCHARs; a separator '\' is always kept.
    // \\.\ and \\?\ are device/extended namespaces, NOT UNC — pass
    // them through raw (they will simply never match; fail-open).
    if (chars >= 3 && in->Buffer[0] == L'\\' && in->Buffer[1] == L'\\' &&
        in->Buffer[2] != L'.' && in->Buffer[2] != L'?')
    {
        ULONG restChars = chars - 2;
        ULONG total = 11 + 1 + restChars;
        if (total + 1 >= EVFILTER_MAX_PATH)
        {
            *out = *in;      // too long to translate — raw (fail-open)
            return;
        }
        WCHAR* buf = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            (total + 1) * sizeof(WCHAR), EV_DEVICE_TAG);
        if (!buf)
        {
            *out = *in;
            return;
        }
        const WCHAR mup[] = L"\\Device\\Mup";
        RtlCopyMemory(buf, mup, 11 * sizeof(WCHAR));
        buf[11] = L'\\';
        RtlCopyMemory(buf + 12, in->Buffer + 2, restChars * sizeof(WCHAR));
        buf[total] = L'\0';
        out->Buffer = buf;
        out->Length = (USHORT)(total * sizeof(WCHAR));
        out->MaximumLength = (USHORT)((total + 1) * sizeof(WCHAR));
        return;
    }

    // Drive letter: X:\... -> resolve \??\X: then append the rest.
    // A separator '\' is always kept, so "C:\" stays a folder entry.
    // Uses the modern handle-based symbolic-link API (ZwOpenSymbolicLink
    // + ZwQuerySymbolicLinkObject); the legacy path-based ZwQuerySymbolicLink
    // was removed from newer WDKs.
    if (chars >= 3 && in->Buffer[1] == L':' && in->Buffer[2] == L'\\')
    {
        WCHAR linkBuf[7];
        linkBuf[0] = L'\\'; linkBuf[1] = L'?'; linkBuf[2] = L'?';
        linkBuf[3] = L'\\'; linkBuf[4] = in->Buffer[0]; linkBuf[5] = L':';
        linkBuf[6] = L'\0';

        UNICODE_STRING link;
        RtlInitUnicodeString(&link, linkBuf);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &link, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE linkHandle = NULL;
        if (NT_SUCCESS(ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &oa)) &&
            linkHandle != NULL)
        {
            WCHAR targetBuf[128];
            UNICODE_STRING target;
            target.Buffer = targetBuf;
            target.Length = 0;
            target.MaximumLength = sizeof(targetBuf);

            if (NT_SUCCESS(ZwQuerySymbolicLinkObject(linkHandle, &target, NULL)) &&
                target.Length > 0)
            {
                ULONG devChars = target.Length / sizeof(WCHAR);
                ULONG restChars = chars - 3;
                ULONG total = devChars + 1 + restChars;
                if (total + 1 < EVFILTER_MAX_PATH)
                {
                    WCHAR* buf = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                        (total + 1) * sizeof(WCHAR), EV_DEVICE_TAG);
                    if (buf)
                    {
                        RtlCopyMemory(buf, target.Buffer, devChars * sizeof(WCHAR));
                        buf[devChars] = L'\\';
                        RtlCopyMemory(buf + devChars + 1, in->Buffer + 3,
                            restChars * sizeof(WCHAR));
                        buf[total] = L'\0';
                        out->Buffer = buf;
                        out->Length = (USHORT)(total * sizeof(WCHAR));
                        out->MaximumLength = (USHORT)((total + 1) * sizeof(WCHAR));
                        ZwClose(linkHandle);
                        return;
                    }
                }
            }
            ZwClose(linkHandle);
        }
    }

    // Unrecognized form (already a device path, mounted folder, etc.):
    // use it as-is. It may simply never match — that fails OPEN.
    *out = *in;
}
