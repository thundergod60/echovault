//------------------------------------------------------------
// evfilter.h — EchoVault minifilter communication protocol
//
// Included by BOTH the kernel driver (EchoVaultFilter.c, under
// <fltKernel.h>) and the user-mode control tool (filterctl.c,
// under <windows.h>). Keep it plain C so both sides accept it.
//------------------------------------------------------------

#ifndef EVFILTER_H
#define EVFILTER_H

// Communication port name (Filter Manager namespace).
#define EVFILTER_PORT_NAME L"\\EchoVaultFilterPort"

// Operations sent from user mode to the driver.
#define EVFILTER_MSG_ADD        1   // register a path as encrypted: deny
                                    //   opens of it unless allow-listed
#define EVFILTER_MSG_ALLOW      2   // allow opens of an encrypted path
                                    //   (call right before decrypting)
#define EVFILTER_MSG_DISALLOW   3   // deny opens again (call after
                                    //   re-encrypting / re-locking)
#define EVFILTER_MSG_REMOVE     4   // unregister a path entirely
                                    //   (file was decrypted for good)
#define EVFILTER_MSG_CLEAR      5   // forget everything (uninstall)
#define EVFILTER_MSG_STATUS     6   // ping / health check
#define EVFILTER_MSG_EXCLUDE_ADD    7   // allow an APP (image base name,
                                        //   e.g. "backup.exe", in Path) to
                                        //   open locked files
#define EVFILTER_MSG_EXCLUDE_REMOVE 8   // revoke that
#define EVFILTER_MSG_EXCLUDE_CLEAR  9   // forget all exclusions

#define EVFILTER_MAX_PATH       1024    // WCHARs, including NUL
#define EVFILTER_MAX_APP        64      // WCHARs: requestor image base
                                        // name (e.g. "notepad.exe")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _EVFILTER_MSG {
    ULONG  OpCode;                 // one of EVFILTER_MSG_*
    ULONG  Reserved;               // must be 0 (driver fills epoch itself)
    WCHAR  Path[EVFILTER_MAX_PATH]; // NUL-terminated, case-insensitive
} EVFILTER_MSG;

// Kernel -> user notification. Delivered to the guard service when an
// open of a locked file was denied, so it can pop the password dialog.
#define EVFILTER_NOTIFY_DENIED 1

typedef struct _EVFILTER_NOTIFY {
    ULONG  OpCode;                 // one of EVFILTER_NOTIFY_*
    ULONG  Reserved;               // reserved, 0
    WCHAR  Path[EVFILTER_MAX_PATH]; // the path that was denied
    WCHAR  RequesterApp[EVFILTER_MAX_APP]; // the app that tried to open
                                           // it (base name, e.g.
                                           // "notepad.exe"), so the guard
                                           // can reopen in the SAME app
} EVFILTER_NOTIFY;

#ifdef __cplusplus
}
#endif

#endif // EVFILTER_H
