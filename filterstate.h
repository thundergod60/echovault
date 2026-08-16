//------------------------------------------------------------
// filterstate.h — user-mode crash-safety state for the EchoVault
// minifilter.
//
// The kernel driver itself can never be fully "safe" — any kernel
// bug can bugcheck. What this module provides is the *survivability*
// layer around it, all in plain user mode:
//
//   1. An off-switch ("Disabled" marker) that survives reboots, so
//      the user can keep the driver unloaded with one command.
//   2. A record of when the driver was loaded and cleanly unloaded,
//      so we can tell whether it was present at an abnormal shutdown.
//   3. Unexpected-shutdown detection (Event Log 6008 via wevtutil),
//      so after a crash the tool tells the user the driver was
//      probably involved and REFUSES to auto-advise reloading it.
//
// Plain C, no C++ features, compiles under MinGW and MSVC, and is
// linked into both filterctl (console) and EchoVault (GUI).
//------------------------------------------------------------

#ifndef FILTERSTATE_H
#define FILTERSTATE_H

#include <windows.h>

// Marker flags
#define EVFS_OPTS_LOADED    0x01   // a load was recorded
#define EVFS_OPTS_UNLOADED  0x02   // a clean unload was recorded
#define EVFS_OPTS_DISABLED  0x04   // user off-switch is set

typedef struct _EVFS_STATE {
    ULONG      Flags;       // EVFS_OPTS_*
    ULONGLONG  LoadedAt;    // FILETIME (100ns since 1601), 0 if none
    ULONGLONG  UnloadedAt;  // FILETIME, 0 if none
} EVFS_STATE;

// Reads the marker state. Returns 1 on success, 0 on failure.
// Absent markers simply yield Flags = 0 (fresh state).
int  EvFsGetState(EVFS_STATE* st);

// Records a load (clears any earlier UnloadedAt) / clean unload.
// t is a FILETIME value. Returns 1 on success.
int  EvFsSetLoaded(ULONGLONG t);
int  EvFsSetUnloaded(ULONGLONG t);

// User off-switch. Returns 1 on success; EvFsIsDisabled returns
// 1 = disabled, 0 = enabled, -1 = error.
int  EvFsSetDisabled(int disabled);
int  EvFsIsDisabled(void);

// True if the driver was loaded and never cleanly unloaded since —
// i.e. it may have been present at whatever ended the last session.
int  EvFsWasLoadedAtLastShutdown(const EVFS_STATE* st);

// Queries the System event log (Event 6008 = "previous shutdown was
// unexpected") via wevtutil. Returns:
//    1  an event with TimeCreated >= since exists (*whenOut = its FILETIME)
//    0  no such event
//   -1  the query could not be performed (wevtutil missing, log
//       inaccessible) — callers must treat this as UNKNOWN, not "clean"
int  EvFsUnexpectedShutdownSince(ULONGLONG since, ULONGLONG* whenOut);

// Builds a full human-readable state report (multi-line, CRLF) into
// buf. driverLoaded tells it whether the driver port is reachable
// right now. Returns 1 on success.
int  EvFsBuildReport(wchar_t* buf, size_t cap, int driverLoaded);

#endif // FILTERSTATE_H
