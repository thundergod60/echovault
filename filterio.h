//------------------------------------------------------------
// filterio.h — user-mode access to the EchoVault minifilter
//
// All functions are BEST-EFFORT: they silently do nothing when
// the driver is not loaded (which is the normal, driver-less
// state of EchoVault). Callers must not depend on them.
//------------------------------------------------------------

#pragma once

#include <string>
#include <functional>

// True if the driver is loaded and reachable.
bool EvFilterAvailable();

// Sends one operation (EVFILTER_MSG_*) for a path. Returns success.
bool EvPortSend(unsigned long op, const std::wstring& path);

// Folder-aware helpers: directories get a trailing backslash so the
// driver treats them as PREFIX entries (the folder itself AND all
// files under it), matching how encryption works on folders.
void EvAllowFor(const std::wstring& path);      // allow opens (before reading)
void EvDenyFor(const std::wstring& path);       // deny opens again (after re-lock)
void EvRegister(const std::wstring& path);      // register as encrypted (after encrypt)
void EvUnregister(const std::wstring& path);    // unregister (after permanent decrypt)

// Guard-service loop (EchoVault.exe --guard): blocks on the driver's
// notification port; for each denied open, calls onDenied(path, app)
// after replying to the kernel (app = the requesting program's base
// name, e.g. "notepad.exe", empty if unknown). Returns when the
// driver disappears.
int EvGuardLoop(const std::function<void(const std::wstring&, const std::wstring&)>& onDenied);
