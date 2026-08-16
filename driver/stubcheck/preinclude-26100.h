//------------------------------------------------------------
// preinclude-26100.h — declares the WDK 10.0.19041+ APIs that the
// 16299 headers used for the local real-header check don't have.
// ExAllocatePool2/POOL_FLAG_NON_PAGED exist in the WDK 26100 the
// cloud runner installs; these declarations mirror them exactly.
//------------------------------------------------------------
#pragma once

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040ULL
#endif

// Plain-type declaration (this file is processed BEFORE the WDK
// headers define ULONG/SIZE_T). Compatible with the real signature
// void* ExAllocatePool2(POOL_FLAGS, SIZE_T, ULONG): ULONG is
// unsigned long and SIZE_T is unsigned long long on x64.
void* ExAllocatePool2(unsigned long Flags, unsigned long long NumberOfBytes, unsigned long Tag);
